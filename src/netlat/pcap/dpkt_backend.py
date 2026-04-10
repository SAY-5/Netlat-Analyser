"""dpkt-based pcap parser backend for netlat."""

from __future__ import annotations

import os
import socket
import struct
from typing import Any, Iterator

import dpkt

from netlat.flows.models import CaptureMetadata, Packet
from netlat.util.logging import get_logger

log = get_logger("dpkt_parser")

# Magic bytes for pcap/pcapng detection
_PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
_PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
_PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"
_PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# TCP flag bitmasks
_FIN = 0x01
_SYN = 0x02
_RST = 0x04
_PSH = 0x08
_ACK = 0x10
_URG = 0x20

# Don't Fragment flag in IP
_DF = 0x02

# Standard MSS for Ethernet
_STANDARD_MSS = 1460

# Ethernet type for VLAN
_ETH_TYPE_8021Q = 0x8100
_ETH_TYPE_IP4 = 0x0800
_ETH_TYPE_IP6 = 0x86DD

# Link-layer types
_DLT_EN10MB = 1  # Ethernet
_DLT_RAW = 101  # Raw IP
_DLT_LINUX_SLL = 113  # Linux cooked capture
_DLT_LINUX_SLL2 = 276  # Linux cooked capture v2


def _format_tcp_flags(flags: int) -> str:
    """Convert TCP flag bits to a human-readable string."""
    parts: list[str] = []
    if flags & _SYN:
        parts.append("SYN")
    if flags & _ACK:
        parts.append("ACK")
    if flags & _FIN:
        parts.append("FIN")
    if flags & _RST:
        parts.append("RST")
    if flags & _PSH:
        parts.append("PSH")
    if flags & _URG:
        parts.append("URG")
    return "-".join(parts) if parts else ""


def _parse_tcp_options(opts_bytes: bytes) -> dict[str, Any]:
    """Parse TCP options from raw bytes.

    Extracts:
        - timestamp (kind=8): (tsval, tsecr)
        - mss (kind=2): max segment size
        - sack (kind=5): list of (left, right) edges
        - window_scale (kind=3): shift count
    """
    result: dict[str, Any] = {}
    i = 0
    while i < len(opts_bytes):
        kind = opts_bytes[i]
        if kind == 0:  # End of options
            break
        if kind == 1:  # NOP
            i += 1
            continue
        if i + 1 >= len(opts_bytes):
            break
        length = opts_bytes[i + 1]
        if length < 2 or i + length > len(opts_bytes):
            break

        if kind == 2 and length == 4:  # MSS
            result["mss"] = struct.unpack("!H", opts_bytes[i + 2 : i + 4])[0]
        elif kind == 3 and length == 3:  # Window Scale
            result["window_scale"] = opts_bytes[i + 2]
        elif kind == 5 and length >= 10:  # SACK
            sack_data = opts_bytes[i + 2 : i + length]
            edges: list[tuple[int, int]] = []
            for j in range(0, len(sack_data) - 7, 8):
                left = struct.unpack("!I", sack_data[j : j + 4])[0]
                right = struct.unpack("!I", sack_data[j + 4 : j + 8])[0]
                edges.append((left, right))
            result["sack"] = edges
        elif kind == 8 and length == 10:  # Timestamp
            tsval = struct.unpack("!I", opts_bytes[i + 2 : i + 6])[0]
            tsecr = struct.unpack("!I", opts_bytes[i + 6 : i + 10])[0]
            result["timestamp"] = (tsval, tsecr)

        i += length

    return result


def _inet_to_str(addr: bytes) -> str:
    """Convert raw IP address bytes to string form."""
    if len(addr) == 4:
        return socket.inet_ntop(socket.AF_INET, addr)
    elif len(addr) == 16:
        return socket.inet_ntop(socket.AF_INET6, addr)
    return addr.hex()


def _extract_ip_from_ethernet(eth: dpkt.ethernet.Ethernet) -> dpkt.ip.IP | dpkt.ip6.IP6 | None:
    """Extract the IP layer from an Ethernet frame, handling VLAN tags."""
    if eth.type == _ETH_TYPE_8021Q:
        vlan_data = eth.data
        # dpkt may have already parsed through VLAN to the IP layer
        if isinstance(vlan_data, dpkt.ip.IP):
            return vlan_data
        if isinstance(vlan_data, dpkt.ip6.IP6):
            return vlan_data
        # dpkt might have parsed it as a VLANtag8021Q or similar object
        if hasattr(vlan_data, "data"):
            inner = vlan_data.data
            if isinstance(inner, dpkt.ip.IP):
                return inner
            if isinstance(inner, dpkt.ip6.IP6):
                return inner
            if hasattr(vlan_data, "type") and isinstance(inner, bytes):
                if vlan_data.type == _ETH_TYPE_IP4:
                    try:
                        return dpkt.ip.IP(inner)
                    except (dpkt.UnpackError, ValueError):
                        return None
                elif vlan_data.type == _ETH_TYPE_IP6:
                    try:
                        return dpkt.ip6.IP6(inner)
                    except (dpkt.UnpackError, ValueError):
                        return None
        # Raw bytes: TCI(2) + inner_ether_type(2) + payload
        if isinstance(vlan_data, bytes) and len(vlan_data) >= 4:
            inner_type = struct.unpack("!HH", vlan_data[:4])[1]
            inner_data = vlan_data[4:]
            if inner_type == _ETH_TYPE_IP4:
                try:
                    return dpkt.ip.IP(inner_data)
                except (dpkt.UnpackError, ValueError):
                    return None
            elif inner_type == _ETH_TYPE_IP6:
                try:
                    return dpkt.ip6.IP6(inner_data)
                except (dpkt.UnpackError, ValueError):
                    return None
        return None

    if isinstance(eth.data, dpkt.ip.IP):
        return eth.data
    if isinstance(eth.data, dpkt.ip6.IP6):
        return eth.data

    if eth.type == _ETH_TYPE_IP4:
        try:
            return dpkt.ip.IP(eth.data) if isinstance(eth.data, bytes) else eth.data
        except (dpkt.UnpackError, ValueError):
            return None
    elif eth.type == _ETH_TYPE_IP6:
        try:
            return dpkt.ip6.IP6(eth.data) if isinstance(eth.data, bytes) else eth.data
        except (dpkt.UnpackError, ValueError):
            return None

    return None


def _ip_to_packet(ts: float, ip: dpkt.ip.IP | dpkt.ip6.IP6, capture_len: int) -> Packet | None:
    """Convert a dpkt IP object to a netlat Packet."""
    is_ipv6 = isinstance(ip, dpkt.ip6.IP6)

    if is_ipv6:
        src_ip = _inet_to_str(ip.src)
        dst_ip = _inet_to_str(ip.dst)
        ip_len = ip.plen + 40  # payload length + fixed header
        transport = ip.data
        # Walk extension headers for IPv6
        nxt = ip.nxt
        while nxt in (0, 43, 44, 60) and hasattr(transport, "data"):
            nxt = transport.nxt if hasattr(transport, "nxt") else 255
            transport = transport.data
        df_set = False  # IPv6 doesn't have DF in the same way
        frag_offset = 0
    else:
        src_ip = _inet_to_str(ip.src)
        dst_ip = _inet_to_str(ip.dst)
        ip_len = ip.len
        transport = ip.data
        df_set = bool(ip.off & _DF) if hasattr(ip, "off") else False
        frag_offset = (ip.off & 0x1FFF) if hasattr(ip, "off") else 0

    if isinstance(transport, dpkt.tcp.TCP):
        tcp: dpkt.tcp.TCP = transport
        flags_int = tcp.flags
        flags_str = _format_tcp_flags(flags_int)
        tcp_header_len = tcp.off * 4 if tcp.off else 20
        payload_len = len(tcp.data) if isinstance(tcp.data, bytes) else 0

        # Parse TCP options
        opts_bytes = bytes(tcp.opts) if tcp.opts else b""
        tcp_options = _parse_tcp_options(opts_bytes) if opts_bytes else None

        # Detect TSO/GRO offloaded segments
        is_offloaded = (
            payload_len > _STANDARD_MSS
            and df_set
            and frag_offset == 0
        )

        return Packet(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=tcp.sport,
            dst_port=tcp.dport,
            protocol="TCP",
            ip_len=ip_len,
            tcp_flags=flags_str,
            seq=tcp.seq,
            ack=tcp.ack,
            payload_len=payload_len,
            window=tcp.win,
            tcp_options=tcp_options,
            is_offloaded=is_offloaded,
            capture_len=capture_len,
        )

    elif isinstance(transport, dpkt.udp.UDP):
        udp: dpkt.udp.UDP = transport
        payload_len = len(udp.data) if isinstance(udp.data, bytes) else 0
        return Packet(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=udp.sport,
            dst_port=udp.dport,
            protocol="UDP",
            ip_len=ip_len,
            payload_len=payload_len,
            capture_len=capture_len,
        )

    else:
        # Non-TCP/UDP (e.g. ICMP) - skip with a generic packet
        proto_name = "OTHER"
        if not is_ipv6 and hasattr(ip, "p"):
            if ip.p == 1:
                proto_name = "ICMP"
        elif is_ipv6 and hasattr(ip, "nxt"):
            if ip.nxt == 58:
                proto_name = "ICMPv6"

        return Packet(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=0,
            dst_port=0,
            protocol=proto_name,
            ip_len=ip_len,
            capture_len=capture_len,
        )


class DpktParser:
    """Full dpkt-based pcap/pcapng parser."""

    def parse_pcap(self, path: str) -> Iterator[Packet]:
        """Parse a pcap or pcapng file, yielding Packet objects.

        Streams through the file without loading it entirely into memory.
        Handles Ethernet, Linux SLL, and raw IP link layers.
        Gracefully handles truncated/malformed packets.
        """
        file_size = os.path.getsize(path)

        with open(path, "rb") as f:
            magic = f.read(4)
            f.seek(0)

            if magic == _PCAPNG_MAGIC:
                reader: Any = dpkt.pcapng.Reader(f)
            elif magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_BE, _PCAP_MAGIC_NS_LE, _PCAP_MAGIC_NS_BE):
                reader = dpkt.pcap.Reader(f)
            else:
                raise ValueError(f"Unknown pcap format (magic: {magic.hex()})")

            dlt = reader.datalink()

            for ts, buf in reader:
                try:
                    pkt = self._parse_frame(ts, buf, dlt, len(buf))
                    if pkt is not None:
                        yield pkt
                except (dpkt.UnpackError, dpkt.NeedData, ValueError, struct.error) as exc:
                    log.debug("skipped_packet", error=str(exc), timestamp=ts)
                    continue

    def parse_pcap_with_metadata(self, path: str) -> tuple[list[Packet], CaptureMetadata]:
        """Parse pcap and collect metadata alongside packets."""
        meta = CaptureMetadata(
            file_path=path,
            file_size_bytes=os.path.getsize(path),
        )

        packets: list[Packet] = []
        flow_keys: set[tuple[str, int, str, int, str]] = set()
        protocols: dict[str, int] = {}

        for pkt in self.parse_pcap(path):
            packets.append(pkt)

            # Track unique flows (normalized)
            src = (pkt.src_ip, pkt.src_port)
            dst = (pkt.dst_ip, pkt.dst_port)
            if src <= dst:
                fk = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.protocol)
            else:
                fk = (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port, pkt.protocol)
            flow_keys.add(fk)

            protocols[pkt.protocol] = protocols.get(pkt.protocol, 0) + 1

        meta.packet_count = len(packets)
        if packets:
            meta.first_timestamp = packets[0].timestamp
            meta.last_timestamp = packets[-1].timestamp
            meta.duration_seconds = meta.last_timestamp - meta.first_timestamp
        meta.unique_flows = len(flow_keys)
        meta.protocols = protocols

        # Detect link type from file
        with open(path, "rb") as f:
            magic = f.read(4)
            f.seek(0)
            if magic == _PCAPNG_MAGIC:
                reader: Any = dpkt.pcapng.Reader(f)
            else:
                reader = dpkt.pcap.Reader(f)
            meta.link_type = reader.datalink()

        return packets, meta

    def _parse_frame(
        self, ts: float, buf: bytes, dlt: int, capture_len: int
    ) -> Packet | None:
        """Parse a single frame based on the link-layer type."""
        ip: dpkt.ip.IP | dpkt.ip6.IP6 | None = None

        if dlt == _DLT_EN10MB:
            if len(buf) < 14:
                log.debug("truncated_ethernet", length=len(buf))
                return None
            eth = dpkt.ethernet.Ethernet(buf)
            ip = _extract_ip_from_ethernet(eth)

        elif dlt == _DLT_LINUX_SLL:
            if len(buf) < 16:
                log.debug("truncated_sll", length=len(buf))
                return None
            sll = dpkt.sll.SLL(buf)
            if sll.ethtype == _ETH_TYPE_IP4:
                ip = dpkt.ip.IP(sll.data) if isinstance(sll.data, bytes) else sll.data
            elif sll.ethtype == _ETH_TYPE_IP6:
                ip = dpkt.ip6.IP6(sll.data) if isinstance(sll.data, bytes) else sll.data

        elif dlt == _DLT_RAW:
            if len(buf) < 1:
                return None
            version = (buf[0] >> 4) & 0xF
            if version == 4:
                ip = dpkt.ip.IP(buf)
            elif version == 6:
                ip = dpkt.ip6.IP6(buf)

        elif dlt == _DLT_LINUX_SLL2:
            if len(buf) < 20:
                log.debug("truncated_sll2", length=len(buf))
                return None
            proto_type = struct.unpack("!H", buf[0:2])[0]
            payload = buf[20:]
            if proto_type == _ETH_TYPE_IP4:
                ip = dpkt.ip.IP(payload)
            elif proto_type == _ETH_TYPE_IP6:
                ip = dpkt.ip6.IP6(payload)

        else:
            log.debug("unsupported_link_type", dlt=dlt)
            return None

        if ip is None:
            log.debug("non_ip_packet", timestamp=ts, dlt=dlt)
            return None

        return _ip_to_packet(ts, ip, capture_len)
