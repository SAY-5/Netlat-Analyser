"""Shared test fixtures for netlat."""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from netlat.flows.models import Packet


def make_packet(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_port=12345,
    dst_port=80,
    protocol="TCP",
    flags="ACK",
    seq=1000,
    ack=2000,
    payload_len=100,
    timestamp=1000.0,
    tsval=None,
    tsecr=None,
    window=65535,
) -> Packet:
    """Create a Packet object directly for unit testing."""
    tcp_options = None
    if tsval is not None or tsecr is not None:
        tcp_options = {"timestamp": (tsval or 0, tsecr or 0)}
    return Packet(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        ip_len=40 + payload_len,
        tcp_flags=flags if protocol == "TCP" else None,
        seq=seq if protocol == "TCP" else None,
        ack=ack if protocol == "TCP" else None,
        payload_len=payload_len,
        window=window if protocol == "TCP" else None,
        tcp_options=tcp_options,
        capture_len=40 + payload_len,
    )


@pytest.fixture
def tmp_pcap_path(tmp_path: Path) -> Path:
    """Return a temporary path for writing pcap files."""
    return tmp_path / "test.pcap"


def _pcap_global_header(
    snaplen: int = 65535,
    link_type: int = 1,  # DLT_EN10MB
) -> bytes:
    """Build a pcap global header."""
    return struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic
        2,  # version major
        4,  # version minor
        0,  # thiszone
        0,  # sigfigs
        snaplen,
        link_type,
    )


def _pcap_packet_header(ts_sec: int, ts_usec: int, captured_len: int, orig_len: int) -> bytes:
    """Build a pcap packet record header."""
    return struct.pack("<IIII", ts_sec, ts_usec, captured_len, orig_len)


def make_tcp_packet(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    flags: int = 0x10,  # ACK
    seq: int = 1000,
    ack: int = 2000,
    payload: bytes = b"",
    window: int = 65535,
    tcp_options: bytes = b"",
    ip_id: int = 1,
    ip_flags: int = 0x02,  # DF
) -> bytes:
    """Build a raw Ethernet + IPv4 + TCP packet.

    Returns the full Ethernet frame bytes.
    """
    # TCP header
    data_offset = (20 + len(tcp_options)) // 4
    # Pad options to 4-byte boundary
    opt_pad = (4 - (len(tcp_options) % 4)) % 4
    tcp_options_padded = tcp_options + b"\x00" * opt_pad
    data_offset = (20 + len(tcp_options_padded)) // 4

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (data_offset << 4),
        flags,
        window,
        0,  # checksum (0 for testing)
        0,  # urgent pointer
    )
    tcp_segment = tcp_header + tcp_options_padded + payload

    # IPv4 header
    ip_total_len = 20 + len(tcp_segment)
    ip_frag_off = (ip_flags << 13)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version + IHL
        0,  # DSCP/ECN
        ip_total_len,
        ip_id,
        ip_frag_off,
        64,  # TTL
        6,  # protocol (TCP)
        0,  # checksum
        _ip_to_bytes(src_ip),
        _ip_to_bytes(dst_ip),
    )
    ip_packet = ip_header + tcp_segment

    # Ethernet frame
    eth_header = (
        b"\x00\x11\x22\x33\x44\x55"  # dst MAC
        + b"\x66\x77\x88\x99\xaa\xbb"  # src MAC
        + b"\x08\x00"  # EtherType IPv4
    )
    return eth_header + ip_packet


def make_udp_packet(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 53,
    payload: bytes = b"",
) -> bytes:
    """Build a raw Ethernet + IPv4 + UDP packet."""
    # UDP header
    udp_len = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    udp_segment = udp_header + payload

    # IPv4 header
    ip_total_len = 20 + len(udp_segment)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_len,
        1,
        0x4000,  # DF
        64,
        17,  # UDP
        0,
        _ip_to_bytes(src_ip),
        _ip_to_bytes(dst_ip),
    )
    ip_packet = ip_header + udp_segment

    eth_header = (
        b"\x00\x11\x22\x33\x44\x55"
        + b"\x66\x77\x88\x99\xaa\xbb"
        + b"\x08\x00"
    )
    return eth_header + ip_packet


def _ip_to_bytes(ip: str) -> bytes:
    """Convert dotted-quad IP string to 4 bytes."""
    import socket
    return socket.inet_aton(ip)


def write_pcap(path: Path, packets: list[tuple[float, bytes]], link_type: int = 1) -> None:
    """Write a minimal pcap file from a list of (timestamp, frame_bytes) tuples."""
    with open(path, "wb") as f:
        f.write(_pcap_global_header(link_type=link_type))
        for ts, frame in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            pkt_hdr = _pcap_packet_header(ts_sec, ts_usec, len(frame), len(frame))
            f.write(pkt_hdr)
            f.write(frame)
