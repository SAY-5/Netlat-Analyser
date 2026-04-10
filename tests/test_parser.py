"""Tests for netlat.pcap.dpkt_backend parser."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from netlat.pcap.dpkt_backend import DpktParser
from tests.conftest import make_tcp_packet, make_udp_packet, write_pcap


@pytest.fixture
def parser() -> DpktParser:
    return DpktParser()


@pytest.fixture
def tcp_handshake_pcap(tmp_path: Path) -> Path:
    """Generate a minimal pcap with a 3-way handshake, data packets, and FIN."""
    pcap_path = tmp_path / "handshake.pcap"

    # Build TCP timestamp option: kind=8, len=10, tsval, tsecr + NOP padding
    def tcp_ts_option(tsval: int, tsecr: int) -> bytes:
        return (
            b"\x01"  # NOP
            + b"\x01"  # NOP
            + struct.pack("!BBii", 8, 10, tsval, tsecr)
        )

    base_ts = 1700000000.0
    packets: list[tuple[float, bytes]] = []

    # SYN (client -> server)
    packets.append((
        base_ts,
        make_tcp_packet(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=54321,
            dst_port=443,
            flags=0x02,  # SYN
            seq=1000,
            ack=0,
            tcp_options=tcp_ts_option(100, 0),
        ),
    ))

    # SYN-ACK (server -> client)
    packets.append((
        base_ts + 0.001,
        make_tcp_packet(
            src_ip="192.168.1.20",
            dst_ip="192.168.1.10",
            src_port=443,
            dst_port=54321,
            flags=0x12,  # SYN-ACK
            seq=2000,
            ack=1001,
            tcp_options=tcp_ts_option(200, 100),
        ),
    ))

    # ACK (client -> server)
    packets.append((
        base_ts + 0.002,
        make_tcp_packet(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=54321,
            dst_port=443,
            flags=0x10,  # ACK
            seq=1001,
            ack=2001,
            tcp_options=tcp_ts_option(102, 200),
        ),
    ))

    # Data packet (client -> server)
    packets.append((
        base_ts + 0.010,
        make_tcp_packet(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=54321,
            dst_port=443,
            flags=0x18,  # PSH-ACK
            seq=1001,
            ack=2001,
            payload=b"GET / HTTP/1.1\r\n\r\n",
            tcp_options=tcp_ts_option(110, 200),
        ),
    ))

    # Data packet (server -> client)
    packets.append((
        base_ts + 0.020,
        make_tcp_packet(
            src_ip="192.168.1.20",
            dst_ip="192.168.1.10",
            src_port=443,
            dst_port=54321,
            flags=0x18,  # PSH-ACK
            seq=2001,
            ack=1019,
            payload=b"HTTP/1.1 200 OK\r\n\r\nHello",
            tcp_options=tcp_ts_option(220, 110),
        ),
    ))

    # FIN-ACK (client -> server)
    packets.append((
        base_ts + 0.030,
        make_tcp_packet(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=54321,
            dst_port=443,
            flags=0x11,  # FIN-ACK
            seq=1019,
            ack=2026,
            tcp_options=tcp_ts_option(130, 220),
        ),
    ))

    # FIN-ACK (server -> client)
    packets.append((
        base_ts + 0.031,
        make_tcp_packet(
            src_ip="192.168.1.20",
            dst_ip="192.168.1.10",
            src_port=443,
            dst_port=54321,
            flags=0x11,  # FIN-ACK
            seq=2026,
            ack=1020,
            tcp_options=tcp_ts_option(231, 130),
        ),
    ))

    write_pcap(pcap_path, packets)
    return pcap_path


class TestDpktParserBasic:
    """Basic pcap parsing tests."""

    def test_correct_packet_count(self, parser: DpktParser, tcp_handshake_pcap: Path) -> None:
        """Parser should yield the correct number of packets."""
        packets = list(parser.parse_pcap(str(tcp_handshake_pcap)))
        assert len(packets) == 7

    def test_correct_ips(self, parser: DpktParser, tcp_handshake_pcap: Path) -> None:
        """First packet should have correct source and destination IPs."""
        packets = list(parser.parse_pcap(str(tcp_handshake_pcap)))
        syn = packets[0]
        assert syn.src_ip == "192.168.1.10"
        assert syn.dst_ip == "192.168.1.20"

    def test_correct_ports(self, parser: DpktParser, tcp_handshake_pcap: Path) -> None:
        packets = list(parser.parse_pcap(str(tcp_handshake_pcap)))
        syn = packets[0]
        assert syn.src_port == 54321
        assert syn.dst_port == 443

    def test_tcp_flags(self, parser: DpktParser, tcp_handshake_pcap: Path) -> None:
        packets = list(parser.parse_pcap(str(tcp_handshake_pcap)))
        assert packets[0].tcp_flags == "SYN"
        assert packets[1].tcp_flags == "SYN-ACK"
        assert packets[2].tcp_flags == "ACK"
        assert packets[3].tcp_flags == "ACK-PSH"
        # FIN-ACK
        assert "FIN" in packets[5].tcp_flags
        assert "ACK" in packets[5].tcp_flags

    def test_tcp_timestamp_extraction(self, parser: DpktParser, tcp_handshake_pcap: Path) -> None:
        """TCP timestamp option should be extracted."""
        packets = list(parser.parse_pcap(str(tcp_handshake_pcap)))
        syn = packets[0]
        assert syn.tcp_options is not None
        assert "timestamp" in syn.tcp_options
        tsval, tsecr = syn.tcp_options["timestamp"]
        assert tsval == 100
        assert tsecr == 0

    def test_payload_len(self, parser: DpktParser, tcp_handshake_pcap: Path) -> None:
        """Data packets should have correct payload length."""
        packets = list(parser.parse_pcap(str(tcp_handshake_pcap)))
        # SYN has no payload
        assert packets[0].payload_len == 0
        # Data packet with "GET / HTTP/1.1\r\n\r\n" = 18 bytes
        assert packets[3].payload_len == 18
        # Data packet with "HTTP/1.1 200 OK\r\n\r\nHello" = 24 bytes
        assert packets[4].payload_len == 24


class TestDpktParserVLAN:
    """VLAN-tagged frame parsing tests."""

    def test_vlan_tagged_frame(self, parser: DpktParser, tmp_path: Path) -> None:
        """Parser should handle 802.1Q VLAN-tagged frames."""
        pcap_path = tmp_path / "vlan.pcap"

        # Build a VLAN-tagged frame manually
        inner_pkt = make_tcp_packet(
            src_ip="10.1.1.1",
            dst_ip="10.1.1.2",
            src_port=8080,
            dst_port=80,
            flags=0x02,  # SYN
            seq=100,
            ack=0,
        )
        # Replace the EtherType with 802.1Q
        eth_dst = inner_pkt[:6]
        eth_src = inner_pkt[6:12]
        ip_payload = inner_pkt[14:]  # skip original ethertype

        # 802.1Q header: TPID (0x8100) + TCI (VLAN 100, priority 0)
        vlan_header = struct.pack("!HH", 0x8100, 100)
        ether_type_ip = struct.pack("!H", 0x0800)
        vlan_frame = eth_dst + eth_src + vlan_header + ether_type_ip + ip_payload

        write_pcap(pcap_path, [(1000.0, vlan_frame)])
        packets = list(parser.parse_pcap(str(pcap_path)))
        assert len(packets) == 1
        assert packets[0].src_ip == "10.1.1.1"
        assert packets[0].dst_ip == "10.1.1.2"
        assert packets[0].protocol == "TCP"


class TestDpktParserTruncated:
    """Truncated packet handling tests."""

    def test_truncated_packet_skipped(self, parser: DpktParser, tmp_path: Path) -> None:
        """Truncated/malformed packets should be skipped gracefully."""
        pcap_path = tmp_path / "truncated.pcap"

        # A valid packet
        valid = make_tcp_packet()
        # A truncated frame (too short for Ethernet)
        truncated = b"\x00\x01\x02"

        write_pcap(pcap_path, [(1000.0, valid), (1001.0, truncated), (1002.0, valid)])
        packets = list(parser.parse_pcap(str(pcap_path)))
        # Should get 2 valid packets, truncated one skipped
        assert len(packets) == 2


class TestDpktParserIPv6:
    """IPv6 parsing tests."""

    def test_ipv6_packet(self, parser: DpktParser, tmp_path: Path) -> None:
        """Parser should handle IPv6 TCP packets."""
        pcap_path = tmp_path / "ipv6.pcap"

        # Build an IPv6 + TCP packet manually
        import socket

        src_ip6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        dst_ip6 = socket.inet_pton(socket.AF_INET6, "2001:db8::2")

        # TCP header (SYN)
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            44444,  # src port
            8080,  # dst port
            5000,  # seq
            0,  # ack
            (5 << 4),  # data offset
            0x02,  # SYN
            65535,  # window
            0,  # checksum
            0,  # urgent
        )

        # IPv6 header
        ip6_header = struct.pack(
            "!IHBB16s16s",
            0x60000000,  # version(6) + traffic class + flow label
            len(tcp_header),  # payload length
            6,  # next header (TCP)
            64,  # hop limit
            src_ip6,
            dst_ip6,
        )

        # Ethernet frame with EtherType 0x86DD (IPv6)
        eth_header = (
            b"\x00\x11\x22\x33\x44\x55"
            + b"\x66\x77\x88\x99\xaa\xbb"
            + b"\x86\xdd"
        )
        frame = eth_header + ip6_header + tcp_header

        write_pcap(pcap_path, [(1000.0, frame)])
        packets = list(parser.parse_pcap(str(pcap_path)))
        assert len(packets) == 1
        pkt = packets[0]
        assert pkt.src_ip == "2001:db8::1"
        assert pkt.dst_ip == "2001:db8::2"
        assert pkt.src_port == 44444
        assert pkt.dst_port == 8080
        assert pkt.protocol == "TCP"
        assert pkt.tcp_flags == "SYN"


class TestDpktParserUDP:
    """UDP parsing tests."""

    def test_udp_packet(self, parser: DpktParser, tmp_path: Path) -> None:
        """Parser should handle UDP packets."""
        pcap_path = tmp_path / "udp.pcap"
        frame = make_udp_packet(payload=b"hello DNS")
        write_pcap(pcap_path, [(1000.0, frame)])

        packets = list(parser.parse_pcap(str(pcap_path)))
        assert len(packets) == 1
        pkt = packets[0]
        assert pkt.protocol == "UDP"
        assert pkt.src_port == 12345
        assert pkt.dst_port == 53
        assert pkt.payload_len == 9  # len("hello DNS")


class TestDpktParserMetadata:
    """Tests for parse_pcap_with_metadata."""

    def test_metadata_fields(self, parser: DpktParser, tcp_handshake_pcap: Path) -> None:
        packets, meta = parser.parse_pcap_with_metadata(str(tcp_handshake_pcap))
        assert meta.packet_count == 7
        assert meta.unique_flows == 1
        assert "TCP" in meta.protocols
        assert meta.protocols["TCP"] == 7
        assert meta.duration_seconds > 0
        assert meta.file_size_bytes > 0
