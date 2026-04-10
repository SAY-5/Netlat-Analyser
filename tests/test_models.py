"""Tests for netlat.flows.models."""

from __future__ import annotations

from netlat.flows.models import (
    AnomalyEvent,
    CaptureMetadata,
    FlowDirection,
    FlowKey,
    Packet,
    RetransmissionEvent,
    RTTSample,
)


class TestPacket:
    """Tests for the Packet dataclass."""

    def test_create_tcp_packet(self) -> None:
        pkt = Packet(
            timestamp=1000.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            ip_len=60,
            tcp_flags="SYN",
            seq=100,
            ack=0,
            payload_len=0,
            window=65535,
        )
        assert pkt.protocol == "TCP"
        assert pkt.tcp_flags == "SYN"
        assert pkt.seq == 100
        assert pkt.is_offloaded is False

    def test_create_udp_packet(self) -> None:
        pkt = Packet(
            timestamp=1000.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=53,
            protocol="UDP",
            ip_len=42,
            payload_len=14,
        )
        assert pkt.protocol == "UDP"
        assert pkt.tcp_flags is None
        assert pkt.seq is None

    def test_packet_defaults(self) -> None:
        pkt = Packet(
            timestamp=0.0,
            src_ip="0.0.0.0",
            dst_ip="0.0.0.0",
            src_port=0,
            dst_port=0,
            protocol="OTHER",
            ip_len=0,
        )
        assert pkt.tcp_options is None
        assert pkt.capture_len == 0
        assert pkt.is_offloaded is False


class TestFlowKey:
    """Tests for FlowKey normalization and properties."""

    def test_normalization_forward(self) -> None:
        """FlowKey should normalize so smaller (ip, port) pair is first."""
        pkt = Packet(
            timestamp=0.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            ip_len=60,
        )
        key = FlowKey.from_packet(pkt)
        assert key.ip_a == "10.0.0.1"
        assert key.port_a == 12345
        assert key.ip_b == "10.0.0.2"
        assert key.port_b == 80

    def test_normalization_reverse(self) -> None:
        """Swapping src/dst should produce the same FlowKey."""
        pkt_fwd = Packet(
            timestamp=0.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            ip_len=60,
        )
        pkt_rev = Packet(
            timestamp=0.0,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=12345,
            protocol="TCP",
            ip_len=60,
        )
        assert FlowKey.from_packet(pkt_fwd) == FlowKey.from_packet(pkt_rev)

    def test_flowkey_ipv6(self) -> None:
        """FlowKey should work with IPv6 addresses."""
        pkt = Packet(
            timestamp=0.0,
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
            src_port=443,
            dst_port=54321,
            protocol="TCP",
            ip_len=100,
        )
        key = FlowKey.from_packet(pkt)
        assert "2001:db8::1" in key.tuple_str
        assert "2001:db8::2" in key.tuple_str
        assert key.protocol == "TCP"

    def test_tuple_str_format(self) -> None:
        """tuple_str should be ip_a:port_a<->ip_b:port_b/PROTO."""
        key = FlowKey(
            ip_a="10.0.0.1",
            port_a=12345,
            ip_b="10.0.0.2",
            port_b=80,
            protocol="TCP",
        )
        assert key.tuple_str == "10.0.0.1:12345<->10.0.0.2:80/TCP"

    def test_flowkey_is_frozen(self) -> None:
        """FlowKey should be immutable (frozen dataclass)."""
        key = FlowKey(
            ip_a="10.0.0.1",
            port_a=12345,
            ip_b="10.0.0.2",
            port_b=80,
            protocol="TCP",
        )
        try:
            key.ip_a = "999.999.999.999"  # type: ignore[misc]
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass

    def test_flowkey_hashable(self) -> None:
        """FlowKey should be usable as dict key."""
        key = FlowKey(
            ip_a="10.0.0.1",
            port_a=12345,
            ip_b="10.0.0.2",
            port_b=80,
            protocol="TCP",
        )
        d = {key: "test"}
        assert d[key] == "test"

    def test_different_protocols_different_keys(self) -> None:
        """Same IPs/ports but different protocol should produce different keys."""
        pkt_tcp = Packet(
            timestamp=0.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            ip_len=60,
        )
        pkt_udp = Packet(
            timestamp=0.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=80,
            protocol="UDP",
            ip_len=60,
        )
        assert FlowKey.from_packet(pkt_tcp) != FlowKey.from_packet(pkt_udp)


class TestFlowDirection:
    def test_enum_values(self) -> None:
        assert FlowDirection.FORWARD.value == "forward"
        assert FlowDirection.REVERSE.value == "reverse"


class TestRTTSample:
    def test_create(self) -> None:
        key = FlowKey("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
        sample = RTTSample(timestamp=1000.0, rtt_ms=1.5, flow_key=key, seq=100)
        assert sample.rtt_ms == 1.5
        assert sample.method == "tcp_handshake"


class TestRetransmissionEvent:
    def test_create(self) -> None:
        key = FlowKey("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
        evt = RetransmissionEvent(timestamp=1000.0, flow_key=key, seq=500)
        assert evt.is_spurious is False


class TestAnomalyEvent:
    def test_create(self) -> None:
        key = FlowKey("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
        evt = AnomalyEvent(
            timestamp=1000.0,
            flow_key=key,
            anomaly_type="high_rtt",
            severity="high",
            description="RTT spike detected",
            value=150.0,
            threshold=50.0,
        )
        assert evt.anomaly_type == "high_rtt"


class TestCaptureMetadata:
    def test_defaults(self) -> None:
        meta = CaptureMetadata(file_path="/tmp/test.pcap")
        assert meta.packet_count == 0
        assert meta.protocols == {}
        assert meta.link_type == 1
