"""Core data models for netlat flow analysis."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Packet:
    """A single parsed network packet."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP", "UDP", "ICMP", "OTHER"
    ip_len: int
    tcp_flags: str | None = None  # e.g. "SYN", "SYN-ACK", "ACK", "FIN-ACK", "RST"
    seq: int | None = None
    ack: int | None = None
    payload_len: int = 0
    window: int | None = None
    tcp_options: dict[str, Any] | None = None
    is_offloaded: bool = False
    capture_len: int = 0


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Normalized 5-tuple flow identifier.

    The key is normalized so that the smaller (ip, port) pair always comes first,
    making FlowKey(A->B) == FlowKey(B->A).
    """

    ip_a: str
    port_a: int
    ip_b: str
    port_b: int
    protocol: str

    @staticmethod
    def from_packet(pkt: Packet) -> FlowKey:
        """Create a normalized FlowKey from a Packet."""
        src = (pkt.src_ip, pkt.src_port)
        dst = (pkt.dst_ip, pkt.dst_port)
        if src <= dst:
            return FlowKey(
                ip_a=pkt.src_ip,
                port_a=pkt.src_port,
                ip_b=pkt.dst_ip,
                port_b=pkt.dst_port,
                protocol=pkt.protocol,
            )
        return FlowKey(
            ip_a=pkt.dst_ip,
            port_a=pkt.dst_port,
            ip_b=pkt.src_ip,
            port_b=pkt.src_port,
            protocol=pkt.protocol,
        )

    @property
    def tuple_str(self) -> str:
        """Human-readable 5-tuple string."""
        return f"{self.ip_a}:{self.port_a}<->{self.ip_b}:{self.port_b}/{self.protocol}"


class FlowDirection(enum.Enum):
    """Direction of a packet relative to the flow originator."""

    FORWARD = "forward"
    REVERSE = "reverse"


@dataclass(slots=True)
class RTTSample:
    """A single RTT measurement from a request-response pair."""

    timestamp: float
    rtt_ms: float
    flow_key: FlowKey
    seq: int | None = None
    method: str = "tcp_handshake"  # tcp_handshake, tcp_timestamp, data_ack


@dataclass(slots=True)
class RetransmissionEvent:
    """A detected retransmission."""

    timestamp: float
    flow_key: FlowKey
    seq: int
    original_timestamp: float | None = None
    is_spurious: bool = False
    classification: str = "unknown"
    gap_ms: float | None = None


@dataclass(slots=True)
class AnomalyEvent:
    """A detected anomaly in the traffic."""

    timestamp: float
    flow_key: FlowKey
    anomaly_type: str  # "high_rtt", "retransmission_burst", "zero_window", "rst_flood"
    severity: str  # "low", "medium", "high", "critical"
    description: str
    value: float = 0.0
    threshold: float = 0.0


@dataclass(slots=True)
class CaptureMetadata:
    """Metadata about a pcap capture file."""

    file_path: str
    file_size_bytes: int = 0
    link_type: int = 1  # DLT_EN10MB
    snaplen: int = 65535
    packet_count: int = 0
    first_timestamp: float = 0.0
    last_timestamp: float = 0.0
    duration_seconds: float = 0.0
    truncated_packets: int = 0
    parse_errors: int = 0
    unique_flows: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
