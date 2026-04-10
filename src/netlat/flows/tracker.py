"""Flow tracking and TCP state machine."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from netlat.flows.models import FlowDirection, FlowKey, Packet


@dataclass
class DirectionState:
    """Per-direction state within a flow."""

    packets_seen: int = 0
    bytes_seen: int = 0
    max_seq: int = 0
    last_seq: int = 0
    last_ack: int = 0
    last_timestamp: float = 0.0
    last_tsval: int = 0
    in_flight: dict[int, tuple[float, int]] = field(default_factory=dict)
    recent_seqs: deque[tuple[int, int, float]] = field(
        default_factory=lambda: deque(maxlen=1000)
    )
    sack_blocks: list[tuple[int, int]] = field(default_factory=list)
    dup_ack_count: int = 0
    last_dup_ack_value: int = 0


@dataclass
class FlowState:
    """Full state of a tracked flow."""

    key: FlowKey
    state: str = "unknown"
    a_to_b: DirectionState = field(default_factory=DirectionState)
    b_to_a: DirectionState = field(default_factory=DirectionState)
    syn_timestamp: float | None = None
    syn_ack_timestamp: float | None = None
    established_timestamp: float | None = None
    handshake_rtt_ms: float | None = None
    first_packet_time: float = 0.0
    last_packet_time: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    retransmissions: int = 0
    zero_windows: int = 0
    resets: int = 0


class FlowTracker:
    """Tracks flows and manages TCP state transitions."""

    def __init__(self, max_flows: int = 100_000, flow_timeout_s: float = 300.0):
        self._flows: dict[FlowKey, FlowState] = {}
        self._max_flows = max_flows
        self._flow_timeout_s = flow_timeout_s

    def process_packet(self, pkt: Packet) -> tuple[FlowState, FlowDirection]:
        """Process a packet and return (FlowState, FlowDirection)."""
        key = FlowKey.from_packet(pkt)

        # Evict oldest flow if at capacity
        if key not in self._flows and len(self._flows) >= self._max_flows:
            self._evict_oldest()

        # Get or create flow
        if key not in self._flows:
            flow = FlowState(key=key, first_packet_time=pkt.timestamp)
            self._flows[key] = flow
        else:
            flow = self._flows[key]

        # Determine direction
        if pkt.src_ip == key.ip_a and pkt.src_port == key.port_a:
            direction = FlowDirection.FORWARD
            dir_state = flow.a_to_b
        else:
            direction = FlowDirection.REVERSE
            dir_state = flow.b_to_a

        # Update counters
        flow.total_packets += 1
        flow.total_bytes += pkt.ip_len
        flow.last_packet_time = pkt.timestamp
        dir_state.packets_seen += 1
        dir_state.bytes_seen += pkt.ip_len
        dir_state.last_timestamp = pkt.timestamp

        # Protocol-specific handling
        if pkt.protocol == "UDP":
            if flow.state == "unknown":
                flow.state = "established"
        elif pkt.protocol == "TCP":
            self._process_tcp(pkt, flow, direction, dir_state)

        return flow, direction

    def _process_tcp(
        self,
        pkt: Packet,
        flow: FlowState,
        direction: FlowDirection,
        dir_state: DirectionState,
    ) -> None:
        """Handle TCP-specific state and tracking."""
        flags = pkt.tcp_flags or ""

        # TCP state machine
        has_syn = "SYN" in flags
        has_ack = "ACK" in flags
        has_fin = "FIN" in flags
        has_rst = "RST" in flags

        if has_rst:
            flow.state = "reset"
            flow.resets += 1
        elif has_syn and not has_ack:
            # SYN
            flow.state = "syn_sent"
            flow.syn_timestamp = pkt.timestamp
        elif has_syn and has_ack:
            # SYN-ACK
            flow.state = "syn_ack_sent"
            flow.syn_ack_timestamp = pkt.timestamp
        elif has_ack and flow.state == "syn_ack_sent" and not has_syn and not has_fin:
            # Completing handshake
            flow.state = "established"
            flow.established_timestamp = pkt.timestamp
            if flow.syn_timestamp is not None:
                flow.handshake_rtt_ms = (pkt.timestamp - flow.syn_timestamp) * 1000.0
        elif has_fin:
            flow.state = "closing"

        # Zero window detection
        if pkt.window is not None and pkt.window == 0:
            flow.zero_windows += 1

        # Seq tracking
        if pkt.seq is not None:
            seq = pkt.seq
            end_seq = seq + max(pkt.payload_len, 0)
            dir_state.last_seq = seq
            if end_seq > dir_state.max_seq:
                dir_state.max_seq = end_seq

            # Track in-flight data segments
            if pkt.payload_len > 0:
                dir_state.in_flight[seq] = (pkt.timestamp, pkt.payload_len)
                dir_state.recent_seqs.append((seq, pkt.payload_len, pkt.timestamp))

        # ACK tracking
        if pkt.ack is not None:
            ack_val = pkt.ack
            # Dup ACK detection: same ACK value with no payload
            if pkt.payload_len == 0 and ack_val == dir_state.last_dup_ack_value:
                dir_state.dup_ack_count += 1
            else:
                dir_state.last_dup_ack_value = ack_val
                dir_state.dup_ack_count = 0
            dir_state.last_ack = ack_val

        # TSval tracking
        if pkt.tcp_options and "timestamp" in pkt.tcp_options:
            tsval, _tsecr = pkt.tcp_options["timestamp"]
            if tsval:
                dir_state.last_tsval = tsval

    def get_flow(self, key: FlowKey) -> FlowState | None:
        """Look up a flow by key."""
        return self._flows.get(key)

    def get_all_flows(self) -> list[FlowState]:
        """Return all tracked flows."""
        return list(self._flows.values())

    def evict_stale(self, current_time: float) -> int:
        """Remove flows that haven't seen traffic within flow_timeout_s."""
        stale_keys = [
            k
            for k, f in self._flows.items()
            if (current_time - f.last_packet_time) > self._flow_timeout_s
        ]
        for k in stale_keys:
            del self._flows[k]
        return len(stale_keys)

    def _evict_oldest(self) -> None:
        """Evict the flow with the oldest last_packet_time."""
        if not self._flows:
            return
        oldest_key = min(self._flows, key=lambda k: self._flows[k].last_packet_time)
        del self._flows[oldest_key]
