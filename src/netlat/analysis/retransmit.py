"""Retransmission detection and classification."""

from __future__ import annotations

from collections import defaultdict

from netlat.analysis.rtt import RTTEstimator
from netlat.flows.models import (
    FlowDirection,
    FlowKey,
    Packet,
    RetransmissionEvent,
)
from netlat.flows.tracker import DirectionState, FlowState


class RetransmissionDetector:
    """Detects and classifies TCP retransmissions."""

    def __init__(self, rto_min_ms: float = 200.0) -> None:
        self._rto_min_ms = rto_min_ms
        self._events: list[RetransmissionEvent] = []
        self._flow_events: dict[FlowKey, list[RetransmissionEvent]] = defaultdict(list)

    def on_packet(
        self,
        pkt: Packet,
        flow: FlowState,
        direction: FlowDirection,
        rtt_estimator: RTTEstimator,
    ) -> list[RetransmissionEvent]:
        """Process a packet and return any retransmission events detected."""
        events: list[RetransmissionEvent] = []

        if pkt.protocol != "TCP":
            return events

        # Only check data packets for retransmission
        if pkt.seq is None or pkt.payload_len <= 0:
            return events

        seq = pkt.seq
        end_seq = seq + pkt.payload_len

        # Get direction state
        if direction == FlowDirection.FORWARD:
            dir_state = flow.a_to_b
            opp_state = flow.b_to_a
        else:
            dir_state = flow.b_to_a
            opp_state = flow.a_to_b

        # Check if this seq range overlaps with any previously sent range
        original_timestamp: float | None = None
        found_overlap = False

        for prev_seq, prev_len, prev_ts in dir_state.recent_seqs:
            if prev_ts >= pkt.timestamp:
                # Not an earlier send
                continue
            prev_end = prev_seq + prev_len
            # Check overlap: [seq, end_seq) overlaps [prev_seq, prev_end)
            if seq < prev_end and end_seq > prev_seq:
                found_overlap = True
                if original_timestamp is None or prev_ts < original_timestamp:
                    original_timestamp = prev_ts
                break

        if not found_overlap:
            return events

        # It's a retransmission
        gap_ms: float | None = None
        if original_timestamp is not None:
            gap_ms = (pkt.timestamp - original_timestamp) * 1000.0

        # Classify
        classification = self._classify(
            pkt, flow, direction, dir_state, opp_state, gap_ms
        )

        is_spurious = False
        # Check for DSACK (SACK blocks echoing already-acked data)
        if pkt.tcp_options and "sack" in pkt.tcp_options:
            is_spurious = True
            classification = "spurious"

        event = RetransmissionEvent(
            timestamp=pkt.timestamp,
            flow_key=flow.key,
            seq=seq,
            original_timestamp=original_timestamp,
            is_spurious=is_spurious,
            classification=classification,
            gap_ms=gap_ms,
        )

        self._events.append(event)
        self._flow_events[flow.key].append(event)

        # Notify RTT estimator (Karn's algorithm)
        rtt_estimator.mark_retransmission(flow.key, direction, seq)

        # Increment flow retransmission counter
        flow.retransmissions += 1

        return [event]

    def _classify(
        self,
        pkt: Packet,
        flow: FlowState,
        direction: FlowDirection,
        dir_state: DirectionState,
        opp_state: DirectionState,
        gap_ms: float | None,
    ) -> str:
        """Classify the retransmission type."""
        # Fast retransmit: 3+ duplicate ACKs from opposite direction
        if opp_state.dup_ack_count >= 3:
            return "fast_retransmit"

        # Timeout/RTO: gap >= rto_min_ms
        if gap_ms is not None and gap_ms >= self._rto_min_ms:
            return "timeout_rto"

        # Tail loss: retransmitted seq near max_seq (within 3 * 1460 = 4380)
        seq = pkt.seq
        if seq is not None and dir_state.max_seq > 0:
            if dir_state.max_seq - seq <= 3 * 1460:
                return "tail_loss"

        return "unknown"

    def get_all_events(self) -> list[RetransmissionEvent]:
        """Return all retransmission events."""
        return list(self._events)

    def get_flow_events(self, flow_key: FlowKey) -> list[RetransmissionEvent]:
        """Return retransmission events for a specific flow."""
        return list(self._flow_events.get(flow_key, []))

    def get_summary(self) -> dict:
        """Return summary statistics."""
        classifications: dict[str, int] = defaultdict(int)
        for event in self._events:
            classifications[event.classification] += 1

        return {
            "total": len(self._events),
            "spurious": sum(1 for e in self._events if e.is_spurious),
            "by_classification": dict(classifications),
            "flows_affected": len(self._flow_events),
        }
