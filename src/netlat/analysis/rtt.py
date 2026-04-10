"""RTT estimation from TCP flows."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from netlat.flows.models import FlowDirection, FlowKey, Packet, RTTSample
from netlat.flows.tracker import FlowState


_MAX_RTT_MS = 60000.0
_MAX_TSVAL_ENTRIES = 1000


class RTTEstimator:
    """Estimates RTT using handshake, TCP timestamps, and seq/ack matching."""

    def __init__(self) -> None:
        # flow_key -> True if handshake RTT already emitted
        self._handshake_done: set[FlowKey] = set()
        # (flow_key, direction) -> {tsval: timestamp}
        self._tsval_map: dict[tuple[FlowKey, FlowDirection], dict[int, float]] = {}
        # (flow_key, direction) -> set of retransmitted seqs
        self._retransmitted: dict[tuple[FlowKey, FlowDirection], set[int]] = {}
        # All samples collected
        self._samples: list[RTTSample] = []

    def on_packet(
        self, pkt: Packet, flow: FlowState, direction: FlowDirection
    ) -> list[RTTSample]:
        """Process a packet and return any new RTT samples."""
        samples: list[RTTSample] = []

        if pkt.protocol != "TCP":
            return samples

        # 1. Handshake RTT
        hs = self._check_handshake(pkt, flow)
        if hs is not None:
            samples.append(hs)

        # 2. TCP Timestamp RTT
        ts = self._check_timestamp_rtt(pkt, flow, direction)
        if ts is not None:
            samples.append(ts)

        # 3. Seq/ACK RTT
        sa = self._check_seq_ack_rtt(pkt, flow, direction)
        if sa is not None:
            samples.append(sa)

        # Record this packet's TSval for future matching
        self._record_tsval(pkt, flow.key, direction)

        self._samples.extend(samples)
        return samples

    def mark_retransmission(
        self, flow_key: FlowKey, direction: FlowDirection, seq: int
    ) -> None:
        """Mark a seq as retransmitted so Karn's algorithm filters it."""
        rkey = (flow_key, direction)
        if rkey not in self._retransmitted:
            self._retransmitted[rkey] = set()
        self._retransmitted[rkey].add(seq)

    def get_all_samples(self) -> list[RTTSample]:
        """Return all collected RTT samples."""
        return list(self._samples)

    def get_flow_samples(self, flow_key: FlowKey) -> list[RTTSample]:
        """Return RTT samples for a specific flow."""
        return [s for s in self._samples if s.flow_key == flow_key]

    # --- Internal methods ---

    def _check_handshake(self, pkt: Packet, flow: FlowState) -> RTTSample | None:
        """Emit handshake RTT once when flow becomes established."""
        if flow.key in self._handshake_done:
            return None
        if (
            flow.state == "established"
            and flow.established_timestamp is not None
            and flow.syn_timestamp is not None
            and flow.handshake_rtt_ms is not None
        ):
            rtt_ms = flow.handshake_rtt_ms
            if not self._valid_rtt(rtt_ms):
                return None
            self._handshake_done.add(flow.key)
            return RTTSample(
                timestamp=flow.established_timestamp,
                rtt_ms=rtt_ms,
                flow_key=flow.key,
                seq=None,
                method="tcp_handshake",
            )
        return None

    def _record_tsval(
        self, pkt: Packet, flow_key: FlowKey, direction: FlowDirection
    ) -> None:
        """Store TSval → timestamp mapping for this direction."""
        if pkt.tcp_options and "timestamp" in pkt.tcp_options:
            tsval, _ = pkt.tcp_options["timestamp"]
            if tsval and tsval > 0:
                mkey = (flow_key, direction)
                if mkey not in self._tsval_map:
                    self._tsval_map[mkey] = {}
                m = self._tsval_map[mkey]
                m[tsval] = pkt.timestamp
                # Bound memory
                if len(m) > _MAX_TSVAL_ENTRIES:
                    # Remove oldest entries
                    sorted_keys = sorted(m.keys())
                    for k in sorted_keys[: len(m) - _MAX_TSVAL_ENTRIES]:
                        del m[k]

    def _check_timestamp_rtt(
        self, pkt: Packet, flow: FlowState, direction: FlowDirection
    ) -> RTTSample | None:
        """Check TCP timestamp echo for RTT measurement."""
        if not pkt.tcp_options or "timestamp" not in pkt.tcp_options:
            return None
        _tsval, tsecr = pkt.tcp_options["timestamp"]
        if not tsecr or tsecr <= 0:
            return None

        # Karn's: skip if this packet's seq was retransmitted
        if pkt.seq is not None:
            rkey = (flow.key, direction)
            if rkey in self._retransmitted and pkt.seq in self._retransmitted[rkey]:
                return None

        # Look up TSecr in the opposite direction's TSval map
        opposite = (
            FlowDirection.REVERSE
            if direction == FlowDirection.FORWARD
            else FlowDirection.FORWARD
        )
        opp_key = (flow.key, opposite)
        opp_map = self._tsval_map.get(opp_key, {})
        if tsecr in opp_map:
            original_ts = opp_map[tsecr]
            rtt_ms = (pkt.timestamp - original_ts) * 1000.0
            if not self._valid_rtt(rtt_ms):
                return None
            return RTTSample(
                timestamp=pkt.timestamp,
                rtt_ms=rtt_ms,
                flow_key=flow.key,
                seq=pkt.seq,
                method="tcp_timestamp",
            )
        return None

    def _check_seq_ack_rtt(
        self, pkt: Packet, flow: FlowState, direction: FlowDirection
    ) -> RTTSample | None:
        """Match ACK to in-flight data for seq/ack RTT."""
        if pkt.ack is None:
            return None

        # The ACK acknowledges data from the opposite direction
        opposite = (
            FlowDirection.REVERSE
            if direction == FlowDirection.FORWARD
            else FlowDirection.FORWARD
        )
        if opposite == FlowDirection.FORWARD:
            opp_state = flow.a_to_b
        else:
            opp_state = flow.b_to_a

        ack_val = pkt.ack
        best_match: tuple[float, int] | None = None

        for seq, (send_ts, plen) in list(opp_state.in_flight.items()):
            # ACK covers data from seq to seq+plen
            if ack_val >= seq + plen:
                # Karn's: skip retransmitted seqs
                rkey = (flow.key, opposite)
                if rkey in self._retransmitted and seq in self._retransmitted[rkey]:
                    continue
                if best_match is None or send_ts < best_match[0]:
                    best_match = (send_ts, seq)

        if best_match is not None:
            send_ts, matched_seq = best_match
            rtt_ms = (pkt.timestamp - send_ts) * 1000.0
            if not self._valid_rtt(rtt_ms):
                return None
            # Remove matched entry from in-flight
            opp_state.in_flight.pop(matched_seq, None)
            return RTTSample(
                timestamp=pkt.timestamp,
                rtt_ms=rtt_ms,
                flow_key=flow.key,
                seq=matched_seq,
                method="data_ack",
            )
        return None

    @staticmethod
    def _valid_rtt(rtt_ms: float) -> bool:
        """Guard: no negative or absurdly large RTT."""
        return 0.0 < rtt_ms <= _MAX_RTT_MS
