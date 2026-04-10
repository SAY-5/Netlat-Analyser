"""Anomaly detection for network traffic patterns."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from netlat.flows.models import (
    AnomalyEvent,
    FlowKey,
    RTTSample,
    RetransmissionEvent,
)
from netlat.flows.tracker import FlowState


@dataclass
class ThresholdProfile:
    """Configurable thresholds for anomaly detection."""

    rtt_spike_multiplier: float = 3.0
    retrans_pct_threshold: float = 1.0
    burst_loss_count: int = 5
    burst_loss_window_ms: float = 100.0
    handshake_timeout_ms: float = 1000.0
    min_rtt_samples: int = 10
    zero_window_persistence_ms: float = 500.0


@dataclass
class _EWMAState:
    """Exponentially weighted moving average state for RTT tracking."""

    mean: float = 0.0
    variance: float = 0.0
    count: int = 0
    alpha: float = 0.1  # smoothing factor

    def update(self, value: float) -> None:
        self.count += 1
        if self.count == 1:
            self.mean = value
            self.variance = 0.0
        else:
            diff = value - self.mean
            self.mean += self.alpha * diff
            self.variance = (1 - self.alpha) * (self.variance + self.alpha * diff * diff)


class AnomalyDetector:
    """Detects anomalies in network traffic patterns."""

    def __init__(self, default_profile: ThresholdProfile | None = None) -> None:
        self._profile = default_profile or ThresholdProfile()
        self._events: list[AnomalyEvent] = []
        self._ewma: dict[FlowKey, _EWMAState] = {}
        self._rtt_count: dict[FlowKey, int] = defaultdict(int)
        self._retrans_history: dict[FlowKey, list[float]] = defaultdict(list)
        self._zero_window_start: dict[FlowKey, float] = {}
        self._handshake_alerted: set[FlowKey] = set()
        self._reset_alerted: set[FlowKey] = set()

    def on_rtt_sample(self, sample: RTTSample) -> list[AnomalyEvent]:
        """Check an RTT sample for anomalies using EWMA."""
        events: list[AnomalyEvent] = []
        flow_key = sample.flow_key

        if flow_key not in self._ewma:
            self._ewma[flow_key] = _EWMAState()

        state = self._ewma[flow_key]
        self._rtt_count[flow_key] += 1

        # Update EWMA before checking (so state converges)
        old_mean = state.mean
        old_variance = state.variance
        state.update(sample.rtt_ms)

        # Only check after min_rtt_samples
        if self._rtt_count[flow_key] >= self._profile.min_rtt_samples:
            # Use old mean/variance for threshold (before this sample pollutes it)
            if old_mean > 0:
                stddev = max(math.sqrt(old_variance), old_mean * 0.1)
                threshold = old_mean + self._profile.rtt_spike_multiplier * stddev
                if sample.rtt_ms > threshold:
                    # Determine severity
                    ratio = sample.rtt_ms / threshold if threshold > 0 else 1.0
                    if ratio > 2.0:
                        severity = "critical"
                    else:
                        severity = "warning"

                    event = AnomalyEvent(
                        timestamp=sample.timestamp,
                        flow_key=flow_key,
                        anomaly_type="rtt_spike",
                        severity=severity,
                        description=(
                            f"RTT spike: {sample.rtt_ms:.1f}ms "
                            f"(threshold {threshold:.1f}ms, mean {old_mean:.1f}ms)"
                        ),
                        value=sample.rtt_ms,
                        threshold=threshold,
                    )
                    events.append(event)
                    self._events.append(event)

        return events

    def on_retransmission(
        self, event: RetransmissionEvent, flow: FlowState
    ) -> list[AnomalyEvent]:
        """Check a retransmission event for burst detection."""
        events: list[AnomalyEvent] = []
        flow_key = event.flow_key
        history = self._retrans_history[flow_key]
        history.append(event.timestamp)

        # Check for burst: N retransmissions within a window
        window_s = self._profile.burst_loss_window_ms / 1000.0
        recent = [t for t in history if event.timestamp - t <= window_s]
        if len(recent) >= self._profile.burst_loss_count:
            anomaly = AnomalyEvent(
                timestamp=event.timestamp,
                flow_key=flow_key,
                anomaly_type="burst_loss",
                severity="critical",
                description=(
                    f"Burst loss: {len(recent)} retransmissions "
                    f"within {self._profile.burst_loss_window_ms:.0f}ms"
                ),
                value=float(len(recent)),
                threshold=float(self._profile.burst_loss_count),
            )
            events.append(anomaly)
            self._events.append(anomaly)
            # Clear to avoid re-firing
            self._retrans_history[flow_key] = []

        return events

    def on_flow_state_change(self, flow: FlowState) -> list[AnomalyEvent]:
        """Check for anomalies on flow state changes."""
        events: list[AnomalyEvent] = []

        # Detect slow handshakes (any state with handshake_rtt_ms set)
        if (
            flow.handshake_rtt_ms is not None
            and flow.handshake_rtt_ms > self._profile.handshake_timeout_ms
            and flow.key not in self._handshake_alerted
        ):
            self._handshake_alerted.add(flow.key)
            event = AnomalyEvent(
                timestamp=flow.established_timestamp or flow.last_packet_time,
                flow_key=flow.key,
                anomaly_type="handshake_timeout",
                severity="warning",
                description=(
                    f"Slow TCP handshake: {flow.handshake_rtt_ms:.1f}ms "
                    f"(>{self._profile.handshake_timeout_ms:.0f}ms threshold)"
                ),
                value=flow.handshake_rtt_ms,
                threshold=self._profile.handshake_timeout_ms,
            )
            events.append(event)
            self._events.append(event)

        # Detect connection resets
        if (
            flow.state == "reset"
            and flow.resets > 0
            and flow.key not in self._reset_alerted
        ):
            self._reset_alerted.add(flow.key)
            event = AnomalyEvent(
                timestamp=flow.last_packet_time,
                flow_key=flow.key,
                anomaly_type="connection_reset",
                severity="warning",
                description=f"Connection reset detected (resets={flow.resets})",
                value=float(flow.resets),
                threshold=0.0,
            )
            events.append(event)
            self._events.append(event)

        return events

    def on_zero_window(
        self, flow_key: FlowKey, timestamp: float, is_zero: bool
    ) -> list[AnomalyEvent]:
        """Check for zero-window persistence anomalies."""
        events: list[AnomalyEvent] = []

        if is_zero:
            if flow_key not in self._zero_window_start:
                # First zero window - record start, no event yet
                self._zero_window_start[flow_key] = timestamp
            else:
                # Check persistence
                start_ts = self._zero_window_start[flow_key]
                duration_ms = (timestamp - start_ts) * 1000.0
                if duration_ms >= self._profile.zero_window_persistence_ms:
                    event = AnomalyEvent(
                        timestamp=timestamp,
                        flow_key=flow_key,
                        anomaly_type="zero_window_persistence",
                        severity="warning",
                        description=(
                            f"Zero window persisted for {duration_ms:.0f}ms "
                            f"(>{self._profile.zero_window_persistence_ms:.0f}ms)"
                        ),
                        value=duration_ms,
                        threshold=self._profile.zero_window_persistence_ms,
                    )
                    events.append(event)
                    self._events.append(event)
                    # Reset so we can detect again
                    self._zero_window_start[flow_key] = timestamp
        else:
            # Window opened, clear tracking
            self._zero_window_start.pop(flow_key, None)

        return events

    def get_all_events(self) -> list[AnomalyEvent]:
        """Return all detected anomaly events."""
        return list(self._events)

    def get_summary(self) -> dict:
        """Return summary statistics."""
        by_type: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        for event in self._events:
            by_type[event.anomaly_type] += 1
            by_severity[event.severity] += 1
        return {
            "total": len(self._events),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
        }
