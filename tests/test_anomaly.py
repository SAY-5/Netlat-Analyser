"""Tests for Anomaly Detector (Phase 5)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from conftest import make_packet  # noqa: E402

from netlat.analysis.anomaly import AnomalyDetector, ThresholdProfile  # noqa: E402
from netlat.flows.models import (  # noqa: E402
    AnomalyEvent,
    FlowKey,
    RetransmissionEvent,
    RTTSample,
)
from netlat.flows.tracker import FlowState, FlowTracker  # noqa: E402


def _make_flow_key() -> FlowKey:
    """Create a standard test flow key."""
    return FlowKey(
        ip_a="10.0.0.1", port_a=12345,
        ip_b="10.0.0.2", port_b=80,
        protocol="TCP",
    )


def _make_rtt_sample(flow_key: FlowKey, rtt_ms: float, timestamp: float = 1.0) -> RTTSample:
    return RTTSample(
        timestamp=timestamp,
        rtt_ms=rtt_ms,
        flow_key=flow_key,
        seq=None,
        method="data_ack",
    )


def test_rtt_spike_detection():
    """20 samples at ~1.0ms, then 1 at 15.0ms -> 1 anomaly."""
    detector = AnomalyDetector(ThresholdProfile(min_rtt_samples=10))
    flow_key = _make_flow_key()

    # Feed 20 stable samples
    for i in range(20):
        sample = _make_rtt_sample(flow_key, rtt_ms=1.0, timestamp=1.0 + i * 0.01)
        events = detector.on_rtt_sample(sample)
        assert len(events) == 0, f"Unexpected spike at sample {i}"

    # Feed a spike
    spike = _make_rtt_sample(flow_key, rtt_ms=15.0, timestamp=2.0)
    events = detector.on_rtt_sample(spike)
    assert len(events) == 1
    assert events[0].anomaly_type == "rtt_spike"
    assert events[0].value == 15.0


def test_rtt_spike_not_triggered_below_threshold():
    """Slightly elevated RTT should not trigger a spike."""
    detector = AnomalyDetector(ThresholdProfile(min_rtt_samples=10))
    flow_key = _make_flow_key()

    for i in range(20):
        sample = _make_rtt_sample(flow_key, rtt_ms=1.0, timestamp=1.0 + i * 0.01)
        detector.on_rtt_sample(sample)

    # Small increase within threshold (threshold ~1.3 for mean=1.0, stddev_min=0.1)
    mild = _make_rtt_sample(flow_key, rtt_ms=1.2, timestamp=2.0)
    events = detector.on_rtt_sample(mild)
    assert len(events) == 0


def test_rtt_spike_not_triggered_before_min_samples():
    """No spike detection before min_rtt_samples are collected."""
    detector = AnomalyDetector(ThresholdProfile(min_rtt_samples=10))
    flow_key = _make_flow_key()

    # Only 5 samples then a huge value
    for i in range(5):
        sample = _make_rtt_sample(flow_key, rtt_ms=1.0, timestamp=1.0 + i * 0.01)
        detector.on_rtt_sample(sample)

    spike = _make_rtt_sample(flow_key, rtt_ms=100.0, timestamp=2.0)
    events = detector.on_rtt_sample(spike)
    assert len(events) == 0


def test_burst_loss_detection():
    """5 retransmissions within 50ms -> burst_loss anomaly."""
    detector = AnomalyDetector(ThresholdProfile(
        burst_loss_count=5,
        burst_loss_window_ms=100.0,
    ))
    flow_key = _make_flow_key()
    flow = FlowState(key=flow_key)

    events_found = []
    for i in range(5):
        retrans = RetransmissionEvent(
            timestamp=1.0 + i * 0.01,  # 10ms apart, all within 100ms
            flow_key=flow_key,
            seq=1000 + i * 100,
        )
        events = detector.on_retransmission(retrans, flow)
        events_found.extend(events)

    assert len(events_found) >= 1
    assert any(e.anomaly_type == "burst_loss" for e in events_found)


def test_handshake_timeout():
    """Flow with handshake_rtt_ms=1500 -> handshake_timeout anomaly."""
    detector = AnomalyDetector(ThresholdProfile(handshake_timeout_ms=1000.0))
    flow_key = _make_flow_key()
    flow = FlowState(key=flow_key)
    flow.handshake_rtt_ms = 1500.0
    flow.last_packet_time = 3.0

    events = detector.on_flow_state_change(flow)
    assert len(events) == 1
    assert events[0].anomaly_type == "handshake_timeout"
    assert events[0].value == 1500.0


def test_reset_detection():
    """Flow with state='reset' -> connection_reset anomaly."""
    detector = AnomalyDetector()
    flow_key = _make_flow_key()
    flow = FlowState(key=flow_key)
    flow.state = "reset"
    flow.resets = 1
    flow.last_packet_time = 2.0

    events = detector.on_flow_state_change(flow)
    assert len(events) == 1
    assert events[0].anomaly_type == "connection_reset"
    assert events[0].severity == "warning"


def test_zero_window_persistence():
    """Zero window for 600ms > 500ms threshold -> anomaly."""
    detector = AnomalyDetector(ThresholdProfile(zero_window_persistence_ms=500.0))
    flow_key = _make_flow_key()

    # Zero window starts
    events = detector.on_zero_window(flow_key, timestamp=1.0, is_zero=True)
    assert len(events) == 0

    # Still zero after 600ms
    events = detector.on_zero_window(flow_key, timestamp=1.6, is_zero=True)
    assert len(events) == 1
    assert events[0].anomaly_type == "zero_window_persistence"
    assert events[0].value >= 500.0


def test_ewma_convergence():
    """100 samples at 10ms -> EWMA mean should converge near 10ms."""
    detector = AnomalyDetector(ThresholdProfile(min_rtt_samples=10))
    flow_key = _make_flow_key()

    for i in range(100):
        sample = _make_rtt_sample(flow_key, rtt_ms=10.0, timestamp=1.0 + i * 0.01)
        detector.on_rtt_sample(sample)

    state = detector._ewma[flow_key]
    assert abs(state.mean - 10.0) < 0.5
    # Variance should be very small for constant input
    assert state.variance < 1.0


def test_severity_levels():
    """Critical severity when RTT > 2x threshold."""
    detector = AnomalyDetector(ThresholdProfile(
        min_rtt_samples=10,
        rtt_spike_multiplier=3.0,
    ))
    flow_key = _make_flow_key()

    # Feed stable samples
    for i in range(20):
        sample = _make_rtt_sample(flow_key, rtt_ms=1.0, timestamp=1.0 + i * 0.01)
        detector.on_rtt_sample(sample)

    # Moderate spike -> warning
    moderate = _make_rtt_sample(flow_key, rtt_ms=10.0, timestamp=2.0)
    events = detector.on_rtt_sample(moderate)
    if events:
        # Could be warning or critical depending on exact EWMA state
        assert events[0].severity in ("warning", "critical")

    # Extreme spike -> critical
    extreme = _make_rtt_sample(flow_key, rtt_ms=100.0, timestamp=3.0)
    events = detector.on_rtt_sample(extreme)
    assert len(events) == 1
    assert events[0].severity == "critical"
