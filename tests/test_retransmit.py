"""Tests for Retransmission Detector (Phase 4)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from conftest import make_packet  # noqa: E402

from netlat.analysis.retransmit import RetransmissionDetector  # noqa: E402
from netlat.analysis.rtt import RTTEstimator  # noqa: E402
from netlat.flows.tracker import FlowTracker  # noqa: E402


def _setup():
    """Create common test objects."""
    return FlowTracker(), RTTEstimator(), RetransmissionDetector()


def _send_data(tracker, estimator, detector, seq, payload_len=100, timestamp=1.0,
               src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=12345, dst_port=80,
               flags="ACK", ack=2000):
    """Helper to send a data packet through all components."""
    pkt = make_packet(
        src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
        flags=flags, seq=seq, ack=ack, payload_len=payload_len, timestamp=timestamp,
    )
    flow, direction = tracker.process_packet(pkt)
    events = detector.on_packet(pkt, flow, direction, estimator)
    return flow, direction, events


def test_no_retransmission():
    """5 sequential data packets produce 0 retransmission events."""
    tracker, estimator, detector = _setup()

    for i in range(5):
        _, _, events = _send_data(
            tracker, estimator, detector,
            seq=1000 + i * 100,
            timestamp=1.0 + i * 0.001,
        )
        assert len(events) == 0

    assert len(detector.get_all_events()) == 0


def test_basic_retransmission():
    """Same seq sent twice produces 1 retransmission event."""
    tracker, estimator, detector = _setup()

    # First send
    _send_data(tracker, estimator, detector, seq=1000, timestamp=1.0)

    # Retransmit same seq
    _, _, events = _send_data(tracker, estimator, detector, seq=1000, timestamp=1.05)

    assert len(events) == 1
    assert events[0].seq == 1000
    assert events[0].original_timestamp == 1.0
    assert len(detector.get_all_events()) == 1


def test_fast_retransmit():
    """Data + 3 dup ACKs + retransmit -> classification 'fast_retransmit'."""
    tracker, estimator, detector = _setup()

    # Client sends data
    _send_data(tracker, estimator, detector, seq=1000, timestamp=1.0)

    # Client sends more data
    _send_data(tracker, estimator, detector, seq=1100, timestamp=1.001)

    # Server sends 4 ACKs with same ack value (1st sets baseline, next 3 are dups)
    for i in range(4):
        ack_pkt = make_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=12345,
            flags="ACK", seq=2000, ack=1000,
            payload_len=0, timestamp=1.002 + i * 0.001,
        )
        flow, direction = tracker.process_packet(ack_pkt)
        detector.on_packet(ack_pkt, flow, direction, estimator)

    # Client retransmits seq=1000
    _, _, events = _send_data(
        tracker, estimator, detector, seq=1000, timestamp=1.010
    )

    assert len(events) == 1
    assert events[0].classification == "fast_retransmit"


def test_timeout_rto():
    """Data + retransmit with 300ms gap -> classification 'timeout_rto'."""
    tracker, estimator, detector = _setup()

    # Client sends data
    _send_data(tracker, estimator, detector, seq=1000, timestamp=1.0)

    # Retransmit after 300ms (> 200ms rto_min)
    _, _, events = _send_data(
        tracker, estimator, detector, seq=1000, timestamp=1.3
    )

    assert len(events) == 1
    assert events[0].classification == "timeout_rto"
    assert events[0].gap_ms is not None
    assert events[0].gap_ms >= 200.0


def test_tail_loss():
    """Retransmit near max_seq -> classification 'tail_loss'."""
    tracker, estimator, detector = _setup()

    # Send a packet that sets max_seq high
    _send_data(tracker, estimator, detector, seq=5000, payload_len=100, timestamp=1.0)
    # max_seq is now 5100

    # Send data near max_seq
    _send_data(tracker, estimator, detector, seq=4000, payload_len=100, timestamp=1.001)

    # Retransmit seq=4000 (within 3*1460=4380 of max_seq=5100, diff=1100)
    # Gap is 50ms which is < 200ms rto_min, and no dup acks, so tail_loss
    _, _, events = _send_data(
        tracker, estimator, detector, seq=4000, timestamp=1.050
    )

    assert len(events) == 1
    assert events[0].classification == "tail_loss"


def test_summary_counts():
    """Multiple retransmissions produce correct summary counts."""
    tracker, estimator, detector = _setup()

    # Create a timeout_rto retransmission
    _send_data(tracker, estimator, detector, seq=1000, timestamp=1.0)
    _send_data(tracker, estimator, detector, seq=1000, timestamp=1.3)

    # Create another packet and retransmit with small gap (unknown or tail_loss)
    _send_data(tracker, estimator, detector, seq=2000, timestamp=2.0)
    _send_data(tracker, estimator, detector, seq=2000, timestamp=2.05)

    summary = detector.get_summary()
    assert summary["total"] == 2
    assert summary["flows_affected"] == 1
    assert isinstance(summary["by_classification"], dict)
    total_classified = sum(summary["by_classification"].values())
    assert total_classified == 2
