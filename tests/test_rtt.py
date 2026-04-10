"""Tests for RTT Estimator (Phase 3)."""

from __future__ import annotations

import sys
from pathlib import Path

# Make conftest importable
sys.path.insert(0, str(Path(__file__).parent))

from conftest import make_packet  # noqa: E402

from netlat.analysis.rtt import RTTEstimator  # noqa: E402
from netlat.flows.models import FlowDirection, FlowKey  # noqa: E402
from netlat.flows.tracker import FlowTracker  # noqa: E402


def _do_handshake(tracker: FlowTracker, syn_ts=0.0, synack_ts=0.001, ack_ts=0.002):
    """Helper: complete TCP 3-way handshake, return final (flow, direction)."""
    syn = make_packet(flags="SYN", seq=100, ack=0, payload_len=0, timestamp=syn_ts)
    tracker.process_packet(syn)

    syn_ack = make_packet(
        src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=12345,
        flags="SYN-ACK", seq=200, ack=101,
        payload_len=0, timestamp=synack_ts,
    )
    tracker.process_packet(syn_ack)

    ack = make_packet(flags="ACK", seq=101, ack=201, payload_len=0, timestamp=ack_ts)
    flow, direction = tracker.process_packet(ack)
    return flow, direction


def test_handshake_rtt():
    """SYN t=0, SYN-ACK t=0.001, ACK t=0.002 -> 2.0ms handshake RTT."""
    tracker = FlowTracker()
    estimator = RTTEstimator()

    syn = make_packet(flags="SYN", seq=100, ack=0, payload_len=0, timestamp=0.0)
    flow, direction = tracker.process_packet(syn)
    samples = estimator.on_packet(syn, flow, direction)
    assert len(samples) == 0

    syn_ack = make_packet(
        src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=12345,
        flags="SYN-ACK", seq=200, ack=101,
        payload_len=0, timestamp=0.001,
    )
    flow, direction = tracker.process_packet(syn_ack)
    samples = estimator.on_packet(syn_ack, flow, direction)
    assert len(samples) == 0

    ack = make_packet(flags="ACK", seq=101, ack=201, payload_len=0, timestamp=0.002)
    flow, direction = tracker.process_packet(ack)
    samples = estimator.on_packet(ack, flow, direction)

    hs_samples = [s for s in samples if s.method == "tcp_handshake"]
    assert len(hs_samples) == 1
    assert abs(hs_samples[0].rtt_ms - 2.0) < 0.01


def test_timestamp_rtt_basic():
    """Packets with TSval/TSecr produce tcp_timestamp RTT samples."""
    tracker = FlowTracker()
    estimator = RTTEstimator()

    # Complete handshake first
    _do_handshake(tracker)
    # We need to also run estimator on handshake but skip for simplicity;
    # just mark handshake done by doing it properly
    tracker2 = FlowTracker()
    estimator2 = RTTEstimator()

    # Client sends data with TSval=100
    data_pkt = make_packet(
        seq=1000, ack=2000, payload_len=100, timestamp=1.0,
        tsval=100, tsecr=0,
    )
    flow, direction = tracker2.process_packet(data_pkt)
    estimator2.on_packet(data_pkt, flow, direction)

    # Server replies with TSecr=100 (echoing client's TSval)
    reply = make_packet(
        src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=12345,
        seq=2000, ack=1100, payload_len=0, timestamp=1.005,
        tsval=200, tsecr=100,
    )
    flow, direction = tracker2.process_packet(reply)
    samples = estimator2.on_packet(reply, flow, direction)

    ts_samples = [s for s in samples if s.method == "tcp_timestamp"]
    assert len(ts_samples) == 1
    assert abs(ts_samples[0].rtt_ms - 5.0) < 0.01


def test_timestamp_rtt_filtered_on_retransmit():
    """Marking a seq as retransmitted filters out the timestamp RTT sample."""
    tracker = FlowTracker()
    estimator = RTTEstimator()

    # Client sends data with TSval=100
    data_pkt = make_packet(
        seq=1000, ack=2000, payload_len=100, timestamp=1.0,
        tsval=100, tsecr=0,
    )
    flow, direction = tracker.process_packet(data_pkt)
    estimator.on_packet(data_pkt, flow, direction)

    # Mark the server's reply seq as retransmitted (Karn's on the reply direction)
    # Actually Karn's says: if the packet echoing TSecr was itself retransmitted, skip.
    # Let's mark the server's seq as retransmitted
    reply = make_packet(
        src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=12345,
        seq=2000, ack=1100, payload_len=0, timestamp=1.005,
        tsval=200, tsecr=100,
    )
    flow_after, reply_dir = tracker.process_packet(reply)
    # Mark this reply's seq as retransmitted in its direction
    estimator.mark_retransmission(flow_after.key, reply_dir, 2000)

    samples = estimator.on_packet(reply, flow_after, reply_dir)
    ts_samples = [s for s in samples if s.method == "tcp_timestamp"]
    assert len(ts_samples) == 0


def test_seq_ack_rtt():
    """Data + ACK produces a data_ack RTT sample."""
    tracker = FlowTracker()
    estimator = RTTEstimator()

    # Client sends data
    data_pkt = make_packet(
        seq=1000, ack=2000, payload_len=100, timestamp=1.0,
    )
    flow, direction = tracker.process_packet(data_pkt)
    estimator.on_packet(data_pkt, flow, direction)

    # Server ACKs the data (ack=1100 covers seq 1000+100)
    ack_pkt = make_packet(
        src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=12345,
        flags="ACK", seq=2000, ack=1100, payload_len=0, timestamp=1.010,
    )
    flow, direction = tracker.process_packet(ack_pkt)
    samples = estimator.on_packet(ack_pkt, flow, direction)

    da_samples = [s for s in samples if s.method == "data_ack"]
    assert len(da_samples) == 1
    assert abs(da_samples[0].rtt_ms - 10.0) < 0.01


def test_seq_ack_karn_filter():
    """Retransmitted seq is filtered from data_ack RTT by Karn's algorithm."""
    tracker = FlowTracker()
    estimator = RTTEstimator()

    # Client sends data
    data_pkt = make_packet(seq=1000, ack=2000, payload_len=100, timestamp=1.0)
    flow, direction = tracker.process_packet(data_pkt)
    estimator.on_packet(data_pkt, flow, direction)

    # Mark seq 1000 as retransmitted in FORWARD direction
    estimator.mark_retransmission(flow.key, FlowDirection.FORWARD, 1000)

    # Server ACKs
    ack_pkt = make_packet(
        src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=12345,
        flags="ACK", seq=2000, ack=1100, payload_len=0, timestamp=1.010,
    )
    flow, direction = tracker.process_packet(ack_pkt)
    samples = estimator.on_packet(ack_pkt, flow, direction)

    da_samples = [s for s in samples if s.method == "data_ack"]
    assert len(da_samples) == 0


def test_no_rtt_for_udp():
    """No RTT samples produced for UDP packets."""
    tracker = FlowTracker()
    estimator = RTTEstimator()

    pkt = make_packet(protocol="UDP", src_port=5000, dst_port=53, timestamp=1.0)
    flow, direction = tracker.process_packet(pkt)
    samples = estimator.on_packet(pkt, flow, direction)
    assert len(samples) == 0


def test_memory_bounds():
    """5000 unique TSvals: map is bounded to MAX_TSVAL_ENTRIES."""
    tracker = FlowTracker()
    estimator = RTTEstimator()

    for i in range(5000):
        pkt = make_packet(
            seq=1000 + i, ack=2000, payload_len=1, timestamp=1.0 + i * 0.001,
            tsval=1000 + i, tsecr=0,
        )
        flow, direction = tracker.process_packet(pkt)
        estimator.on_packet(pkt, flow, direction)

    # Check that the internal map is bounded
    for key, tsmap in estimator._tsval_map.items():
        assert len(tsmap) <= 1000
