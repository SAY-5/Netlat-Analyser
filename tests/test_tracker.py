"""Tests for FlowTracker (Phase 2)."""

from __future__ import annotations

import sys
from pathlib import Path

# Make conftest importable
sys.path.insert(0, str(Path(__file__).parent))

from conftest import make_packet  # noqa: E402

from netlat.flows.models import FlowDirection, FlowKey  # noqa: E402
from netlat.flows.tracker import FlowTracker  # noqa: E402


def test_basic_flow_creation():
    """SYN -> SYN-ACK -> ACK produces correct state transitions."""
    tracker = FlowTracker()

    # SYN: client (10.0.0.1:12345) -> server (10.0.0.2:80)
    syn = make_packet(flags="SYN", seq=100, ack=0, payload_len=0, timestamp=1.0)
    flow, direction = tracker.process_packet(syn)
    assert flow.state == "syn_sent"
    assert flow.syn_timestamp == 1.0
    assert direction == FlowDirection.FORWARD

    # SYN-ACK: server -> client
    syn_ack = make_packet(
        src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=12345,
        flags="SYN-ACK", seq=200, ack=101,
        payload_len=0, timestamp=1.001,
    )
    flow, direction = tracker.process_packet(syn_ack)
    assert flow.state == "syn_ack_sent"
    assert flow.syn_ack_timestamp == 1.001
    assert direction == FlowDirection.REVERSE

    # ACK: client -> server (completes handshake)
    ack = make_packet(flags="ACK", seq=101, ack=201, payload_len=0, timestamp=1.002)
    flow, direction = tracker.process_packet(ack)
    assert flow.state == "established"
    assert flow.established_timestamp == 1.002
    assert flow.handshake_rtt_ms is not None
    assert abs(flow.handshake_rtt_ms - 2.0) < 0.01


def test_bidirectional_counting():
    """10 packets each direction are counted correctly."""
    tracker = FlowTracker()

    for i in range(10):
        pkt = make_packet(
            seq=1000 + i * 100, ack=2000, payload_len=100,
            timestamp=1.0 + i * 0.001,
        )
        tracker.process_packet(pkt)

    for i in range(10):
        pkt = make_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=12345,
            seq=2000 + i * 100, ack=1000, payload_len=100,
            timestamp=2.0 + i * 0.001,
        )
        tracker.process_packet(pkt)

    flows = tracker.get_all_flows()
    assert len(flows) == 1
    flow = flows[0]
    assert flow.total_packets == 20
    assert flow.a_to_b.packets_seen == 10
    assert flow.b_to_a.packets_seen == 10


def test_flow_key_normalization():
    """A->B and B->A map to the same FlowState."""
    tracker = FlowTracker()

    pkt_ab = make_packet(timestamp=1.0)
    tracker.process_packet(pkt_ab)

    pkt_ba = make_packet(
        src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=12345,
        timestamp=2.0,
    )
    tracker.process_packet(pkt_ba)

    assert len(tracker.get_all_flows()) == 1


def test_seq_tracking():
    """Verify max_seq and in_flight updates."""
    tracker = FlowTracker()

    pkt1 = make_packet(seq=1000, payload_len=100, timestamp=1.0)
    flow, _ = tracker.process_packet(pkt1)
    assert flow.a_to_b.max_seq == 1100
    assert 1000 in flow.a_to_b.in_flight

    pkt2 = make_packet(seq=1100, payload_len=200, timestamp=1.001)
    flow, _ = tracker.process_packet(pkt2)
    assert flow.a_to_b.max_seq == 1300
    assert 1100 in flow.a_to_b.in_flight


def test_zero_window_detection():
    """Window=0 increments zero_windows counter."""
    tracker = FlowTracker()

    pkt = make_packet(window=0, timestamp=1.0)
    flow, _ = tracker.process_packet(pkt)
    assert flow.zero_windows == 1

    pkt2 = make_packet(window=0, timestamp=1.001)
    flow, _ = tracker.process_packet(pkt2)
    assert flow.zero_windows == 2


def test_reset_detection():
    """RST flag sets state to 'reset' and increments resets."""
    tracker = FlowTracker()

    pkt = make_packet(flags="RST", timestamp=1.0)
    flow, _ = tracker.process_packet(pkt)
    assert flow.state == "reset"
    assert flow.resets == 1


def test_dup_ack_tracking():
    """4 ACKs with same value → dup_ack_count == 3."""
    tracker = FlowTracker()

    for i in range(4):
        pkt = make_packet(
            flags="ACK", seq=1000, ack=5000, payload_len=0,
            timestamp=1.0 + i * 0.001,
        )
        tracker.process_packet(pkt)

    flow = tracker.get_all_flows()[0]
    # First ACK sets the value (count=0), next 3 are dups
    assert flow.a_to_b.dup_ack_count == 3


def test_eviction():
    """When max_flows=2, adding a 3rd flow evicts the oldest."""
    tracker = FlowTracker(max_flows=2)

    # Flow 1
    pkt1 = make_packet(src_port=1001, dst_port=80, timestamp=1.0)
    tracker.process_packet(pkt1)
    # Flow 2
    pkt2 = make_packet(src_port=1002, dst_port=80, timestamp=2.0)
    tracker.process_packet(pkt2)

    assert len(tracker.get_all_flows()) == 2

    # Flow 3 should evict the oldest (flow 1)
    pkt3 = make_packet(src_port=1003, dst_port=80, timestamp=3.0)
    tracker.process_packet(pkt3)

    assert len(tracker.get_all_flows()) == 2
    # Flow 1 should be evicted (oldest last_packet_time)
    keys = {f.key for f in tracker.get_all_flows()}
    key1 = FlowKey.from_packet(pkt1)
    assert key1 not in keys


def test_stale_eviction():
    """flow_timeout_s=10: flow older than 15s is evicted."""
    tracker = FlowTracker(flow_timeout_s=10.0)

    pkt1 = make_packet(src_port=1001, dst_port=80, timestamp=1.0)
    tracker.process_packet(pkt1)

    pkt2 = make_packet(src_port=1002, dst_port=80, timestamp=10.0)
    tracker.process_packet(pkt2)

    evicted = tracker.evict_stale(current_time=16.0)
    assert evicted == 1
    assert len(tracker.get_all_flows()) == 1


def test_udp_flow():
    """UDP packets create immediate 'established' flow."""
    tracker = FlowTracker()

    pkt = make_packet(
        protocol="UDP", src_port=5000, dst_port=53,
        timestamp=1.0,
    )
    flow, direction = tracker.process_packet(pkt)
    assert flow.state == "established"
    assert flow.key.protocol == "UDP"
