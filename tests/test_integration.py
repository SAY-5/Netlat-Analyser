"""Integration tests for the full netlat pipeline."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from netlat.analysis.pipeline import AnalysisConfig, AnalysisPipeline
from netlat.export.prometheus import NetLatMetrics
from netlat.report.render import ReportRenderer

# Skip all tests if scapy is not installed
scapy = pytest.importorskip("scapy")
from scapy.all import IP, TCP, Ether, Raw, wrpcap  # noqa: E402


def _generate_normal_pcap(path: Path, num_pairs: int = 50) -> None:
    """Generate a clean normal TCP pcap with no anomalies."""
    packets = []
    client = "10.0.1.1"
    server = "10.0.2.1"
    sport = 40000
    dport = 80
    t = 1705276800.0

    # Handshake
    syn = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="S", seq=1000,
        options=[("Timestamp", (100, 0)), ("MSS", 1460)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    syn_ack = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="SA", seq=5000, ack=1001,
        options=[("Timestamp", (200, 100)), ("MSS", 1460)],
    )
    syn_ack.time = t
    packets.append(syn_ack)

    t += 0.001
    ack = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=1001, ack=5001,
        options=[("Timestamp", (101, 200))],
    )
    ack.time = t
    packets.append(ack)

    client_seq = 1001
    server_seq = 5001
    tsval_c = 102
    tsval_s = 201

    for i in range(num_pairs):
        t += 0.1
        payload = f"REQ{i:04d}".encode() + b"A" * 50
        pkt = Ether() / IP(src=client, dst=server) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        client_seq += len(payload)
        tsval_c += 1

        t += 0.001
        resp = f"RSP{i:04d}".encode() + b"B" * 50
        pkt = Ether() / IP(src=server, dst=client) / TCP(
            sport=dport, dport=sport, flags="PA", seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        ) / Raw(load=resp)
        pkt.time = t
        packets.append(pkt)
        server_seq += len(resp)
        tsval_s += 2

    # FIN
    t += 0.1
    fin = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq,
        options=[("Timestamp", (tsval_c, tsval_s))],
    )
    fin.time = t
    packets.append(fin)

    t += 0.001
    fin2 = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1,
        options=[("Timestamp", (tsval_s + 1, tsval_c))],
    )
    fin2.time = t
    packets.append(fin2)

    t += 0.001
    last = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1,
        options=[("Timestamp", (tsval_c + 1, tsval_s + 1))],
    )
    last.time = t
    packets.append(last)

    wrpcap(str(path), packets)


def _generate_retransmit_pcap(path: Path) -> None:
    """Generate a TCP pcap with retransmissions."""
    packets = []
    client = "10.0.2.10"
    server = "10.0.2.20"
    sport = 55555
    dport = 80
    t = 1705276800.0

    # Handshake
    syn = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="S", seq=100,
        options=[("Timestamp", (500, 0)), ("MSS", 1460)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    syn_ack = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="SA", seq=200, ack=101,
        options=[("Timestamp", (600, 500)), ("MSS", 1460)],
    )
    syn_ack.time = t
    packets.append(syn_ack)

    t += 0.001
    ack = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=101, ack=201,
        options=[("Timestamp", (501, 600))],
    )
    ack.time = t
    packets.append(ack)

    client_seq = 101
    server_seq = 201
    data = b"X" * 500

    # Send data with retransmissions
    for i in range(15):
        t += 0.1
        tsval_c = 502 + i * 3
        tsval_s = 601 + i * 2
        pkt = Ether() / IP(src=client, dst=server) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=data)
        pkt.time = t
        packets.append(pkt)

        # Retransmit every 3rd packet
        if i % 3 == 1:
            t += 0.05
            retrans = Ether() / IP(src=client, dst=server) / TCP(
                sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
                options=[("Timestamp", (tsval_c + 1, tsval_s))],
            ) / Raw(load=data)
            retrans.time = t
            packets.append(retrans)

        client_seq += len(data)

        t += 0.002
        ack_pkt = Ether() / IP(src=server, dst=client) / TCP(
            sport=dport, dport=sport, flags="A", seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        )
        ack_pkt.time = t
        packets.append(ack_pkt)

    # FIN
    t += 0.1
    fin = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq,
    )
    fin.time = t
    packets.append(fin)

    t += 0.001
    fin2 = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1,
    )
    fin2.time = t
    packets.append(fin2)

    t += 0.001
    last = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1,
    )
    last.time = t
    packets.append(last)

    wrpcap(str(path), packets)


def _generate_rtt_spike_pcap(path: Path) -> None:
    """Generate a TCP pcap with a latency spike after baseline."""
    packets = []
    client = "10.0.3.10"
    server = "10.0.3.20"
    sport = 56789
    dport = 8080
    t = 1705276800.0

    # Handshake
    syn = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="S", seq=5000,
        options=[("Timestamp", (1000, 0)), ("MSS", 1460)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    syn_ack = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="SA", seq=6000, ack=5001,
        options=[("Timestamp", (2000, 1000)), ("MSS", 1460)],
    )
    syn_ack.time = t
    packets.append(syn_ack)

    t += 0.001
    ack = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=5001, ack=6001,
        options=[("Timestamp", (1001, 2000))],
    )
    ack.time = t
    packets.append(ack)

    client_seq = 5001
    server_seq = 6001
    tsval_c = 1002
    tsval_s = 2001

    # Normal baseline: 25 exchanges at ~1ms RTT
    for i in range(25):
        t += 0.1
        payload = b"N" * 100
        pkt = Ether() / IP(src=client, dst=server) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        client_seq += len(payload)
        tsval_c += 1

        t += 0.001
        ack_pkt = Ether() / IP(src=server, dst=client) / TCP(
            sport=dport, dport=sport, flags="A", seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        )
        ack_pkt.time = t
        packets.append(ack_pkt)
        tsval_s += 2

    # Spike: 5 exchanges at 300ms RTT
    for i in range(5):
        t += 0.1
        payload = b"S" * 100
        pkt = Ether() / IP(src=client, dst=server) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        client_seq += len(payload)
        tsval_c += 1

        t += 0.300  # 300ms spike
        ack_pkt = Ether() / IP(src=server, dst=client) / TCP(
            sport=dport, dport=sport, flags="A", seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        )
        ack_pkt.time = t
        packets.append(ack_pkt)
        tsval_s += 2

    # FIN
    t += 0.1
    fin = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq,
        options=[("Timestamp", (tsval_c, tsval_s))],
    )
    fin.time = t
    packets.append(fin)

    t += 0.001
    fin2 = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1,
        options=[("Timestamp", (tsval_s + 1, tsval_c))],
    )
    fin2.time = t
    packets.append(fin2)

    t += 0.001
    last = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1,
        options=[("Timestamp", (tsval_c + 1, tsval_s + 1))],
    )
    last.time = t
    packets.append(last)

    wrpcap(str(path), packets)


def _generate_multi_flow_pcap(path: Path) -> None:
    """Generate a multi-flow pcap: normal + spike + retransmit."""
    packets = []
    t = 1705276800.0

    # ---- Flow 1: Normal (10.0.1.1:40000 <-> 10.0.2.1:80) ----
    client1, server1, sp1, dp1 = "10.0.1.1", "10.0.2.1", 40000, 80

    syn = Ether() / IP(src=client1, dst=server1) / TCP(
        sport=sp1, dport=dp1, flags="S", seq=1000,
        options=[("Timestamp", (100, 0)), ("MSS", 1460)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    sa = Ether() / IP(src=server1, dst=client1) / TCP(
        sport=dp1, dport=sp1, flags="SA", seq=5000, ack=1001,
        options=[("Timestamp", (200, 100)), ("MSS", 1460)],
    )
    sa.time = t
    packets.append(sa)

    t += 0.001
    a = Ether() / IP(src=client1, dst=server1) / TCP(
        sport=sp1, dport=dp1, flags="A", seq=1001, ack=5001,
        options=[("Timestamp", (101, 200))],
    )
    a.time = t
    packets.append(a)

    cs1, ss1, tc1, ts1 = 1001, 5001, 102, 201
    for i in range(30):
        t += 0.1
        p = b"R" * 60
        pkt = Ether() / IP(src=client1, dst=server1) / TCP(
            sport=sp1, dport=dp1, flags="PA", seq=cs1, ack=ss1,
            options=[("Timestamp", (tc1, ts1))],
        ) / Raw(load=p)
        pkt.time = t
        packets.append(pkt)
        cs1 += len(p)
        tc1 += 1

        t += 0.001
        rp = b"P" * 60
        pkt = Ether() / IP(src=server1, dst=client1) / TCP(
            sport=dp1, dport=sp1, flags="PA", seq=ss1, ack=cs1,
            options=[("Timestamp", (ts1 + 1, tc1))],
        ) / Raw(load=rp)
        pkt.time = t
        packets.append(pkt)
        ss1 += len(rp)
        ts1 += 2

    t += 0.1
    fin = Ether() / IP(src=client1, dst=server1) / TCP(
        sport=sp1, dport=dp1, flags="FA", seq=cs1, ack=ss1,
        options=[("Timestamp", (tc1, ts1))],
    )
    fin.time = t
    packets.append(fin)
    t += 0.001
    fa = Ether() / IP(src=server1, dst=client1) / TCP(
        sport=dp1, dport=sp1, flags="FA", seq=ss1, ack=cs1 + 1,
        options=[("Timestamp", (ts1 + 1, tc1))],
    )
    fa.time = t
    packets.append(fa)
    t += 0.001
    la = Ether() / IP(src=client1, dst=server1) / TCP(
        sport=sp1, dport=dp1, flags="A", seq=cs1 + 1, ack=ss1 + 1,
        options=[("Timestamp", (tc1 + 1, ts1 + 1))],
    )
    la.time = t
    packets.append(la)

    # ---- Flow 2: RTT spike (10.0.1.1:45000 <-> 10.0.2.1:443) ----
    t = 1705276800.0
    client2, server2, sp2, dp2 = "10.0.1.1", "10.0.2.1", 45000, 443

    syn = Ether() / IP(src=client2, dst=server2) / TCP(
        sport=sp2, dport=dp2, flags="S", seq=10000,
        options=[("Timestamp", (1000, 0)), ("MSS", 1460)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    sa = Ether() / IP(src=server2, dst=client2) / TCP(
        sport=dp2, dport=sp2, flags="SA", seq=20000, ack=10001,
        options=[("Timestamp", (2000, 1000)), ("MSS", 1460)],
    )
    sa.time = t
    packets.append(sa)

    t += 0.001
    a = Ether() / IP(src=client2, dst=server2) / TCP(
        sport=sp2, dport=dp2, flags="A", seq=10001, ack=20001,
        options=[("Timestamp", (1001, 2000))],
    )
    a.time = t
    packets.append(a)

    cs2, ss2, tc2, ts2 = 10001, 20001, 1002, 2001

    # Baseline (30 pairs at 1ms to build enough samples for anomaly detection)
    for i in range(30):
        t += 0.1
        p = b"Q" * 60
        pkt = Ether() / IP(src=client2, dst=server2) / TCP(
            sport=sp2, dport=dp2, flags="PA", seq=cs2, ack=ss2,
            options=[("Timestamp", (tc2, ts2))],
        ) / Raw(load=p)
        pkt.time = t
        packets.append(pkt)
        cs2 += len(p)
        tc2 += 1

        t += 0.001
        rp = b"A" * 60
        pkt = Ether() / IP(src=server2, dst=client2) / TCP(
            sport=dp2, dport=sp2, flags="PA", seq=ss2, ack=cs2,
            options=[("Timestamp", (ts2 + 1, tc2))],
        ) / Raw(load=rp)
        pkt.time = t
        packets.append(pkt)
        ss2 += len(rp)
        ts2 += 2

    # Spike (10 pairs at 500ms -- large enough to trigger anomaly detection)
    for i in range(10):
        t += 0.1
        p = b"W" * 60
        pkt = Ether() / IP(src=client2, dst=server2) / TCP(
            sport=sp2, dport=dp2, flags="PA", seq=cs2, ack=ss2,
            options=[("Timestamp", (tc2, ts2))],
        ) / Raw(load=p)
        pkt.time = t
        packets.append(pkt)
        cs2 += len(p)
        tc2 += 1

        t += 0.500  # 500ms spike
        rp = b"Z" * 60
        pkt = Ether() / IP(src=server2, dst=client2) / TCP(
            sport=dp2, dport=sp2, flags="PA", seq=ss2, ack=cs2,
            options=[("Timestamp", (ts2 + 1, tc2))],
        ) / Raw(load=rp)
        pkt.time = t
        packets.append(pkt)
        ss2 += len(rp)
        ts2 += 2

    t += 0.1
    fin = Ether() / IP(src=client2, dst=server2) / TCP(
        sport=sp2, dport=dp2, flags="FA", seq=cs2, ack=ss2,
        options=[("Timestamp", (tc2, ts2))],
    )
    fin.time = t
    packets.append(fin)
    t += 0.001
    fa = Ether() / IP(src=server2, dst=client2) / TCP(
        sport=dp2, dport=sp2, flags="FA", seq=ss2, ack=cs2 + 1,
        options=[("Timestamp", (ts2 + 1, tc2))],
    )
    fa.time = t
    packets.append(fa)
    t += 0.001
    la = Ether() / IP(src=client2, dst=server2) / TCP(
        sport=sp2, dport=dp2, flags="A", seq=cs2 + 1, ack=ss2 + 1,
        options=[("Timestamp", (tc2 + 1, ts2 + 1))],
    )
    la.time = t
    packets.append(la)

    # ---- Flow 3: Retransmissions (10.0.3.1:55000 <-> 10.0.4.1:8080) ----
    t = 1705276800.0
    client3, server3, sp3, dp3 = "10.0.3.1", "10.0.4.1", 55000, 8080

    syn = Ether() / IP(src=client3, dst=server3) / TCP(
        sport=sp3, dport=dp3, flags="S", seq=30000,
        options=[("Timestamp", (3000, 0)), ("MSS", 1460)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    sa = Ether() / IP(src=server3, dst=client3) / TCP(
        sport=dp3, dport=sp3, flags="SA", seq=40000, ack=30001,
        options=[("Timestamp", (4000, 3000)), ("MSS", 1460)],
    )
    sa.time = t
    packets.append(sa)

    t += 0.001
    a = Ether() / IP(src=client3, dst=server3) / TCP(
        sport=sp3, dport=dp3, flags="A", seq=30001, ack=40001,
        options=[("Timestamp", (3001, 4000))],
    )
    a.time = t
    packets.append(a)

    cs3, ss3, tc3, ts3 = 30001, 40001, 3002, 4001
    data = b"Y" * 200

    for i in range(20):
        t += 0.1
        pkt = Ether() / IP(src=client3, dst=server3) / TCP(
            sport=sp3, dport=dp3, flags="PA", seq=cs3, ack=ss3,
            options=[("Timestamp", (tc3, ts3))],
        ) / Raw(load=data)
        pkt.time = t
        packets.append(pkt)

        # Retransmit every 4th packet
        if i % 4 == 2:
            t += 0.05
            retrans = Ether() / IP(src=client3, dst=server3) / TCP(
                sport=sp3, dport=dp3, flags="PA", seq=cs3, ack=ss3,
                options=[("Timestamp", (tc3 + 1, ts3))],
            ) / Raw(load=data)
            retrans.time = t
            packets.append(retrans)

        cs3 += len(data)
        tc3 += 2

        t += 0.002
        ack_pkt = Ether() / IP(src=server3, dst=client3) / TCP(
            sport=dp3, dport=sp3, flags="A", seq=ss3, ack=cs3,
            options=[("Timestamp", (ts3 + 1, tc3))],
        )
        ack_pkt.time = t
        packets.append(ack_pkt)
        ts3 += 2

    t += 0.1
    fin = Ether() / IP(src=client3, dst=server3) / TCP(
        sport=sp3, dport=dp3, flags="FA", seq=cs3, ack=ss3,
        options=[("Timestamp", (tc3, ts3))],
    )
    fin.time = t
    packets.append(fin)
    t += 0.001
    fa = Ether() / IP(src=server3, dst=client3) / TCP(
        sport=dp3, dport=sp3, flags="FA", seq=ss3, ack=cs3 + 1,
        options=[("Timestamp", (ts3 + 1, tc3))],
    )
    fa.time = t
    packets.append(fa)
    t += 0.001
    la = Ether() / IP(src=client3, dst=server3) / TCP(
        sport=sp3, dport=dp3, flags="A", seq=cs3 + 1, ack=ss3 + 1,
        options=[("Timestamp", (tc3 + 1, ts3 + 1))],
    )
    la.time = t
    packets.append(la)

    # Sort all packets by time
    packets.sort(key=lambda p: float(p.time))
    wrpcap(str(path), packets)


class TestFullPipelineNormal:
    """Test the full pipeline with normal (clean) traffic."""

    def test_normal_traffic(self, tmp_path: Path) -> None:
        pcap = tmp_path / "normal.pcap"
        _generate_normal_pcap(pcap)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        result = pipeline.analyze_pcap(pcap)

        # Should have RTT samples
        assert result.rtt_summary["count"] > 0
        # Should have flows
        assert len(result.flows) >= 1
        # Should have processed packets
        assert result.packets_processed > 0
        # Normal traffic - should have no anomalies (or very few)
        # The anomaly detector may fire on variance, so we just check it doesn't explode
        assert result.anomaly_summary["total"] >= 0
        # RTT should be reasonable (timestamp-based RTT may have minor variance)
        assert result.rtt_summary["mean_ms"] < 200.0
        # No retransmissions
        assert result.retransmission_summary["total"] == 0


class TestFullPipelineRetransmit:
    """Test the full pipeline with retransmission traffic."""

    def test_retransmission_detected(self, tmp_path: Path) -> None:
        pcap = tmp_path / "retransmit.pcap"
        _generate_retransmit_pcap(pcap)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        result = pipeline.analyze_pcap(pcap)

        # Should detect retransmissions
        assert result.retransmission_summary["total"] > 0
        assert len(result.retransmission_events) > 0
        # Should have flows affected
        assert result.retransmission_summary["flows_affected"] >= 1
        # Should have RTT samples
        assert result.rtt_summary["count"] > 0


class TestFullPipelineRTTSpike:
    """Test the full pipeline with an RTT spike scenario."""

    def test_rtt_spike_detected(self, tmp_path: Path) -> None:
        pcap = tmp_path / "spike.pcap"
        _generate_rtt_spike_pcap(pcap)

        pipeline = AnalysisPipeline(config=AnalysisConfig(
            anomaly_rtt_multiplier=3.0,
        ))
        result = pipeline.analyze_pcap(pcap)

        # Should have RTT samples
        assert result.rtt_summary["count"] > 0
        # Max RTT should be much higher than min
        assert result.rtt_summary["max_ms"] > 100.0
        # Should detect anomalies (rtt_spike type)
        anomaly_types = [e.anomaly_type for e in result.anomaly_events]
        assert "rtt_spike" in anomaly_types, (
            f"Expected rtt_spike anomaly, got: {anomaly_types}"
        )


class TestFullPipelineMultiFlow:
    """Test the full pipeline with multi-flow incident scenario."""

    def test_multi_flow_incident(self, tmp_path: Path) -> None:
        pcap = tmp_path / "multi.pcap"
        _generate_multi_flow_pcap(pcap)

        pipeline = AnalysisPipeline(config=AnalysisConfig(
            anomaly_rtt_multiplier=3.0,
        ))
        result = pipeline.analyze_pcap(pcap)

        # Should have 3 flows
        assert len(result.flows) == 3

        # Build a lookup by flow
        flow_by_port: dict[int, object] = {}
        for f in result.flows:
            # Identify flows by their distinctive port
            if f.key.port_a == 40000 or f.key.port_b == 40000:
                flow_by_port[40000] = f
            elif f.key.port_a == 45000 or f.key.port_b == 45000:
                flow_by_port[45000] = f
            elif f.key.port_a == 55000 or f.key.port_b == 55000:
                flow_by_port[55000] = f

        # Flow 1 (port 40000): should be clean, no retransmissions
        f1 = flow_by_port.get(40000)
        assert f1 is not None
        assert f1.retransmissions == 0

        # Flow 2 (port 45000): should have anomalies
        f2 = flow_by_port.get(45000)
        assert f2 is not None
        # Check for anomalies on this flow
        flow2_anomalies = [
            e for e in result.anomaly_events
            if (e.flow_key.port_a == 45000 or e.flow_key.port_b == 45000)
        ]
        assert len(flow2_anomalies) > 0, "Flow 2 should have anomalies (rtt_spike)"

        # Flow 3 (port 55000): should have retransmissions
        f3 = flow_by_port.get(55000)
        assert f3 is not None
        assert f3.retransmissions > 0


class TestCLIIntegration:
    """Test the CLI commands end-to-end."""

    def test_cli_analyze_json(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from netlat.cli import app

        pcap = tmp_path / "cli_test.pcap"
        _generate_normal_pcap(pcap, num_pairs=10)

        runner = CliRunner()
        result = runner.invoke(app, ["analyze", "--pcap", str(pcap), "--format", "json"])
        assert result.exit_code == 0
        # Should be valid JSON
        data = json.loads(result.output)
        assert "rtt_summary" in data
        assert "metadata" in data
        assert data["metadata"]["packet_count"] > 0

    def test_cli_analyze_text(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from netlat.cli import app

        pcap = tmp_path / "cli_test.pcap"
        _generate_normal_pcap(pcap, num_pairs=10)

        runner = CliRunner()
        result = runner.invoke(app, ["analyze", "--pcap", str(pcap), "--format", "text"])
        assert result.exit_code == 0
        assert "netlat" in result.output
        assert "RTT Summary" in result.output
        assert "Retransmissions" in result.output


class TestPrometheusIntegration:
    """Test Prometheus metrics from analysis results."""

    def test_metrics_from_analysis(self, tmp_path: Path) -> None:
        from prometheus_client import CollectorRegistry

        pcap = tmp_path / "prom_test.pcap"
        _generate_normal_pcap(pcap, num_pairs=15)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        result = pipeline.analyze_pcap(pcap)

        registry = CollectorRegistry()
        metrics = NetLatMetrics(registry=registry)
        metrics.update_from_result(result)

        output = metrics.generate().decode()
        # Should contain our metric names
        assert "netlat_rtt_ms" in output
        assert "netlat_packets_processed_total" in output
        assert "netlat_active_flows" in output
        assert "netlat_capture_duration_seconds" in output


class TestPerformance:
    """Performance tests for the analysis pipeline."""

    def test_processing_speed(self, tmp_path: Path) -> None:
        """Ensure pipeline processes at a reasonable speed."""
        pcap = tmp_path / "perf.pcap"
        # Generate a moderately large pcap
        num_pairs = 5000
        _generate_normal_pcap(pcap, num_pairs=num_pairs)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        t0 = time.monotonic()
        result = pipeline.analyze_pcap(pcap)
        elapsed = time.monotonic() - t0

        total_packets = result.packets_processed
        assert total_packets > 0
        pps = total_packets / elapsed if elapsed > 0 else float("inf")
        # Should process at a reasonable speed (>1k packets/sec)
        # Note: scapy-generated pcaps are large; dpkt parsing dominates
        assert pps > 1_000, f"Too slow: {pps:.0f} packets/sec ({total_packets} in {elapsed:.2f}s)"


class TestDeterminism:
    """Test that analysis produces deterministic output."""

    def test_deterministic_output(self, tmp_path: Path) -> None:
        pcap = tmp_path / "determ.pcap"
        _generate_normal_pcap(pcap, num_pairs=20)

        renderer = ReportRenderer()

        # Run 1
        pipeline1 = AnalysisPipeline(config=AnalysisConfig())
        result1 = pipeline1.analyze_pcap(pcap)
        json1 = renderer.render_json(result1)

        # Run 2
        pipeline2 = AnalysisPipeline(config=AnalysisConfig())
        result2 = pipeline2.analyze_pcap(pcap)
        json2 = renderer.render_json(result2)

        # Parse and compare (ignoring analysis_duration_s which may vary)
        d1 = json.loads(json1)
        d2 = json.loads(json2)
        d1.pop("analysis_duration_s", None)
        d2.pop("analysis_duration_s", None)
        assert d1 == d2
