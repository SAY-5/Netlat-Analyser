#!/usr/bin/env python3
"""Demo script for netlat - generates a synthetic pcap and runs full analysis."""

from __future__ import annotations

import json
import sys
import time

try:
    from scapy.all import (
        IP,
        TCP,
        Ether,
        Raw,
        wrpcap,
    )
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy", file=sys.stderr)
    sys.exit(1)

from pathlib import Path


DEMO_PCAP = "/tmp/netlat_demo.pcap"
DEMO_JSON = "/tmp/netlat_demo_report.json"

# Base time: 2024-01-15 00:00:00 UTC
BASE_TIME = 1705276800.0


def _make_tcp_ts(tsval: int, tsecr: int) -> list:
    """Build TCP timestamp option."""
    return [("Timestamp", (tsval, tsecr)), ("NOP", None), ("NOP", None)]


def _generate_flow1_normal() -> list:
    """Flow 1: Normal traffic 10.0.1.1:40000 <-> 10.0.2.1:80, ~1ms RTT."""
    packets = []
    client = "10.0.1.1"
    server = "10.0.2.1"
    sport = 40000
    dport = 80
    t = BASE_TIME

    # 3-way handshake
    syn = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="S", seq=1000,
        options=[("Timestamp", (100, 0)), ("MSS", 1460), ("WScale", 7)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001  # 1ms
    syn_ack = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="SA", seq=5000, ack=1001,
        options=[("Timestamp", (200, 100)), ("MSS", 1460), ("WScale", 7)],
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

    # Data exchange: ~95 request-response pairs over 30s
    client_seq = 1001
    server_seq = 5001
    tsval_c = 102
    tsval_s = 201

    for i in range(95):
        t += 0.3  # every 300ms
        payload = f"GET /page/{i} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
        pkt = Ether() / IP(src=client, dst=server) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        client_seq += len(payload)
        tsval_c += 1

        t += 0.001  # 1ms RTT
        resp = f"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nOK{i:03d}".encode()
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
    fin1 = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq,
        options=[("Timestamp", (tsval_c, tsval_s))],
    )
    fin1.time = t
    packets.append(fin1)

    t += 0.001
    fin2 = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1,
        options=[("Timestamp", (tsval_s + 1, tsval_c))],
    )
    fin2.time = t
    packets.append(fin2)

    t += 0.001
    last_ack = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1,
        options=[("Timestamp", (tsval_c + 1, tsval_s + 1))],
    )
    last_ack.time = t
    packets.append(last_ack)

    return packets


def _generate_flow2_latency_spike() -> list:
    """Flow 2: Latency spike 10.0.1.1:45000 <-> 10.0.2.1:443."""
    packets = []
    client = "10.0.1.1"
    server = "10.0.2.1"
    sport = 45000
    dport = 443
    t = BASE_TIME

    # Handshake
    syn = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="S", seq=10000,
        options=[("Timestamp", (1000, 0)), ("MSS", 1460), ("WScale", 7)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    syn_ack = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="SA", seq=20000, ack=10001,
        options=[("Timestamp", (2000, 1000)), ("MSS", 1460), ("WScale", 7)],
    )
    syn_ack.time = t
    packets.append(syn_ack)

    t += 0.001
    ack = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=10001, ack=20001,
        options=[("Timestamp", (1001, 2000))],
    )
    ack.time = t
    packets.append(ack)

    client_seq = 10001
    server_seq = 20001
    tsval_c = 1002
    tsval_s = 2001

    # Phase 1: Normal 1ms RTT for ~10s (~65 pairs)
    for i in range(65):
        t += 0.15
        payload = f"REQ-{i:04d}:".encode() + b"A" * 50
        pkt = Ether() / IP(src=client, dst=server) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        client_seq += len(payload)
        tsval_c += 1

        t += 0.001  # 1ms RTT
        resp = f"RSP-{i:04d}:".encode() + b"B" * 50
        pkt = Ether() / IP(src=server, dst=client) / TCP(
            sport=dport, dport=sport, flags="PA", seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        ) / Raw(load=resp)
        pkt.time = t
        packets.append(pkt)
        server_seq += len(resp)
        tsval_s += 2

    # Phase 2: Latency spike - 200ms RTT for ~2s (~8 pairs)
    for i in range(8):
        t += 0.25
        payload = f"SLOW-{i:04d}:".encode() + b"C" * 50
        pkt = Ether() / IP(src=client, dst=server) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        client_seq += len(payload)
        tsval_c += 1

        t += 0.200  # 200ms RTT!
        resp = f"SRSP-{i:04d}:".encode() + b"D" * 50
        pkt = Ether() / IP(src=server, dst=client) / TCP(
            sport=dport, dport=sport, flags="PA", seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        ) / Raw(load=resp)
        pkt.time = t
        packets.append(pkt)
        server_seq += len(resp)
        tsval_s += 2

    # Phase 3: Recovery - back to 1ms for rest (~25 pairs)
    for i in range(25):
        t += 0.15
        payload = f"RCV-{i:04d}:".encode() + b"E" * 50
        pkt = Ether() / IP(src=client, dst=server) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        client_seq += len(payload)
        tsval_c += 1

        t += 0.001
        resp = f"RRSP-{i:04d}:".encode() + b"F" * 50
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
    fin1 = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq,
        options=[("Timestamp", (tsval_c, tsval_s))],
    )
    fin1.time = t
    packets.append(fin1)

    t += 0.001
    fin2 = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1,
        options=[("Timestamp", (tsval_s + 1, tsval_c))],
    )
    fin2.time = t
    packets.append(fin2)

    t += 0.001
    last_ack = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1,
        options=[("Timestamp", (tsval_c + 1, tsval_s + 1))],
    )
    last_ack.time = t
    packets.append(last_ack)

    return packets


def _generate_flow3_packet_loss() -> list:
    """Flow 3: Packet loss 10.0.3.1:55000 <-> 10.0.4.1:8080, ~5% retransmission."""
    packets = []
    client = "10.0.3.1"
    server = "10.0.4.1"
    sport = 55000
    dport = 8080
    t = BASE_TIME

    # Handshake
    syn = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="S", seq=30000,
        options=[("Timestamp", (3000, 0)), ("MSS", 1460), ("WScale", 7)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    syn_ack = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="SA", seq=40000, ack=30001,
        options=[("Timestamp", (4000, 3000)), ("MSS", 1460), ("WScale", 7)],
    )
    syn_ack.time = t
    packets.append(syn_ack)

    t += 0.001
    ack = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=30001, ack=40001,
        options=[("Timestamp", (3001, 4000))],
    )
    ack.time = t
    packets.append(ack)

    client_seq = 30001
    server_seq = 40001
    tsval_c = 3002
    tsval_s = 4001

    # Send 90 data packets, retransmit ~every 10th one (burst losses)
    for i in range(90):
        t += 0.15
        payload = f"DATA-{i:04d}:".encode() + b"X" * 100
        pkt = Ether() / IP(src=client, dst=server) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)

        plen = len(payload)

        # Simulate retransmission for ~every 10th packet, plus bursts
        if i % 10 == 7:
            # Burst: retransmit 2-3 times rapidly
            for r in range(2):
                t += 0.05  # 50ms gap
                retrans = Ether() / IP(src=client, dst=server) / TCP(
                    sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
                    options=[("Timestamp", (tsval_c + r + 1, tsval_s))],
                ) / Raw(load=payload)
                retrans.time = t
                packets.append(retrans)

        client_seq += plen
        tsval_c += 1

        # Server ACK
        t += 0.002
        ack_pkt = Ether() / IP(src=server, dst=client) / TCP(
            sport=dport, dport=sport, flags="A", seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        )
        ack_pkt.time = t
        packets.append(ack_pkt)
        tsval_s += 2

    # FIN
    t += 0.1
    fin1 = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq,
        options=[("Timestamp", (tsval_c, tsval_s))],
    )
    fin1.time = t
    packets.append(fin1)

    t += 0.001
    fin2 = Ether() / IP(src=server, dst=client) / TCP(
        sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1,
        options=[("Timestamp", (tsval_s + 1, tsval_c))],
    )
    fin2.time = t
    packets.append(fin2)

    t += 0.001
    last_ack = Ether() / IP(src=client, dst=server) / TCP(
        sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1,
        options=[("Timestamp", (tsval_c + 1, tsval_s + 1))],
    )
    last_ack.time = t
    packets.append(last_ack)

    return packets


def generate_demo_pcap(pcap_path: str = DEMO_PCAP) -> str:
    """Generate the full demo pcap with all 3 flows."""
    print("Generating synthetic pcap...")

    flow1 = _generate_flow1_normal()
    flow2 = _generate_flow2_latency_spike()
    flow3 = _generate_flow3_packet_loss()

    # Merge and sort by timestamp
    all_packets = flow1 + flow2 + flow3
    all_packets.sort(key=lambda p: float(p.time))

    wrpcap(pcap_path, all_packets)
    print(f"  Wrote {len(all_packets)} packets to {pcap_path}")
    return pcap_path


def run_demo() -> None:
    """Run the full demo: generate pcap, analyze, render, save."""
    print("=" * 72)
    print("  netlat Demo - Network Latency Incident Simulation")
    print("=" * 72)
    print()

    # Step 1: Generate pcap
    pcap_path = generate_demo_pcap()
    print()

    # Step 2: Run analysis pipeline
    print("Running analysis pipeline...")
    from netlat.analysis.pipeline import AnalysisConfig, AnalysisPipeline

    config = AnalysisConfig(
        anomaly_rtt_multiplier=3.0,
        anomaly_retrans_pct=1.0,
    )
    pipeline = AnalysisPipeline(config=config)
    t0 = time.monotonic()
    result = pipeline.analyze_pcap(Path(pcap_path))
    elapsed = time.monotonic() - t0
    print(f"  Analysis completed in {elapsed:.3f}s")
    print(f"  Processed {result.packets_processed} packets across {len(result.flows)} flows")
    print()

    # Step 3: Render human report
    from netlat.report.render import ReportRenderer

    renderer = ReportRenderer()
    human_report = renderer.render_human(result)
    print(human_report)

    # Step 4: Save JSON report
    json_report = renderer.render_json(result)
    Path(DEMO_JSON).write_text(json_report)
    print(f"\nJSON report saved to {DEMO_JSON}")

    # Step 5: Print summary of detected issues
    print()
    print("=" * 72)
    print("  Demo Summary - Detected Issues")
    print("=" * 72)

    anomaly_count = len(result.anomaly_events)
    retrans_count = len(result.retransmission_events)
    rtt_count = len(result.rtt_samples)

    print(f"\n  Total RTT samples:       {rtt_count}")
    print(f"  Total retransmissions:   {retrans_count}")
    print(f"  Total anomalies:         {anomaly_count}")

    if result.anomaly_events:
        print("\n  Anomaly details:")
        for i, evt in enumerate(result.anomaly_events[:20], 1):
            print(f"    {i}. [{evt.severity.upper():8s}] {evt.anomaly_type}: {evt.description}")
            print(f"       Flow: {evt.flow_key.tuple_str}")

    if result.top_flows_by_retransmissions:
        print("\n  Top flows by retransmissions:")
        for fk, cnt in result.top_flows_by_retransmissions[:5]:
            print(f"    {fk.tuple_str}: {cnt} retransmissions")

    if result.top_flows_by_rtt:
        print("\n  Top flows by max RTT:")
        for fk, rtt_val in result.top_flows_by_rtt[:5]:
            print(f"    {fk.tuple_str}: {rtt_val:.2f}ms")

    print()
    print(f"  Files generated:")
    print(f"    Pcap:   {DEMO_PCAP}")
    print(f"    JSON:   {DEMO_JSON}")
    print()
    print("=" * 72)


if __name__ == "__main__":
    run_demo()
