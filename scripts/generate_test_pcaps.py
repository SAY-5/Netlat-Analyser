#!/usr/bin/env python3
"""Generate test pcap files using scapy for netlat development and testing."""

from __future__ import annotations

import os
import sys

try:
    from scapy.all import (
        IP,
        TCP,
        UDP,
        DNS,
        DNSQR,
        Ether,
        Raw,
        wrpcap,
    )
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy", file=sys.stderr)
    sys.exit(1)


OUTPUT_DIR = "/tmp/netlat_test_pcaps"

# Base time for deterministic timestamps
BASE_TIME = 1705276800.0


def generate_normal_tcp(path: str | None = None, num_packets: int = 100) -> str:
    """Generate a normal TCP session with 3-way handshake, data, and teardown.

    Args:
        path: Output pcap path. Defaults to OUTPUT_DIR/normal_tcp.pcap.
        num_packets: Approximate number of packets to generate.

    Returns:
        Path to the generated pcap file.
    """
    if path is None:
        path = os.path.join(OUTPUT_DIR, "normal_tcp.pcap")

    packets = []
    client_ip = "10.0.1.10"
    server_ip = "10.0.1.20"
    client_port = 54321
    server_port = 443
    t = BASE_TIME

    # 3-way handshake
    syn = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="S", seq=1000,
        options=[("Timestamp", (100, 0)), ("MSS", 1460), ("WScale", 7)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    syn_ack = Ether() / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001,
        options=[("Timestamp", (200, 100)), ("MSS", 1460), ("WScale", 7)],
    )
    syn_ack.time = t
    packets.append(syn_ack)

    t += 0.001
    ack = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001,
        options=[("Timestamp", (101, 200))],
    )
    ack.time = t
    packets.append(ack)

    # Data exchange - generate pairs up to num_packets
    client_seq = 1001
    server_seq = 2001
    tsval_c = 102
    tsval_s = 201
    pairs = max((num_packets - 6) // 2, 1)  # subtract handshake + fin

    for i in range(pairs):
        t += 0.1
        payload = f"GET /page/{i} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
        pkt = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
            sport=client_port, dport=server_port, flags="PA",
            seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        client_seq += len(payload)
        tsval_c += 1

        t += 0.001  # 1ms RTT
        response_data = f"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nOK{i:03d}".encode()
        resp = Ether() / IP(src=server_ip, dst=client_ip) / TCP(
            sport=server_port, dport=client_port, flags="PA",
            seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        ) / Raw(load=response_data)
        resp.time = t
        packets.append(resp)
        server_seq += len(response_data)
        tsval_s += 2

    # Teardown
    t += 0.1
    fin1 = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="FA",
        seq=client_seq, ack=server_seq,
        options=[("Timestamp", (tsval_c, tsval_s))],
    )
    fin1.time = t
    packets.append(fin1)

    t += 0.001
    fin_ack = Ether() / IP(src=server_ip, dst=client_ip) / TCP(
        sport=server_port, dport=client_port, flags="FA",
        seq=server_seq, ack=client_seq + 1,
        options=[("Timestamp", (tsval_s + 1, tsval_c))],
    )
    fin_ack.time = t
    packets.append(fin_ack)

    t += 0.001
    last_ack = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=client_port, dport=server_port, flags="A",
        seq=client_seq + 1, ack=server_seq + 1,
        options=[("Timestamp", (tsval_c + 1, tsval_s + 1))],
    )
    last_ack.time = t
    packets.append(last_ack)

    wrpcap(path, packets)
    print(f"  Created {os.path.basename(path)} ({len(packets)} packets)")
    return path


def generate_retransmit_scenario(path: str | None = None) -> str:
    """Generate a TCP session with retransmissions and burst loss.

    Args:
        path: Output pcap path. Defaults to OUTPUT_DIR/retransmit_tcp.pcap.

    Returns:
        Path to the generated pcap file.
    """
    if path is None:
        path = os.path.join(OUTPUT_DIR, "retransmit_tcp.pcap")

    packets = []
    client_ip = "10.0.2.10"
    server_ip = "10.0.2.20"
    sport = 55555
    dport = 80
    t = BASE_TIME

    # Handshake
    syn = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=sport, dport=dport, flags="S", seq=100,
        options=[("Timestamp", (500, 0)), ("MSS", 1460)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    syn_ack = Ether() / IP(src=server_ip, dst=client_ip) / TCP(
        sport=dport, dport=sport, flags="SA", seq=200, ack=101,
        options=[("Timestamp", (600, 500)), ("MSS", 1460)],
    )
    syn_ack.time = t
    packets.append(syn_ack)

    t += 0.001
    ack = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=sport, dport=dport, flags="A", seq=101, ack=201,
        options=[("Timestamp", (501, 600))],
    )
    ack.time = t
    packets.append(ack)

    # Data with retransmissions
    client_seq = 101
    server_seq = 201
    tsval_c = 502
    tsval_s = 601
    data = b"X" * 1000

    for i in range(20):
        t += 0.1
        pkt = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=data)
        pkt.time = t
        packets.append(pkt)

        # Retransmit every 5th packet
        if i % 5 == 3:
            t += 0.05
            retrans = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
                sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
                options=[("Timestamp", (tsval_c + 1, tsval_s))],
            ) / Raw(load=data)
            retrans.time = t
            packets.append(retrans)

            # Second retransmit for burst
            t += 0.05
            retrans2 = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
                sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
                options=[("Timestamp", (tsval_c + 2, tsval_s))],
            ) / Raw(load=data)
            retrans2.time = t
            packets.append(retrans2)

        client_seq += len(data)
        tsval_c += 3

        # ACK
        t += 0.002
        ack_pkt = Ether() / IP(src=server_ip, dst=client_ip) / TCP(
            sport=dport, dport=sport, flags="A", seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        )
        ack_pkt.time = t
        packets.append(ack_pkt)
        tsval_s += 2

    # FIN
    t += 0.1
    fin1 = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq,
        options=[("Timestamp", (tsval_c, tsval_s))],
    )
    fin1.time = t
    packets.append(fin1)

    t += 0.001
    fin2 = Ether() / IP(src=server_ip, dst=client_ip) / TCP(
        sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1,
        options=[("Timestamp", (tsval_s + 1, tsval_c))],
    )
    fin2.time = t
    packets.append(fin2)

    t += 0.001
    last = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1,
        options=[("Timestamp", (tsval_c + 1, tsval_s + 1))],
    )
    last.time = t
    packets.append(last)

    wrpcap(path, packets)
    print(f"  Created {os.path.basename(path)} ({len(packets)} packets)")
    return path


def generate_rtt_spike_scenario(path: str | None = None) -> str:
    """Generate a TCP session with normal RTT then a latency spike.

    Args:
        path: Output pcap path. Defaults to OUTPUT_DIR/rtt_spike_tcp.pcap.

    Returns:
        Path to the generated pcap file.
    """
    if path is None:
        path = os.path.join(OUTPUT_DIR, "rtt_spike_tcp.pcap")

    packets = []
    client_ip = "10.0.3.10"
    server_ip = "10.0.3.20"
    sport = 56789
    dport = 8080
    t = BASE_TIME

    # Handshake
    syn = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=sport, dport=dport, flags="S", seq=5000,
        options=[("Timestamp", (1000, 0)), ("MSS", 1460)],
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    syn_ack = Ether() / IP(src=server_ip, dst=client_ip) / TCP(
        sport=dport, dport=sport, flags="SA", seq=6000, ack=5001,
        options=[("Timestamp", (2000, 1000)), ("MSS", 1460)],
    )
    syn_ack.time = t
    packets.append(syn_ack)

    t += 0.001
    ack = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=sport, dport=dport, flags="A", seq=5001, ack=6001,
        options=[("Timestamp", (1001, 2000))],
    )
    ack.time = t
    packets.append(ack)

    client_seq = 5001
    server_seq = 6001
    tsval_c = 1002
    tsval_s = 2001

    # Phase 1: Normal ~1ms RTT (20 exchanges for baseline)
    for i in range(20):
        t += 0.1
        payload = b"A" * 100
        pkt = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        client_seq += len(payload)
        tsval_c += 1

        t += 0.001  # 1ms RTT
        ack_pkt = Ether() / IP(src=server_ip, dst=client_ip) / TCP(
            sport=dport, dport=sport, flags="A", seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        )
        ack_pkt.time = t
        packets.append(ack_pkt)
        tsval_s += 2

    # Phase 2: Spike - 200ms+ RTT (5 exchanges)
    for i in range(5):
        t += 0.1
        payload = b"SLOW" * 25
        pkt = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
            sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq,
            options=[("Timestamp", (tsval_c, tsval_s))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        client_seq += len(payload)
        tsval_c += 1

        t += 0.250  # 250ms RTT spike
        ack_pkt = Ether() / IP(src=server_ip, dst=client_ip) / TCP(
            sport=dport, dport=sport, flags="A", seq=server_seq, ack=client_seq,
            options=[("Timestamp", (tsval_s + 1, tsval_c))],
        )
        ack_pkt.time = t
        packets.append(ack_pkt)
        tsval_s += 2

    # FIN
    t += 0.1
    fin1 = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq,
        options=[("Timestamp", (tsval_c, tsval_s))],
    )
    fin1.time = t
    packets.append(fin1)

    t += 0.001
    fin2 = Ether() / IP(src=server_ip, dst=client_ip) / TCP(
        sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1,
        options=[("Timestamp", (tsval_s + 1, tsval_c))],
    )
    fin2.time = t
    packets.append(fin2)

    t += 0.001
    last = Ether() / IP(src=client_ip, dst=server_ip) / TCP(
        sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1,
        options=[("Timestamp", (tsval_c + 1, tsval_s + 1))],
    )
    last.time = t
    packets.append(last)

    wrpcap(path, packets)
    print(f"  Created {os.path.basename(path)} ({len(packets)} packets)")
    return path


def generate_multi_flow_incident(path: str | None = None) -> str:
    """Generate the full demo scenario with 3 flows (normal, spike, loss).

    This delegates to scripts/demo.py's pcap generator.

    Args:
        path: Output pcap path. Defaults to OUTPUT_DIR/multi_flow_incident.pcap.

    Returns:
        Path to the generated pcap file.
    """
    if path is None:
        path = os.path.join(OUTPUT_DIR, "multi_flow_incident.pcap")

    # Import from demo script
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from demo import generate_demo_pcap

    generate_demo_pcap(path)
    return path


def generate_large_capture(path: str | None = None, num_packets: int = 100000) -> str:
    """Generate a large pcap for performance testing.

    Args:
        path: Output pcap path. Defaults to OUTPUT_DIR/large_capture.pcap.
        num_packets: Number of packets to generate.

    Returns:
        Path to the generated pcap file.
    """
    if path is None:
        path = os.path.join(OUTPUT_DIR, "large_capture.pcap")

    packets = []
    t = BASE_TIME

    # Use 10 concurrent flows to make it realistic
    flows = []
    for f in range(10):
        flows.append({
            "client": f"10.1.{f}.1",
            "server": f"10.2.{f}.1",
            "sport": 40000 + f,
            "dport": 80 + f,
            "client_seq": 1000 + f * 100000,
            "server_seq": 2000 + f * 100000,
            "tsval_c": 100 + f * 10000,
            "tsval_s": 200 + f * 10000,
        })

    # Handshakes for all flows
    for f in flows:
        syn = Ether() / IP(src=f["client"], dst=f["server"]) / TCP(
            sport=f["sport"], dport=f["dport"], flags="S", seq=f["client_seq"],
            options=[("Timestamp", (f["tsval_c"], 0)), ("MSS", 1460)],
        )
        syn.time = t
        packets.append(syn)
        t += 0.0001

        syn_ack = Ether() / IP(src=f["server"], dst=f["client"]) / TCP(
            sport=f["dport"], dport=f["sport"], flags="SA",
            seq=f["server_seq"], ack=f["client_seq"] + 1,
            options=[("Timestamp", (f["tsval_s"], f["tsval_c"])), ("MSS", 1460)],
        )
        syn_ack.time = t
        packets.append(syn_ack)
        t += 0.0001

        ack = Ether() / IP(src=f["client"], dst=f["server"]) / TCP(
            sport=f["sport"], dport=f["dport"], flags="A",
            seq=f["client_seq"] + 1, ack=f["server_seq"] + 1,
            options=[("Timestamp", (f["tsval_c"] + 1, f["tsval_s"]))],
        )
        ack.time = t
        packets.append(ack)
        t += 0.0001

        f["client_seq"] += 1
        f["server_seq"] += 1
        f["tsval_c"] += 2
        f["tsval_s"] += 1

    # Generate data packets round-robin across flows
    remaining = num_packets - len(packets)
    payload = b"D" * 100

    for i in range(remaining // 2):
        f = flows[i % len(flows)]
        t += 0.00005  # 50us between packets

        pkt = Ether() / IP(src=f["client"], dst=f["server"]) / TCP(
            sport=f["sport"], dport=f["dport"], flags="PA",
            seq=f["client_seq"], ack=f["server_seq"],
            options=[("Timestamp", (f["tsval_c"], f["tsval_s"]))],
        ) / Raw(load=payload)
        pkt.time = t
        packets.append(pkt)
        f["client_seq"] += len(payload)
        f["tsval_c"] += 1

        t += 0.001
        ack_pkt = Ether() / IP(src=f["server"], dst=f["client"]) / TCP(
            sport=f["dport"], dport=f["sport"], flags="A",
            seq=f["server_seq"], ack=f["client_seq"],
            options=[("Timestamp", (f["tsval_s"] + 1, f["tsval_c"]))],
        )
        ack_pkt.time = t
        packets.append(ack_pkt)
        f["tsval_s"] += 2

    wrpcap(path, packets)
    print(f"  Created {os.path.basename(path)} ({len(packets)} packets)")
    return path


def generate_mixed_flows(path: str | None = None) -> str:
    """Generate a pcap with multiple TCP and UDP flows.

    Args:
        path: Output pcap path. Defaults to OUTPUT_DIR/mixed_flows.pcap.

    Returns:
        Path to the generated pcap file.
    """
    if path is None:
        path = os.path.join(OUTPUT_DIR, "mixed_flows.pcap")

    packets = []
    t = BASE_TIME

    # TCP flow 1
    syn = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=11111, dport=80, flags="S", seq=100,
    )
    syn.time = t
    packets.append(syn)

    t += 0.001
    syn_ack = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(
        sport=80, dport=11111, flags="SA", seq=200, ack=101,
    )
    syn_ack.time = t
    packets.append(syn_ack)

    t += 0.001
    ack = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=11111, dport=80, flags="A", seq=101, ack=201,
    )
    ack.time = t
    packets.append(ack)

    # TCP flow 2
    t += 0.001
    syn2 = Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / TCP(
        sport=22222, dport=443, flags="S", seq=300,
    )
    syn2.time = t
    packets.append(syn2)

    t += 0.001
    syn_ack2 = Ether() / IP(src="10.0.0.4", dst="10.0.0.3") / TCP(
        sport=443, dport=22222, flags="SA", seq=400, ack=301,
    )
    syn_ack2.time = t
    packets.append(syn_ack2)

    # UDP flow (DNS)
    t += 0.001
    dns_q = Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(
        sport=33333, dport=53,
    ) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    dns_q.time = t
    packets.append(dns_q)

    t += 0.002
    dns_r = Ether() / IP(src="8.8.8.8", dst="10.0.0.1") / UDP(
        sport=53, dport=33333,
    ) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    dns_r.time = t
    packets.append(dns_r)

    # More TCP flow 1 data
    t += 0.001
    data_pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=11111, dport=80, flags="PA", seq=101, ack=201,
    ) / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
    data_pkt.time = t
    packets.append(data_pkt)

    wrpcap(path, packets)
    print(f"  Created {os.path.basename(path)} ({len(packets)} packets)")
    return path


def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Generating test pcaps in {OUTPUT_DIR}/")
    generate_normal_tcp()
    generate_retransmit_scenario()
    generate_rtt_spike_scenario()
    generate_mixed_flows()
    print("Done.")


if __name__ == "__main__":
    main()
