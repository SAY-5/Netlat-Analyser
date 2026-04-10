"""Tests for the analysis pipeline and report renderer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.conftest import make_tcp_packet, write_pcap

from netlat.analysis.pipeline import (
    AnalysisConfig,
    AnalysisPipeline,
    FocusFilter,
    _parse_time_window,
)
from netlat.report.render import ReportRenderer


def _build_clean_handshake(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    base_ts: float = 1000.0,
) -> list[tuple[float, bytes]]:
    """Build a clean TCP handshake + data exchange with no anomalies."""
    SYN = 0x02
    SYN_ACK = 0x12
    ACK = 0x10

    packets = []
    ts = base_ts

    # SYN
    packets.append((ts, make_tcp_packet(
        src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
        flags=SYN, seq=100, ack=0, window=65535,
    )))
    ts += 0.010

    # SYN-ACK
    packets.append((ts, make_tcp_packet(
        src_ip=dst_ip, dst_ip=src_ip, src_port=dst_port, dst_port=src_port,
        flags=SYN_ACK, seq=200, ack=101, window=65535,
    )))
    ts += 0.010

    # ACK (completing handshake)
    packets.append((ts, make_tcp_packet(
        src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
        flags=ACK, seq=101, ack=201, window=65535,
    )))
    ts += 0.010

    # Data: client sends some data
    packets.append((ts, make_tcp_packet(
        src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
        flags=ACK, seq=101, ack=201, payload=b"GET / HTTP/1.1\r\n", window=65535,
    )))
    ts += 0.020

    # Data: server ACKs
    packets.append((ts, make_tcp_packet(
        src_ip=dst_ip, dst_ip=src_ip, src_port=dst_port, dst_port=src_port,
        flags=ACK, seq=201, ack=117, window=65535,
    )))

    return packets


class TestEndToEndNormal:
    """Test the pipeline with a clean pcap - no anomalies expected."""

    def test_end_to_end_normal(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "clean.pcap"
        packets = _build_clean_handshake()
        write_pcap(pcap_path, packets)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        result = pipeline.analyze_pcap(pcap_path)

        # Basic assertions
        assert result.packets_processed == 5
        assert result.packets_skipped == 0
        assert len(result.flows) >= 1
        assert result.metadata.packet_count == 5
        assert result.analysis_duration_s >= 0

        # No anomalies in a clean capture
        assert len(result.anomaly_events) == 0
        assert result.anomaly_summary["total"] == 0

        # No retransmissions
        assert len(result.retransmission_events) == 0
        assert result.retransmission_summary["total"] == 0

        # RTT: should have at least handshake RTT
        assert len(result.rtt_samples) >= 1
        assert result.rtt_summary["count"] >= 1
        assert result.rtt_summary["min_ms"] > 0


class TestFocusFilter:
    """Test focus filter functionality."""

    def test_focus_filter_ip(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "multi.pcap"

        # Two flows: 10.0.0.1->10.0.0.2 and 192.168.1.1->192.168.1.2
        packets_a = _build_clean_handshake(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80,
            base_ts=1000.0,
        )
        packets_b = _build_clean_handshake(
            src_ip="192.168.1.1", dst_ip="192.168.1.2",
            src_port=54321, dst_port=443,
            base_ts=1000.1,
        )
        all_packets = packets_a + packets_b
        all_packets.sort(key=lambda x: x[0])
        write_pcap(pcap_path, all_packets)

        # Focus on 10.0.0.1
        config = AnalysisConfig(focus_filter="10.0.0.1")
        pipeline = AnalysisPipeline(config=config)
        result = pipeline.analyze_pcap(pcap_path)

        # Should only process the first flow's packets
        assert result.packets_processed == 5
        assert result.packets_skipped == 5
        assert len(result.flows) == 1
        flow = result.flows[0]
        # Flow key should involve 10.0.0.1
        assert "10.0.0.1" in flow.key.tuple_str

    def test_focus_filter_port(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "multi_port.pcap"

        packets_a = _build_clean_handshake(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80,
            base_ts=1000.0,
        )
        packets_b = _build_clean_handshake(
            src_ip="10.0.0.3", dst_ip="10.0.0.4",
            src_port=54321, dst_port=443,
            base_ts=1000.1,
        )
        all_packets = packets_a + packets_b
        all_packets.sort(key=lambda x: x[0])
        write_pcap(pcap_path, all_packets)

        # Focus on port 443
        config = AnalysisConfig(focus_filter=":443")
        pipeline = AnalysisPipeline(config=config)
        result = pipeline.analyze_pcap(pcap_path)

        assert result.packets_processed == 5
        assert result.packets_skipped == 5
        assert len(result.flows) == 1
        assert "443" in result.flows[0].key.tuple_str


class TestFocusFilterUnit:
    """Unit tests for the FocusFilter class."""

    def test_ip_filter(self) -> None:
        f = FocusFilter("10.0.0.1")
        from tests.conftest import make_packet
        pkt = make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2")
        assert f.matches(pkt) is True

        pkt2 = make_packet(src_ip="192.168.1.1", dst_ip="192.168.1.2")
        assert f.matches(pkt2) is False

    def test_port_filter(self) -> None:
        f = FocusFilter(":80")
        from tests.conftest import make_packet
        pkt = make_packet(src_port=12345, dst_port=80)
        assert f.matches(pkt) is True

        pkt2 = make_packet(src_port=12345, dst_port=443)
        assert f.matches(pkt2) is False

    def test_cidr_filter(self) -> None:
        f = FocusFilter("10.0.0.0/24")
        from tests.conftest import make_packet
        pkt = make_packet(src_ip="10.0.0.50", dst_ip="192.168.1.1")
        assert f.matches(pkt) is True

        pkt2 = make_packet(src_ip="192.168.1.1", dst_ip="192.168.1.2")
        assert f.matches(pkt2) is False

    def test_ip_port_filter(self) -> None:
        f = FocusFilter("10.0.0.1:80")
        from tests.conftest import make_packet

        # IP and port on same side (src) - should match
        pkt_src = make_packet(src_ip="10.0.0.1", src_port=80, dst_ip="10.0.0.2", dst_port=443)
        assert f.matches(pkt_src) is True

        # IP and port on same side (dst) - should match
        pkt_dst = make_packet(src_ip="10.0.0.2", src_port=443, dst_ip="10.0.0.1", dst_port=80)
        assert f.matches(pkt_dst) is True

        # IP on src but port 80 on dst (different sides) - should NOT match
        pkt_cross = make_packet(src_ip="10.0.0.1", src_port=443, dst_ip="10.0.0.2", dst_port=80)
        assert f.matches(pkt_cross) is False

        # Neither side matches
        pkt_none = make_packet(src_ip="10.0.0.1", src_port=443, dst_ip="10.0.0.2", dst_port=8080)
        assert f.matches(pkt_none) is False


class TestTimeWindow:
    """Test time window parsing."""

    def test_parse_seconds(self) -> None:
        assert _parse_time_window("10s") == 10.0

    def test_parse_minutes(self) -> None:
        assert _parse_time_window("5m") == 300.0

    def test_parse_hours(self) -> None:
        assert _parse_time_window("1h") == 3600.0

    def test_parse_bare_number(self) -> None:
        assert _parse_time_window("30") == 30.0

    def test_parse_invalid(self) -> None:
        with pytest.raises(ValueError):
            _parse_time_window("abc")


class TestReportHuman:
    """Test human-readable report rendering."""

    def test_report_human_output(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "report.pcap"
        packets = _build_clean_handshake()
        write_pcap(pcap_path, packets)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        result = pipeline.analyze_pcap(pcap_path)

        renderer = ReportRenderer()
        text = renderer.render_human(result)

        assert "netlat" in text
        assert "Capture Summary" in text
        assert "RTT Summary" in text
        assert "Retransmissions" in text
        assert "Anomalies" in text
        assert "Flows" in text
        assert str(pcap_path) in text


class TestReportJSON:
    """Test JSON report rendering."""

    def test_report_json_output(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "report_json.pcap"
        packets = _build_clean_handshake()
        write_pcap(pcap_path, packets)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        result = pipeline.analyze_pcap(pcap_path)

        renderer = ReportRenderer()
        json_str = renderer.render_json(result)

        data = json.loads(json_str)
        assert "metadata" in data
        assert "rtt_summary" in data
        assert "retransmission_summary" in data
        assert "anomaly_summary" in data
        assert "flows" in data
        assert "rtt_samples" in data
        assert data["packets_processed"] == 5
        assert data["metadata"]["packet_count"] == 5

    def test_report_json_has_iso_timestamps(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "report_ts.pcap"
        packets = _build_clean_handshake()
        write_pcap(pcap_path, packets)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        result = pipeline.analyze_pcap(pcap_path)

        renderer = ReportRenderer()
        json_str = renderer.render_json(result)
        data = json.loads(json_str)

        # First timestamp should be ISO format
        first_ts = data["metadata"]["first_timestamp"]
        assert "T" in first_ts  # ISO 8601 has a T separator


class TestReportToFile:
    """Test file-based report output."""

    def test_render_to_file_both(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "file_report.pcap"
        packets = _build_clean_handshake()
        write_pcap(pcap_path, packets)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        result = pipeline.analyze_pcap(pcap_path)

        renderer = ReportRenderer()
        out_path = tmp_path / "report"
        renderer.render_to_file(result, out_path, format="both")

        assert (tmp_path / "report.txt").exists()
        assert (tmp_path / "report.json").exists()
