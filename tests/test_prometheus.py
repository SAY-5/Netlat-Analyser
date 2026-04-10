"""Tests for the Prometheus metrics exporter."""

from __future__ import annotations

from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry

from tests.conftest import make_tcp_packet, write_pcap

from netlat.analysis.pipeline import AnalysisConfig, AnalysisPipeline
from netlat.export.prometheus import MetricsServer, NetLatMetrics
from netlat.flows.models import (
    AnomalyEvent,
    FlowKey,
    RTTSample,
    RetransmissionEvent,
)


def _make_flow_key() -> FlowKey:
    return FlowKey(
        ip_a="10.0.0.1",
        port_a=12345,
        ip_b="10.0.0.2",
        port_b=80,
        protocol="TCP",
    )


class TestMetricsInitialization:
    """Test that all metrics are properly initialized."""

    def test_metrics_initialization(self) -> None:
        registry = CollectorRegistry()
        metrics = NetLatMetrics(registry=registry)

        assert metrics.rtt_ms is not None
        assert metrics.retransmissions_total is not None
        assert metrics.anomalies_total is not None
        assert metrics.packets_total is not None
        assert metrics.active_flows is not None
        assert metrics.packets_processed is not None
        assert metrics.packets_skipped is not None
        assert metrics.capture_duration is not None
        assert metrics.analysis_duration is not None

    def test_generate_empty(self) -> None:
        registry = CollectorRegistry()
        metrics = NetLatMetrics(registry=registry)
        output = metrics.generate()
        assert isinstance(output, bytes)


class TestRecordRTTSample:
    """Test recording RTT samples."""

    def test_record_rtt_sample(self) -> None:
        registry = CollectorRegistry()
        metrics = NetLatMetrics(registry=registry)
        fk = _make_flow_key()

        sample = RTTSample(
            timestamp=1000.0,
            rtt_ms=15.5,
            flow_key=fk,
            method="tcp_handshake",
        )
        metrics.record_rtt_sample(sample)

        output = metrics.generate().decode()
        assert "netlat_rtt_ms" in output

    def test_record_multiple_samples(self) -> None:
        registry = CollectorRegistry()
        metrics = NetLatMetrics(registry=registry)
        fk = _make_flow_key()

        for rtt in [10.0, 20.0, 50.0]:
            sample = RTTSample(
                timestamp=1000.0, rtt_ms=rtt, flow_key=fk, method="data_ack"
            )
            metrics.record_rtt_sample(sample)

        output = metrics.generate().decode()
        assert "netlat_rtt_ms_count" in output


class TestRecordRetransmission:
    """Test recording retransmission events."""

    def test_record_retransmission(self) -> None:
        registry = CollectorRegistry()
        metrics = NetLatMetrics(registry=registry)
        fk = _make_flow_key()

        event = RetransmissionEvent(
            timestamp=1000.0,
            flow_key=fk,
            seq=12345,
            classification="fast_retransmit",
        )
        metrics.record_retransmission(event)

        output = metrics.generate().decode()
        assert "netlat_retransmissions_total" in output
        assert "fast_retransmit" in output


class TestRecordAnomaly:
    """Test recording anomaly events."""

    def test_record_anomaly(self) -> None:
        registry = CollectorRegistry()
        metrics = NetLatMetrics(registry=registry)
        fk = _make_flow_key()

        event = AnomalyEvent(
            timestamp=1000.0,
            flow_key=fk,
            anomaly_type="high_rtt",
            severity="high",
            description="RTT spike",
            value=500.0,
            threshold=100.0,
        )
        metrics.record_anomaly(event)

        output = metrics.generate().decode()
        assert "netlat_anomalies_total" in output
        assert "high_rtt" in output


def _build_clean_handshake() -> list[tuple[float, bytes]]:
    """Build a minimal TCP handshake for integration testing."""
    SYN = 0x02
    SYN_ACK = 0x12
    ACK = 0x10

    packets = []
    ts = 1000.0

    packets.append((ts, make_tcp_packet(
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=12345, dst_port=80,
        flags=SYN, seq=100, ack=0,
    )))
    ts += 0.010
    packets.append((ts, make_tcp_packet(
        src_ip="10.0.0.2", dst_ip="10.0.0.1",
        src_port=80, dst_port=12345,
        flags=SYN_ACK, seq=200, ack=101,
    )))
    ts += 0.010
    packets.append((ts, make_tcp_packet(
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=12345, dst_port=80,
        flags=ACK, seq=101, ack=201,
    )))

    return packets


class TestUpdateFromResult:
    """Test bulk update from an AnalysisResult."""

    def test_update_from_result(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "metrics.pcap"
        packets = _build_clean_handshake()
        write_pcap(pcap_path, packets)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        result = pipeline.analyze_pcap(pcap_path)

        registry = CollectorRegistry()
        metrics = NetLatMetrics(registry=registry)
        metrics.update_from_result(result)

        output = metrics.generate().decode()

        # Should have flow count
        assert "netlat_active_flows" in output
        # Should have packet counts
        assert "netlat_packets_total" in output
        # Should have analysis duration
        assert "netlat_analysis_duration_seconds" in output


class TestMetricsOutput:
    """Test Prometheus text exposition format output."""

    def test_metrics_output(self) -> None:
        registry = CollectorRegistry()
        metrics = NetLatMetrics(registry=registry)
        fk = _make_flow_key()

        # Record some data
        metrics.record_rtt_sample(RTTSample(
            timestamp=1000.0, rtt_ms=10.0, flow_key=fk, method="tcp_handshake",
        ))
        metrics.record_retransmission(RetransmissionEvent(
            timestamp=1000.0, flow_key=fk, seq=100, classification="timeout_rto",
        ))
        metrics.record_anomaly(AnomalyEvent(
            timestamp=1000.0, flow_key=fk, anomaly_type="high_rtt",
            severity="high", description="test",
        ))

        output = metrics.generate().decode()

        # Verify Prometheus format
        assert "# HELP" in output
        assert "# TYPE" in output
        assert "netlat_rtt_ms_bucket" in output
        assert "netlat_retransmissions_total" in output
        assert "netlat_anomalies_total" in output


class TestMetricsServer:
    """Test MetricsServer setup (without actually starting HTTP)."""

    def test_server_creation(self) -> None:
        server = MetricsServer(port=9999)
        assert server.metrics is not None

    def test_server_update(self, tmp_path: Path) -> None:
        pcap_path = tmp_path / "srv.pcap"
        packets = _build_clean_handshake()
        write_pcap(pcap_path, packets)

        pipeline = AnalysisPipeline(config=AnalysisConfig())
        result = pipeline.analyze_pcap(pcap_path)

        server = MetricsServer(port=9998)
        server.update(result)

        output = server.metrics.generate().decode()
        assert "netlat_active_flows" in output
