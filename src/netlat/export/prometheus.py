"""Prometheus metrics exporter for netlat."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    start_http_server,
)

if TYPE_CHECKING:
    from netlat.analysis.pipeline import AnalysisResult
    from netlat.flows.models import AnomalyEvent, RTTSample, RetransmissionEvent


# Default histogram buckets for RTT in milliseconds
_RTT_BUCKETS = (0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 5000, 10000)


class NetLatMetrics:
    """Prometheus metrics for netlat analysis."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self._registry = registry or CollectorRegistry()

        self.rtt_ms = Histogram(
            "netlat_rtt_ms",
            "RTT measurements in milliseconds",
            ["flow", "method"],
            buckets=_RTT_BUCKETS,
            registry=self._registry,
        )

        self.retransmissions_total = Counter(
            "netlat_retransmissions_total",
            "Total retransmissions detected",
            ["flow", "classification"],
            registry=self._registry,
        )

        self.anomalies_total = Counter(
            "netlat_anomalies_total",
            "Total anomalies detected",
            ["type", "severity"],
            registry=self._registry,
        )

        self.packets_total = Counter(
            "netlat_packets_total",
            "Total packets processed",
            ["protocol"],
            registry=self._registry,
        )

        self.active_flows = Gauge(
            "netlat_active_flows",
            "Number of active flows",
            registry=self._registry,
        )

        self.packets_processed = Counter(
            "netlat_packets_processed_total",
            "Total packets processed by the pipeline",
            registry=self._registry,
        )

        self.packets_skipped = Counter(
            "netlat_packets_skipped_total",
            "Total packets skipped by the pipeline",
            registry=self._registry,
        )

        self.capture_duration = Gauge(
            "netlat_capture_duration_seconds",
            "Duration of the capture in seconds",
            registry=self._registry,
        )

        self.analysis_duration = Gauge(
            "netlat_analysis_duration_seconds",
            "Time taken for analysis in seconds",
            registry=self._registry,
        )

    def record_rtt_sample(self, sample: RTTSample) -> None:
        """Record a single RTT sample."""
        self.rtt_ms.labels(
            flow=sample.flow_key.tuple_str,
            method=sample.method,
        ).observe(sample.rtt_ms)

    def record_retransmission(self, event: RetransmissionEvent) -> None:
        """Record a retransmission event."""
        self.retransmissions_total.labels(
            flow=event.flow_key.tuple_str,
            classification=event.classification,
        ).inc()

    def record_anomaly(self, event: AnomalyEvent) -> None:
        """Record an anomaly event."""
        self.anomalies_total.labels(
            type=event.anomaly_type,
            severity=event.severity,
        ).inc()

    def update_from_result(self, result: AnalysisResult) -> None:
        """Bulk-update all metrics from an AnalysisResult."""
        # RTT samples
        for sample in result.rtt_samples:
            self.record_rtt_sample(sample)

        # Retransmissions
        for event in result.retransmission_events:
            self.record_retransmission(event)

        # Anomalies
        for event in result.anomaly_events:
            self.record_anomaly(event)

        # Packet counts by protocol
        for proto, count in result.metadata.protocols.items():
            self.packets_total.labels(protocol=proto).inc(count)

        # Gauges
        self.active_flows.set(len(result.flows))
        self.capture_duration.set(result.metadata.duration_seconds)
        self.analysis_duration.set(result.analysis_duration_s)
        self.packets_processed.inc(result.packets_processed)
        self.packets_skipped.inc(result.packets_skipped)

    def generate(self) -> bytes:
        """Generate Prometheus text exposition format."""
        return generate_latest(self._registry)


class MetricsServer:
    """HTTP server that exposes Prometheus metrics."""

    def __init__(
        self,
        port: int = 9090,
        metrics: NetLatMetrics | None = None,
    ) -> None:
        self._port = port
        self._metrics = metrics or NetLatMetrics()
        self._thread: threading.Thread | None = None

    @property
    def metrics(self) -> NetLatMetrics:
        """Access the underlying metrics object."""
        return self._metrics

    def start(self) -> None:
        """Start the metrics HTTP server in a background thread."""
        start_http_server(self._port, registry=self._metrics._registry)

    def update(self, result: AnalysisResult) -> None:
        """Update metrics from an analysis result."""
        self._metrics.update_from_result(result)
