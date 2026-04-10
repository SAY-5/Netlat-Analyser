"""Analysis pipeline - orchestrates parsing, tracking, RTT, retransmit, anomaly."""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from netlat.analysis.anomaly import AnomalyDetector, ThresholdProfile
from netlat.analysis.retransmit import RetransmissionDetector
from netlat.analysis.rtt import RTTEstimator
from netlat.flows.models import (
    AnomalyEvent,
    CaptureMetadata,
    FlowKey,
    Packet,
    RTTSample,
    RetransmissionEvent,
)
from netlat.flows.tracker import FlowState, FlowTracker
from netlat.pcap.dpkt_backend import DpktParser
from netlat.util.logging import get_logger

log = get_logger("pipeline")


@dataclass
class AnalysisConfig:
    """Configuration for the analysis pipeline."""

    time_window: str | None = None  # "10s", "1m", "5m"
    focus_filter: str | None = None  # IP, CIDR, :port, IP:port
    anomaly_rtt_multiplier: float = 3.0
    anomaly_retrans_pct: float = 1.0
    max_flows: int = 100_000
    flow_timeout_s: float = 300.0


@dataclass
class AnalysisResult:
    """Complete result of a pipeline analysis run."""

    metadata: CaptureMetadata
    config: AnalysisConfig
    flows: list[FlowState]
    rtt_samples: list[RTTSample]
    rtt_summary: dict
    retransmission_events: list[RetransmissionEvent]
    retransmission_summary: dict
    anomaly_events: list[AnomalyEvent]
    anomaly_summary: dict
    top_flows_by_retransmissions: list[tuple[FlowKey, int]]
    top_flows_by_rtt: list[tuple[FlowKey, float]]
    analysis_duration_s: float
    packets_processed: int
    packets_skipped: int


def _parse_time_window(window_str: str) -> float:
    """Parse a time window string like '10s', '1m', '5m' into seconds."""
    m = re.match(r"^(\d+(?:\.\d+)?)\s*([smhSMH]?)$", window_str.strip())
    if not m:
        raise ValueError(f"Invalid time window format: {window_str!r}")
    value = float(m.group(1))
    unit = m.group(2).lower()
    if unit == "m":
        return value * 60.0
    if unit == "h":
        return value * 3600.0
    return value  # seconds by default


class FocusFilter:
    """Packet filter matching IP, CIDR, :port, or IP:port patterns."""

    def __init__(self, spec: str) -> None:
        self._spec = spec.strip()
        self._network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
        self._ip: str | None = None
        self._port: int | None = None
        self._parse()

    def _parse(self) -> None:
        spec = self._spec

        # :port
        if spec.startswith(":"):
            self._port = int(spec[1:])
            return

        # IP:port
        if ":" in spec and not spec.startswith("["):
            # Could be IPv4:port or just a port
            parts = spec.rsplit(":", 1)
            if len(parts) == 2:
                try:
                    self._port = int(parts[1])
                    self._ip = parts[0]
                    return
                except ValueError:
                    pass

        # CIDR notation
        if "/" in spec:
            try:
                self._network = ipaddress.ip_network(spec, strict=False)
                return
            except ValueError:
                pass

        # Plain IP
        try:
            ipaddress.ip_address(spec)
            self._ip = spec
            return
        except ValueError:
            pass

        raise ValueError(f"Invalid focus filter: {spec!r}")

    def matches(self, pkt: Packet) -> bool:
        """Return True if the packet matches this filter."""
        if self._network is not None:
            try:
                src_match = ipaddress.ip_address(pkt.src_ip) in self._network
                dst_match = ipaddress.ip_address(pkt.dst_ip) in self._network
            except ValueError:
                return False
            if not (src_match or dst_match):
                return False

        # IP:port combined - require IP and port on the SAME side
        if self._ip is not None and self._port is not None and self._network is None:
            src_match = pkt.src_ip == self._ip and pkt.src_port == self._port
            dst_match = pkt.dst_ip == self._ip and pkt.dst_port == self._port
            return src_match or dst_match

        # IP only
        if self._ip is not None and self._network is None:
            if pkt.src_ip != self._ip and pkt.dst_ip != self._ip:
                return False

        # Port only
        if self._port is not None and self._ip is None:
            if pkt.src_port != self._port and pkt.dst_port != self._port:
                return False

        return True


def _compute_rtt_summary(samples: list[RTTSample]) -> dict:
    """Compute RTT statistics from samples."""
    if not samples:
        return {
            "count": 0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "by_method": {},
        }

    values = [s.rtt_ms for s in samples]
    values_sorted = sorted(values)
    n = len(values_sorted)

    by_method: dict[str, int] = {}
    for s in samples:
        by_method[s.method] = by_method.get(s.method, 0) + 1

    return {
        "count": n,
        "min_ms": values_sorted[0],
        "max_ms": values_sorted[-1],
        "mean_ms": sum(values) / n,
        "median_ms": values_sorted[n // 2],
        "p95_ms": values_sorted[int(n * 0.95)] if n > 1 else values_sorted[0],
        "p99_ms": values_sorted[int(n * 0.99)] if n > 1 else values_sorted[0],
        "by_method": by_method,
    }


def _top_flows_by_retransmissions(
    flows: list[FlowState], limit: int = 10
) -> list[tuple[FlowKey, int]]:
    """Return top flows sorted by retransmission count."""
    candidates = [(f.key, f.retransmissions) for f in flows if f.retransmissions > 0]
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[:limit]


def _top_flows_by_rtt(
    samples: list[RTTSample], limit: int = 10
) -> list[tuple[FlowKey, float]]:
    """Return top flows sorted by max RTT."""
    flow_max: dict[FlowKey, float] = {}
    for s in samples:
        if s.flow_key not in flow_max or s.rtt_ms > flow_max[s.flow_key]:
            flow_max[s.flow_key] = s.rtt_ms
    ranked = sorted(flow_max.items(), key=lambda x: x[1], reverse=True)
    return ranked[:limit]


class AnalysisPipeline:
    """Orchestrates the full analysis: parse -> track -> RTT -> retransmit -> anomaly."""

    def __init__(self, config: AnalysisConfig | None = None) -> None:
        self._config = config or AnalysisConfig()

    def analyze_pcap(self, pcap_path: Path) -> AnalysisResult:
        """Run the full analysis pipeline on a pcap file."""
        t0 = time.monotonic()
        config = self._config

        # Set up components
        parser = DpktParser()
        tracker = FlowTracker(
            max_flows=config.max_flows,
            flow_timeout_s=config.flow_timeout_s,
        )
        rtt_estimator = RTTEstimator()
        retransmit_detector = RetransmissionDetector()
        anomaly_detector = AnomalyDetector(
            default_profile=ThresholdProfile(
                rtt_spike_multiplier=config.anomaly_rtt_multiplier,
                retrans_pct_threshold=config.anomaly_retrans_pct,
            )
        )

        # Build focus filter
        focus: FocusFilter | None = None
        if config.focus_filter:
            focus = FocusFilter(config.focus_filter)

        # Parse all packets (needed for time window + metadata)
        packets, metadata = parser.parse_pcap_with_metadata(str(pcap_path))

        # Apply time window filter
        time_cutoff: float | None = None
        if config.time_window and packets:
            window_s = _parse_time_window(config.time_window)
            last_ts = packets[-1].timestamp
            time_cutoff = last_ts - window_s

        # Streaming analysis
        packets_processed = 0
        packets_skipped = 0
        prev_state: dict[FlowKey, str] = {}

        for pkt in packets:
            # Time window filter
            if time_cutoff is not None and pkt.timestamp < time_cutoff:
                packets_skipped += 1
                continue

            # Focus filter
            if focus is not None and not focus.matches(pkt):
                packets_skipped += 1
                continue

            # Track flow
            flow, direction = tracker.process_packet(pkt)
            packets_processed += 1

            # RTT estimation
            rtt_samples = rtt_estimator.on_packet(pkt, flow, direction)
            for sample in rtt_samples:
                anomaly_detector.on_rtt_sample(sample)

            # Retransmission detection
            retransmit_events = retransmit_detector.on_packet(
                pkt, flow, direction, rtt_estimator
            )
            for evt in retransmit_events:
                anomaly_detector.on_retransmission(evt, flow)

            # Flow state change detection
            old_state = prev_state.get(flow.key, "unknown")
            if flow.state != old_state:
                anomaly_detector.on_flow_state_change(flow)
                prev_state[flow.key] = flow.state

            # Zero window detection
            if pkt.window is not None and pkt.window == 0:
                anomaly_detector.on_zero_window(flow.key, pkt.timestamp, True)

        analysis_duration = time.monotonic() - t0

        all_flows = tracker.get_all_flows()
        all_rtt = rtt_estimator.get_all_samples()

        return AnalysisResult(
            metadata=metadata,
            config=config,
            flows=all_flows,
            rtt_samples=all_rtt,
            rtt_summary=_compute_rtt_summary(all_rtt),
            retransmission_events=retransmit_detector.get_all_events(),
            retransmission_summary=retransmit_detector.get_summary(),
            anomaly_events=anomaly_detector.get_all_events(),
            anomaly_summary=anomaly_detector.get_summary(),
            top_flows_by_retransmissions=_top_flows_by_retransmissions(all_flows),
            top_flows_by_rtt=_top_flows_by_rtt(all_rtt),
            analysis_duration_s=analysis_duration,
            packets_processed=packets_processed,
            packets_skipped=packets_skipped,
        )
