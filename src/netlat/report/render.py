"""Report rendering - human-readable and JSON output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import orjson

from netlat.analysis.pipeline import AnalysisResult


def _ts_iso(ts: float) -> str:
    """Convert UNIX timestamp to ISO 8601 string."""
    if ts <= 0:
        return "N/A"
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _fmt_duration(seconds: float) -> str:
    """Format seconds into a human-readable duration."""
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.1f}s"


def _bar(value: float, max_value: float, width: int = 30) -> str:
    """Create a simple ASCII bar."""
    if max_value <= 0:
        return ""
    filled = int((value / max_value) * width)
    filled = min(filled, width)
    return "#" * filled + "." * (width - filled)


class ReportRenderer:
    """Renders AnalysisResult into human-readable or JSON format."""

    def render_human(self, result: AnalysisResult) -> str:
        """Render a human-readable report with ASCII formatting."""
        lines: list[str] = []
        meta = result.metadata

        # Header
        lines.append("=" * 72)
        lines.append("  netlat - Network Latency Analysis Report")
        lines.append("=" * 72)
        lines.append("")

        # Capture metadata
        lines.append("--- Capture Summary ---")
        lines.append(f"  File:       {meta.file_path}")
        lines.append(f"  Size:       {meta.file_size_bytes:,} bytes")
        lines.append(f"  Packets:    {meta.packet_count:,}")
        lines.append(f"  Duration:   {_fmt_duration(meta.duration_seconds)}")
        lines.append(f"  Time range: {_ts_iso(meta.first_timestamp)} .. {_ts_iso(meta.last_timestamp)}")
        lines.append(f"  Flows:      {meta.unique_flows}")
        if meta.protocols:
            proto_str = ", ".join(f"{k}: {v}" for k, v in sorted(meta.protocols.items()))
            lines.append(f"  Protocols:  {proto_str}")
        lines.append("")

        # Analysis config
        lines.append("--- Analysis Config ---")
        lines.append(f"  Time window:   {result.config.time_window or 'entire capture'}")
        lines.append(f"  Focus filter:  {result.config.focus_filter or 'none'}")
        lines.append(f"  Processed:     {result.packets_processed:,} packets")
        lines.append(f"  Skipped:       {result.packets_skipped:,} packets")
        lines.append(f"  Analysis time: {result.analysis_duration_s:.3f}s")
        lines.append("")

        # RTT Summary
        rtt = result.rtt_summary
        lines.append("--- RTT Summary ---")
        if rtt["count"] > 0:
            lines.append(f"  Samples:  {rtt['count']:,}")
            lines.append(f"  Min:      {rtt['min_ms']:.2f} ms")
            lines.append(f"  Max:      {rtt['max_ms']:.2f} ms")
            lines.append(f"  Mean:     {rtt['mean_ms']:.2f} ms")
            lines.append(f"  Median:   {rtt['median_ms']:.2f} ms")
            lines.append(f"  P95:      {rtt['p95_ms']:.2f} ms")
            lines.append(f"  P99:      {rtt['p99_ms']:.2f} ms")
            if rtt.get("by_method"):
                methods = ", ".join(f"{k}: {v}" for k, v in rtt["by_method"].items())
                lines.append(f"  Methods:  {methods}")
        else:
            lines.append("  No RTT samples collected.")
        lines.append("")

        # Retransmission Summary
        retrans = result.retransmission_summary
        lines.append("--- Retransmissions ---")
        lines.append(f"  Total:          {retrans['total']}")
        lines.append(f"  Spurious:       {retrans.get('spurious', 0)}")
        lines.append(f"  Flows affected: {retrans.get('flows_affected', 0)}")
        by_class = retrans.get("by_classification", {})
        if by_class:
            for cls, cnt in sorted(by_class.items()):
                lines.append(f"    {cls}: {cnt}")
        lines.append("")

        # Anomaly Summary
        anomaly = result.anomaly_summary
        lines.append("--- Anomalies ---")
        lines.append(f"  Total: {anomaly['total']}")
        by_type = anomaly.get("by_type", {})
        if by_type:
            for atype, cnt in sorted(by_type.items()):
                lines.append(f"    {atype}: {cnt}")
        by_sev = anomaly.get("by_severity", {})
        if by_sev:
            lines.append("  By severity:")
            for sev, cnt in sorted(by_sev.items()):
                lines.append(f"    {sev}: {cnt}")
        lines.append("")

        # Top flows by retransmissions
        if result.top_flows_by_retransmissions:
            lines.append("--- Top Flows by Retransmissions ---")
            max_retrans = result.top_flows_by_retransmissions[0][1] if result.top_flows_by_retransmissions else 1
            for fk, count in result.top_flows_by_retransmissions[:10]:
                bar = _bar(count, max_retrans, 20)
                lines.append(f"  {fk.tuple_str:50s} {count:>5d}  [{bar}]")
            lines.append("")

        # Top flows by RTT
        if result.top_flows_by_rtt:
            lines.append("--- Top Flows by RTT ---")
            max_rtt = result.top_flows_by_rtt[0][1] if result.top_flows_by_rtt else 1.0
            for fk, rtt_val in result.top_flows_by_rtt[:10]:
                bar = _bar(rtt_val, max_rtt, 20)
                lines.append(f"  {fk.tuple_str:50s} {rtt_val:>8.2f}ms  [{bar}]")
            lines.append("")

        # Flow listing
        lines.append(f"--- Flows ({len(result.flows)} total) ---")
        for flow in result.flows[:20]:
            lines.append(
                f"  {flow.key.tuple_str:50s}  state={flow.state:<12s}  "
                f"pkts={flow.total_packets:<6d}  retrans={flow.retransmissions}"
            )
        if len(result.flows) > 20:
            lines.append(f"  ... and {len(result.flows) - 20} more flows")
        lines.append("")

        lines.append("=" * 72)
        return "\n".join(lines)

    def render_json(self, result: AnalysisResult) -> str:
        """Render the result as JSON with ISO 8601 timestamps."""
        data = {
            "metadata": {
                "file_path": result.metadata.file_path,
                "file_size_bytes": result.metadata.file_size_bytes,
                "packet_count": result.metadata.packet_count,
                "first_timestamp": _ts_iso(result.metadata.first_timestamp),
                "last_timestamp": _ts_iso(result.metadata.last_timestamp),
                "duration_seconds": result.metadata.duration_seconds,
                "unique_flows": result.metadata.unique_flows,
                "protocols": result.metadata.protocols,
            },
            "config": {
                "time_window": result.config.time_window,
                "focus_filter": result.config.focus_filter,
                "anomaly_rtt_multiplier": result.config.anomaly_rtt_multiplier,
                "anomaly_retrans_pct": result.config.anomaly_retrans_pct,
                "max_flows": result.config.max_flows,
                "flow_timeout_s": result.config.flow_timeout_s,
            },
            "rtt_summary": result.rtt_summary,
            "rtt_samples": [
                {
                    "timestamp": _ts_iso(s.timestamp),
                    "rtt_ms": s.rtt_ms,
                    "flow": s.flow_key.tuple_str,
                    "method": s.method,
                }
                for s in result.rtt_samples
            ],
            "retransmission_summary": result.retransmission_summary,
            "retransmission_events": [
                {
                    "timestamp": _ts_iso(e.timestamp),
                    "flow": e.flow_key.tuple_str,
                    "seq": e.seq,
                    "is_spurious": e.is_spurious,
                    "classification": e.classification,
                    "gap_ms": e.gap_ms,
                }
                for e in result.retransmission_events
            ],
            "anomaly_summary": result.anomaly_summary,
            "anomaly_events": [
                {
                    "timestamp": _ts_iso(e.timestamp),
                    "flow": e.flow_key.tuple_str,
                    "anomaly_type": e.anomaly_type,
                    "severity": e.severity,
                    "description": e.description,
                    "value": e.value,
                    "threshold": e.threshold,
                }
                for e in result.anomaly_events
            ],
            "top_flows_by_retransmissions": [
                {"flow": fk.tuple_str, "count": cnt}
                for fk, cnt in result.top_flows_by_retransmissions
            ],
            "top_flows_by_rtt": [
                {"flow": fk.tuple_str, "max_rtt_ms": rtt_val}
                for fk, rtt_val in result.top_flows_by_rtt
            ],
            "flows": [
                {
                    "key": f.key.tuple_str,
                    "state": f.state,
                    "total_packets": f.total_packets,
                    "total_bytes": f.total_bytes,
                    "retransmissions": f.retransmissions,
                    "zero_windows": f.zero_windows,
                    "resets": f.resets,
                    "handshake_rtt_ms": f.handshake_rtt_ms,
                }
                for f in result.flows
            ],
            "analysis_duration_s": result.analysis_duration_s,
            "packets_processed": result.packets_processed,
            "packets_skipped": result.packets_skipped,
        }

        return orjson.dumps(data, option=orjson.OPT_INDENT_2).decode()

    def render_to_file(
        self,
        result: AnalysisResult,
        path: Path,
        format: str = "both",
    ) -> None:
        """Write report to file(s).

        Args:
            result: The analysis result to render.
            path: Output file path (extension auto-appended for 'both').
            format: 'text', 'json', or 'both'.
        """
        path = Path(path)
        if format in ("text", "both"):
            text_path = path.with_suffix(".txt") if format == "both" else path
            text_path.write_text(self.render_human(result))
        if format in ("json", "both"):
            json_path = path.with_suffix(".json") if format == "both" else path
            json_path.write_text(self.render_json(result))
