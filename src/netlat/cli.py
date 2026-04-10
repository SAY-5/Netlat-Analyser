"""CLI entry point for netlat."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from netlat import __version__
from netlat.util.logging import configure_logging

app = typer.Typer(
    name="netlat",
    help="pcap latency analyzer",
    add_completion=False,
)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"netlat {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(  # noqa: UP007
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """netlat - pcap latency analyzer."""
    configure_logging()


@app.command()
def capture(
    iface: str = typer.Option("any", "--iface", "-i", help="Network interface to capture on."),
    filter: Optional[str] = typer.Option(  # noqa: UP007
        None, "--filter", "-f", help="BPF filter expression."
    ),
    duration: int = typer.Option(60, "--duration", "-d", help="Capture duration in seconds."),
    snaplen: int = typer.Option(65535, "--snaplen", "-s", help="Snap length in bytes."),
    output: Path = typer.Option(
        Path("capture.pcap"), "--output", "-o", help="Output pcap file path."
    ),
    rotate_mb: Optional[int] = typer.Option(  # noqa: UP007
        None, "--rotate-mb", help="Rotate file after N megabytes."
    ),
    rotate_seconds: Optional[int] = typer.Option(  # noqa: UP007
        None, "--rotate-seconds", help="Rotate file after N seconds."
    ),
) -> None:
    """Capture packets from a network interface."""
    typer.echo(f"[stub] capture on {iface} for {duration}s -> {output}")
    raise typer.Exit(code=0)


@app.command()
def analyze(
    pcap: Path = typer.Option(..., "--pcap", "-p", help="Path to pcap file to analyze."),
    time_window: Optional[str] = typer.Option(  # noqa: UP007
        None, "--time-window", "-w", help="Time window (e.g. '10s', '1m', '5m'). Default: entire file."
    ),
    focus: Optional[str] = typer.Option(  # noqa: UP007
        None, "--focus", help="Focus filter: IP, CIDR, :port, or IP:port."
    ),
    anomaly_rtt_multiplier: float = typer.Option(
        3.0,
        "--anomaly-rtt-multiplier",
        help="RTT anomaly threshold as multiplier of median.",
    ),
    anomaly_retrans_pct: float = typer.Option(
        5.0,
        "--anomaly-retrans-pct",
        help="Retransmission percentage anomaly threshold.",
    ),
    format: str = typer.Option(
        "text", "--format", "-F", help="Output format: text, json."
    ),
    output: Optional[Path] = typer.Option(  # noqa: UP007
        None, "--output", "-o", help="Output file (default: stdout)."
    ),
) -> None:
    """Analyze a pcap file for latency and packet issues."""
    from netlat.analysis.pipeline import AnalysisConfig, AnalysisPipeline
    from netlat.report.render import ReportRenderer

    if not pcap.exists():
        typer.echo(f"Error: pcap file not found: {pcap}", err=True)
        raise typer.Exit(code=1)

    config = AnalysisConfig(
        time_window=time_window,
        focus_filter=focus,
        anomaly_rtt_multiplier=anomaly_rtt_multiplier,
        anomaly_retrans_pct=anomaly_retrans_pct,
    )

    pipeline = AnalysisPipeline(config=config)
    result = pipeline.analyze_pcap(pcap)

    renderer = ReportRenderer()

    if format == "json":
        out_text = renderer.render_json(result)
    else:
        out_text = renderer.render_human(result)

    if output:
        output.write_text(out_text)
        typer.echo(f"Output written to {output}")
    else:
        typer.echo(out_text)


@app.command()
def serve(
    port: int = typer.Option(9090, "--port", help="Prometheus metrics port."),
    pcap: Optional[Path] = typer.Option(  # noqa: UP007
        None, "--pcap", "-p", help="Path to pcap file to serve metrics for."
    ),
) -> None:
    """Serve Prometheus metrics from a pcap analysis."""
    from netlat.analysis.pipeline import AnalysisConfig, AnalysisPipeline
    from netlat.export.prometheus import MetricsServer

    if pcap is None:
        typer.echo("Error: --pcap is required for serve command.", err=True)
        raise typer.Exit(code=1)

    if not pcap.exists():
        typer.echo(f"Error: pcap file not found: {pcap}", err=True)
        raise typer.Exit(code=1)

    pipeline = AnalysisPipeline(config=AnalysisConfig())
    result = pipeline.analyze_pcap(pcap)

    server = MetricsServer(port=port)
    server.update(result)

    typer.echo(f"Serving Prometheus metrics on :{port}")
    typer.echo("Press Ctrl+C to stop.")
    server.start()

    # Block until interrupted
    import time

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        typer.echo("\nStopping.")


if __name__ == "__main__":
    app()
