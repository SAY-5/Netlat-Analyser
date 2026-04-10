"""BPF filter builder for netlat.

Provides both the legacy build_bpf_filter() function and the new BPFBuilder class.
"""

from __future__ import annotations

import shutil
import subprocess


def build_bpf_filter(
    *,
    hosts: list[str] | None = None,
    ports: list[int] | None = None,
    protocols: list[str] | None = None,
    custom: str | None = None,
) -> str:
    """Build a BPF filter string from structured parameters.

    Args:
        hosts: IP addresses to filter on (src or dst).
        ports: Port numbers to filter on (src or dst).
        protocols: Protocol names (tcp, udp, icmp).
        custom: Raw BPF filter string to append.

    Returns:
        Combined BPF filter string.
    """
    clauses: list[str] = []

    if hosts:
        host_parts = " or ".join(f"host {h}" for h in hosts)
        clauses.append(f"({host_parts})")

    if ports:
        port_parts = " or ".join(f"port {p}" for p in ports)
        clauses.append(f"({port_parts})")

    if protocols:
        proto_parts = " or ".join(protocols)
        clauses.append(f"({proto_parts})")

    if custom:
        clauses.append(f"({custom})")

    return " and ".join(clauses) if clauses else ""


class BPFBuilder:
    """Fluent builder for BPF filter expressions."""

    @staticmethod
    def validate(filter_str: str) -> bool:
        """Validate a BPF filter string using tcpdump -d.

        Returns True if valid, False otherwise.
        Raises RuntimeError if tcpdump is not installed.
        """
        if not filter_str or not filter_str.strip():
            return True

        tcpdump = shutil.which("tcpdump")
        if tcpdump is None:
            raise RuntimeError("tcpdump is not installed or not in PATH")

        try:
            result = subprocess.run(
                [tcpdump, "-d", filter_str],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    @staticmethod
    def for_tcp(port: int | None = None) -> str:
        """Build a BPF filter for TCP traffic, optionally on a specific port."""
        if port is not None:
            return f"tcp port {port}"
        return "tcp"

    @staticmethod
    def for_host(host: str, port: int | None = None) -> str:
        """Build a BPF filter for a specific host, optionally on a specific port."""
        if port is not None:
            return f"host {host} and port {port}"
        return f"host {host}"

    @staticmethod
    def combine(*filters: str) -> str:
        """Combine multiple BPF filter expressions with AND logic.

        Empty/blank filters are skipped.
        """
        parts = [f.strip() for f in filters if f and f.strip()]
        if not parts:
            return ""
        if len(parts) == 1:
            return parts[0]
        return " and ".join(f"({p})" for p in parts)
