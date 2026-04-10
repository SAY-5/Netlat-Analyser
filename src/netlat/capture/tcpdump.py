"""tcpdump-based packet capture for netlat.

Manages the lifecycle of a tcpdump subprocess: preflight checks,
command construction, start/stop/wait, and clean shutdown.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from netlat.util.bpf import BPFBuilder


class TcpdumpCapture:
    """Manage a tcpdump packet capture session."""

    def __init__(
        self,
        interface: str = "any",
        bpf_filter: str = "",
        snaplen: int = 96,
        output_dir: Path | str = Path("."),
        output_prefix: str = "netlat",
        rotate_mb: int = 100,
        rotate_seconds: int | None = None,
        duration: int = 60,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.output_dir = Path(output_dir)
        self.output_prefix = output_prefix
        self.rotate_mb = rotate_mb
        self.rotate_seconds = rotate_seconds
        self.duration = duration

        self._process: subprocess.Popen[bytes] | None = None
        self._output_path: Path | None = None

    def preflight_check(self) -> list[str]:
        """Run preflight checks and return a list of warnings.

        Raises RuntimeError for fatal issues.
        """
        warnings: list[str] = []

        # 1. tcpdump must exist
        tcpdump_path = shutil.which("tcpdump")
        if tcpdump_path is None:
            raise RuntimeError("tcpdump is not installed or not in PATH")

        # 2. Check permissions (non-root may lack capture rights)
        if os.geteuid() != 0:
            warnings.append(
                "Not running as root; tcpdump may fail without CAP_NET_RAW"
            )

        # 3. Interface check (basic validation)
        if self.interface != "any":
            try:
                result = subprocess.run(
                    ["tcpdump", "-D"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    available = result.stdout
                    if self.interface not in available:
                        raise RuntimeError(
                            f"Interface '{self.interface}' not found. "
                            f"Available: {available.strip()}"
                        )
            except subprocess.TimeoutExpired:
                warnings.append("Could not enumerate interfaces (timeout)")

        # 4. BPF filter validation
        if self.bpf_filter:
            try:
                result = subprocess.run(
                    ["tcpdump", "-d", self.bpf_filter],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode != 0:
                    raise RuntimeError(
                        f"Invalid BPF filter '{self.bpf_filter}': "
                        f"{result.stderr.strip()}"
                    )
            except subprocess.TimeoutExpired:
                warnings.append("BPF filter validation timed out")

        # 5. Output directory must exist and be writable
        if not self.output_dir.exists():
            raise RuntimeError(
                f"Output directory does not exist: {self.output_dir}"
            )
        if not os.access(self.output_dir, os.W_OK):
            raise RuntimeError(
                f"Output directory is not writable: {self.output_dir}"
            )

        # 6. Disk space check (warn if < 500 MB free)
        try:
            stat = os.statvfs(str(self.output_dir))
            free_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
            if free_mb < 500:
                warnings.append(
                    f"Low disk space: {free_mb:.0f} MB free in {self.output_dir}"
                )
        except OSError:
            warnings.append("Could not check disk space")

        return warnings

    def build_command(self) -> list[str]:
        """Build the tcpdump command line as a list of arguments."""
        ts = time.strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_prefix}_{ts}.pcap"
        self._output_path = self.output_dir / filename

        cmd: list[str] = [
            "tcpdump",
            "-i", self.interface,
            "-s", str(self.snaplen),
            "-w", str(self._output_path),
            "-C", str(self.rotate_mb),
        ]

        if self.rotate_seconds is not None:
            cmd.extend(["-G", str(self.rotate_seconds)])

        # Microsecond timestamp precision (if supported)
        cmd.append("--time-stamp-precision=micro")

        # BPF filter must be last
        if self.bpf_filter:
            cmd.append(self.bpf_filter)

        return cmd

    def start(self) -> None:
        """Start the tcpdump capture subprocess.

        Raises RuntimeError if already running or if tcpdump fails to start.
        """
        if self._process is not None and self._process.poll() is None:
            raise RuntimeError("Capture is already running")

        cmd = self.build_command()
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"Failed to start tcpdump: {exc}") from exc

    def stop(self) -> Path:
        """Stop the capture gracefully: SIGTERM, then SIGKILL after 5s.

        Returns the path to the capture file.
        Raises RuntimeError if not running.
        """
        if self._process is None:
            raise RuntimeError("No capture process to stop")

        if self._process.poll() is None:
            # Send SIGTERM for clean shutdown
            self._process.send_signal(signal.SIGTERM)
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if SIGTERM didn't work
                self._process.send_signal(signal.SIGKILL)
                self._process.wait(timeout=5)

        assert self._output_path is not None
        return self._output_path

    def wait(self) -> Path:
        """Wait for the capture process to finish (e.g., duration-limited).

        Returns the path to the capture file.
        Raises RuntimeError if not running.
        """
        if self._process is None:
            raise RuntimeError("No capture process to wait on")

        try:
            self._process.wait(timeout=self.duration + 10)
        except subprocess.TimeoutExpired:
            return self.stop()

        assert self._output_path is not None
        return self._output_path

    @property
    def is_running(self) -> bool:
        """Return True if the tcpdump process is currently running."""
        if self._process is None:
            return False
        return self._process.poll() is None
