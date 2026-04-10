"""Tests for tcpdump capture and BPF filter builder."""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from netlat.capture.tcpdump import TcpdumpCapture
from netlat.util.bpf import BPFBuilder


# ---------------------------------------------------------------------------
# BPFBuilder tests
# ---------------------------------------------------------------------------


class TestBPFBuilder:
    def test_for_tcp_no_port(self) -> None:
        assert BPFBuilder.for_tcp() == "tcp"

    def test_for_tcp_with_port(self) -> None:
        assert BPFBuilder.for_tcp(port=443) == "tcp port 443"

    def test_for_host_no_port(self) -> None:
        assert BPFBuilder.for_host("10.0.0.1") == "host 10.0.0.1"

    def test_for_host_with_port(self) -> None:
        assert BPFBuilder.for_host("10.0.0.1", port=80) == "host 10.0.0.1 and port 80"

    def test_combine_single(self) -> None:
        assert BPFBuilder.combine("tcp") == "tcp"

    def test_combine_multiple(self) -> None:
        result = BPFBuilder.combine("tcp", "host 10.0.0.1")
        assert result == "(tcp) and (host 10.0.0.1)"

    def test_combine_skips_empty(self) -> None:
        result = BPFBuilder.combine("tcp", "", "  ", "host 10.0.0.1")
        assert result == "(tcp) and (host 10.0.0.1)"

    def test_combine_all_empty(self) -> None:
        assert BPFBuilder.combine("", "  ") == ""

    def test_validate_empty_is_valid(self) -> None:
        assert BPFBuilder.validate("") is True
        assert BPFBuilder.validate("   ") is True

    @mock.patch("netlat.util.bpf.shutil.which", return_value=None)
    def test_validate_no_tcpdump(self, _mock_which: mock.MagicMock) -> None:
        with pytest.raises(RuntimeError, match="tcpdump is not installed"):
            BPFBuilder.validate("tcp")

    @mock.patch("netlat.util.bpf.shutil.which", return_value="/usr/sbin/tcpdump")
    @mock.patch("netlat.util.bpf.subprocess.run")
    def test_validate_valid_filter(
        self, mock_run: mock.MagicMock, _mock_which: mock.MagicMock
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="(000) ret #65535\n", stderr=""
        )
        assert BPFBuilder.validate("tcp") is True

    @mock.patch("netlat.util.bpf.shutil.which", return_value="/usr/sbin/tcpdump")
    @mock.patch("netlat.util.bpf.subprocess.run")
    def test_validate_invalid_filter(
        self, mock_run: mock.MagicMock, _mock_which: mock.MagicMock
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="syntax error"
        )
        assert BPFBuilder.validate("not_a_valid_filter!!!") is False


# ---------------------------------------------------------------------------
# TcpdumpCapture tests
# ---------------------------------------------------------------------------


class TestTcpdumpCaptureBuildCommand:
    def test_build_command(self, tmp_path: Path) -> None:
        cap = TcpdumpCapture(
            interface="eth0",
            bpf_filter="tcp port 80",
            snaplen=128,
            output_dir=tmp_path,
            output_prefix="test",
            rotate_mb=50,
        )
        cmd = cap.build_command()

        assert cmd[0] == "tcpdump"
        assert "-i" in cmd
        assert cmd[cmd.index("-i") + 1] == "eth0"
        assert "-s" in cmd
        assert cmd[cmd.index("-s") + 1] == "128"
        assert "-C" in cmd
        assert cmd[cmd.index("-C") + 1] == "50"
        assert "--time-stamp-precision=micro" in cmd
        # BPF filter is last
        assert cmd[-1] == "tcp port 80"
        # Output file path
        w_idx = cmd.index("-w")
        output_path = cmd[w_idx + 1]
        assert "test_" in output_path
        assert output_path.endswith(".pcap")

    def test_build_command_with_rotation(self, tmp_path: Path) -> None:
        cap = TcpdumpCapture(
            output_dir=tmp_path,
            rotate_mb=200,
            rotate_seconds=300,
        )
        cmd = cap.build_command()

        assert "-C" in cmd
        assert cmd[cmd.index("-C") + 1] == "200"
        assert "-G" in cmd
        assert cmd[cmd.index("-G") + 1] == "300"

    def test_build_command_no_filter(self, tmp_path: Path) -> None:
        cap = TcpdumpCapture(output_dir=tmp_path, bpf_filter="")
        cmd = cap.build_command()
        # No trailing filter element beyond the --time-stamp-precision flag
        assert cmd[-1] == "--time-stamp-precision=micro"


class TestTcpdumpCapturePreflight:
    @mock.patch("netlat.capture.tcpdump.shutil.which", return_value=None)
    def test_preflight_no_tcpdump(
        self, _mock_which: mock.MagicMock, tmp_path: Path
    ) -> None:
        cap = TcpdumpCapture(output_dir=tmp_path)
        with pytest.raises(RuntimeError, match="tcpdump is not installed"):
            cap.preflight_check()

    @mock.patch("netlat.capture.tcpdump.os.access", return_value=True)
    @mock.patch("netlat.capture.tcpdump.os.geteuid", return_value=0)
    @mock.patch("netlat.capture.tcpdump.subprocess.run")
    @mock.patch("netlat.capture.tcpdump.shutil.which", return_value="/usr/sbin/tcpdump")
    def test_preflight_bad_filter(
        self,
        _mock_which: mock.MagicMock,
        mock_run: mock.MagicMock,
        _mock_geteuid: mock.MagicMock,
        _mock_access: mock.MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="syntax error"
        )
        cap = TcpdumpCapture(
            output_dir=tmp_path,
            bpf_filter="invalid_filter!!!",
            interface="any",  # skip interface check
        )
        with pytest.raises(RuntimeError, match="Invalid BPF filter"):
            cap.preflight_check()

    @mock.patch("netlat.capture.tcpdump.os.statvfs")
    @mock.patch("netlat.capture.tcpdump.os.access", return_value=True)
    @mock.patch("netlat.capture.tcpdump.os.geteuid", return_value=0)
    @mock.patch("netlat.capture.tcpdump.shutil.which", return_value="/usr/sbin/tcpdump")
    def test_preflight_pass_no_filter(
        self,
        _mock_which: mock.MagicMock,
        _mock_geteuid: mock.MagicMock,
        _mock_access: mock.MagicMock,
        mock_statvfs: mock.MagicMock,
        tmp_path: Path,
    ) -> None:
        # Mock statvfs to report plenty of space
        stat = mock.MagicMock()
        stat.f_bavail = 1_000_000
        stat.f_frsize = 4096
        mock_statvfs.return_value = stat

        cap = TcpdumpCapture(output_dir=tmp_path, interface="any")
        warnings = cap.preflight_check()
        assert isinstance(warnings, list)

    def test_preflight_missing_output_dir(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "does_not_exist"
        cap = TcpdumpCapture(output_dir=nonexistent)
        with mock.patch(
            "netlat.capture.tcpdump.shutil.which",
            return_value="/usr/sbin/tcpdump",
        ):
            with mock.patch("netlat.capture.tcpdump.os.geteuid", return_value=0):
                with pytest.raises(RuntimeError, match="does not exist"):
                    cap.preflight_check()


class TestTcpdumpCaptureLifecycle:
    def test_is_running_before_start(self, tmp_path: Path) -> None:
        cap = TcpdumpCapture(output_dir=tmp_path)
        assert cap.is_running is False

    def test_stop_without_start_raises(self, tmp_path: Path) -> None:
        cap = TcpdumpCapture(output_dir=tmp_path)
        with pytest.raises(RuntimeError, match="No capture process"):
            cap.stop()

    def test_wait_without_start_raises(self, tmp_path: Path) -> None:
        cap = TcpdumpCapture(output_dir=tmp_path)
        with pytest.raises(RuntimeError, match="No capture process"):
            cap.wait()

    @mock.patch("netlat.capture.tcpdump.subprocess.Popen")
    def test_start_and_stop(
        self, mock_popen: mock.MagicMock, tmp_path: Path
    ) -> None:
        mock_proc = mock.MagicMock()
        mock_proc.poll.return_value = None  # running
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        cap = TcpdumpCapture(output_dir=tmp_path)
        cap.start()
        assert cap.is_running is True

        path = cap.stop()
        mock_proc.send_signal.assert_called_once_with(signal.SIGTERM)
        assert str(path).endswith(".pcap")

    @mock.patch("netlat.capture.tcpdump.subprocess.Popen")
    def test_start_already_running_raises(
        self, mock_popen: mock.MagicMock, tmp_path: Path
    ) -> None:
        mock_proc = mock.MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        cap = TcpdumpCapture(output_dir=tmp_path)
        cap.start()
        with pytest.raises(RuntimeError, match="already running"):
            cap.start()

    @mock.patch("netlat.capture.tcpdump.subprocess.Popen")
    def test_stop_sigkill_fallback(
        self, mock_popen: mock.MagicMock, tmp_path: Path
    ) -> None:
        """When SIGTERM doesn't stop the process, SIGKILL is sent."""
        mock_proc = mock.MagicMock()
        mock_proc.poll.return_value = None
        # First wait (after SIGTERM) times out, second wait (after SIGKILL) succeeds
        mock_proc.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="tcpdump", timeout=5),
            0,
        ]
        mock_popen.return_value = mock_proc

        cap = TcpdumpCapture(output_dir=tmp_path)
        cap.start()
        cap.stop()

        calls = mock_proc.send_signal.call_args_list
        assert calls[0] == mock.call(signal.SIGTERM)
        assert calls[1] == mock.call(signal.SIGKILL)


# ---------------------------------------------------------------------------
# Live capture tests (require root)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.geteuid() != 0,
    reason="Live capture tests require root privileges",
)
class TestTcpdumpCaptureLive:
    def test_live_short_capture(self, tmp_path: Path) -> None:
        cap = TcpdumpCapture(
            interface="any",
            snaplen=96,
            output_dir=tmp_path,
            duration=3,
        )
        warnings = cap.preflight_check()
        cap.start()
        assert cap.is_running
        import time
        time.sleep(1)
        path = cap.stop()
        assert path.exists()
