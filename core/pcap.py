"""
Optional PCAP ring buffer recorder.

Runs dumpcap as a subprocess alongside tshark to record all WiFi frames
to disk for forensic replay.  Uses dumpcap's built-in ring buffer to
cap disk usage.

dumpcap runs independently of tshark — both read from the same monitor
mode interface (the kernel delivers copies to each reader).
"""

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class PcapRecorder:
    """Manage a dumpcap ring-buffer capture process."""

    def __init__(
        self,
        interface: str,
        pcap_path: str = "/var/lib/nozyme/pcap",
        filesize_kb: int = 10240,
        num_files: int = 10,
    ):
        self.interface = interface
        self.pcap_path = Path(pcap_path)
        self.filesize_kb = filesize_kb
        self.num_files = num_files
        self._proc: Optional[subprocess.Popen] = None

    def start(self):
        """Start the dumpcap ring buffer capture."""
        dumpcap = shutil.which("dumpcap")
        if not dumpcap:
            logger.error("dumpcap not found in PATH — PCAP recording disabled")
            return

        self.pcap_path.mkdir(parents=True, exist_ok=True)
        outfile = self.pcap_path / "capture.pcapng"

        cmd = [
            dumpcap,
            "-i", self.interface,
            "-w", str(outfile),
            "-b", f"filesize:{self.filesize_kb}",
            "-b", f"files:{self.num_files}",
            "-q",  # quiet — suppress packet count output
        ]

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info(
                "PCAP recorder started: %s (ring: %d x %dKB)",
                outfile, self.num_files, self.filesize_kb,
            )
        except OSError as e:
            logger.error("Failed to start dumpcap: %s", e)
            self._proc = None

    def stop(self):
        """Stop the dumpcap process."""
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
            logger.info("PCAP recorder stopped")
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=2)
            logger.warning("PCAP recorder killed (did not stop gracefully)")
        except Exception as e:
            logger.debug("Error stopping PCAP recorder: %s", e)
        finally:
            self._proc = None

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None
