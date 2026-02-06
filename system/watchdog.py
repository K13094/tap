"""
nozyme-tap self-healing watchdog.
Monitors tshark, transport, and pipeline health — auto-recovers on failure.

Recovery actions:
- tshark crash: Restart within 1 second
- Packet starvation (no frames for N seconds): Reset interface + restart
- WiFi interface down: ip link set up + reconfigure monitor mode
- Transport buffer growth: Log warning when buffer depth exceeds threshold
- Memory pressure: Exit process when memory exceeds threshold (systemd restarts)
"""

import os
import signal
import subprocess
import logging
import time
import threading
from typing import Optional, Callable

from nozyme_tap.system.health import get_system_health

logger = logging.getLogger(__name__)


class Watchdog:
    """
    Monitors the capture pipeline and auto-recovers on failure.
    Runs as a background thread alongside the main capture loop.
    """

    def __init__(
        self,
        capture,  # TsharkCapture instance
        interface: str = "wlan1mon",
        channel: int = 6,
        starvation_timeout_s: float = 30.0,
        restart_delay_s: float = 1.0,
        on_restart: Optional[Callable] = None,
        transport=None,  # ZmqTransport instance (optional)
        correlator=None,  # Correlator instance (optional)
        buffer_warn_threshold: int = 500,
        memory_percent_threshold: float = 90.0,
        shutdown_event: Optional[threading.Event] = None,
        check_interval_s: float = 2.0,
    ):
        """
        Args:
            capture: TsharkCapture instance to monitor
            interface: WiFi interface name
            channel: WiFi channel to pin to
            starvation_timeout_s: Seconds with no frames before reset
            restart_delay_s: Delay before restarting tshark
            on_restart: Callback when tshark is restarted
            transport: ZmqTransport instance for buffer monitoring
            correlator: Correlator instance for frame rate monitoring
            buffer_warn_threshold: Buffer depth that triggers warning
            memory_percent_threshold: Exit when memory exceeds this percent (systemd restarts)
            shutdown_event: Threading event for cooperative shutdown (fallback to os.kill if None)
            check_interval_s: Seconds between watchdog checks
        """
        self.capture = capture
        self.interface = interface
        self.channel = channel
        self.starvation_timeout_s = starvation_timeout_s
        self.restart_delay_s = restart_delay_s
        self.on_restart = on_restart
        self.transport = transport
        self.correlator = correlator
        self.buffer_warn_threshold = buffer_warn_threshold
        self.memory_percent_threshold = memory_percent_threshold
        self._shutdown_event = shutdown_event
        self._check_interval_s = check_interval_s

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._last_frame_count = 0
        self._last_tshark_lines = 0
        self._last_frame_check_time = 0.0
        self._stats = {
            "restarts": 0,
            "interface_resets": 0,
            "starvation_events": 0,
            "buffer_warnings": 0,
            "pipeline_stalls": 0,
            "memory_kills": 0,
        }

    def start(self):
        """Start the watchdog thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="watchdog"
        )
        self._thread.start()
        logger.info("Watchdog started")

    def stop(self):
        """Stop the watchdog."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _monitor_loop(self):
        """Main monitoring loop."""
        self._last_frame_check_time = time.time()

        while self._running:
            try:
                # --- Check 1: tshark process alive ---
                if not self.capture.is_running:
                    logger.warning("tshark is not running, restarting...")
                    self._restart_tshark()

                # --- Check 2: packet starvation ---
                elif self.capture.seconds_since_last_line > self.starvation_timeout_s:
                    logger.warning(
                        f"Packet starvation: no frames for "
                        f"{self.capture.seconds_since_last_line:.0f}s"
                    )
                    with self._lock:
                        self._stats["starvation_events"] += 1
                    self._reset_interface()
                    self._restart_tshark()

                # --- Check 3: transport buffer depth ---
                if self.transport:
                    buf_count = self.transport.buffered_count
                    if buf_count > self.buffer_warn_threshold:
                        with self._lock:
                            self._stats["buffer_warnings"] += 1
                        logger.warning(
                            f"Transport buffer high: {buf_count} messages "
                            f"({self.transport.buffered_bytes} bytes)"
                        )

                # --- Check 4: correlator frame throughput ---
                if self.correlator:
                    self._check_pipeline_throughput()

                # --- Check 5: memory pressure ---
                self._check_memory_pressure()

            except Exception as e:
                logger.error(f"Watchdog error: {e}")

            time.sleep(self._check_interval_s)

    def _check_pipeline_throughput(self):
        """Check that the correlator is still processing frames.
        Only flags a stall when tshark lines are advancing (>100 delta)
        but correlator frame count is stuck — distinguishes 'parser filtering
        non-drone frames' from 'truly stalled pipeline'.
        """
        now = time.time()
        try:
            current_count = self.correlator.stats.get("frames_processed", 0)
        except Exception:
            return

        elapsed = now - self._last_frame_check_time
        if elapsed < 10:
            # Too soon to measure, skip
            return

        # Track tshark line delta to distinguish filtering from stalling
        capture_stats = self.capture.stats
        tshark_lines = capture_stats.get("lines_read", 0)
        tshark_delta = tshark_lines - self._last_tshark_lines

        # Only flag stall when tshark is actively advancing (>100 new lines)
        # but correlator hasn't processed any new drone frames
        if (tshark_delta > 100
                and current_count == self._last_frame_count
                and elapsed > 30):
            with self._lock:
                self._stats["pipeline_stalls"] += 1
            logger.warning(
                f"Pipeline may be stalled: tshark advanced {tshark_delta} lines "
                f"but correlator stuck at {current_count} frames for {elapsed:.0f}s"
            )

        self._last_frame_count = current_count
        self._last_tshark_lines = tshark_lines
        self._last_frame_check_time = now

    def _check_memory_pressure(self):
        """Exit if memory usage exceeds threshold. systemd Restart=always will bring us back."""
        try:
            health = get_system_health()
            mem_pct = health.get("memory_percent", 0.0)
            if mem_pct > self.memory_percent_threshold:
                with self._lock:
                    self._stats["memory_kills"] += 1
                logger.critical(
                    f"Memory pressure: {mem_pct:.1f}% exceeds threshold "
                    f"{self.memory_percent_threshold}%. Exiting for systemd restart."
                )
                if self._shutdown_event:
                    self._shutdown_event.set()
                else:
                    os.kill(os.getpid(), signal.SIGTERM)
        except Exception as e:
            logger.debug(f"Memory check failed: {e}")

    def _restart_tshark(self):
        """Stop and restart tshark."""
        logger.info(f"Restarting tshark in {self.restart_delay_s}s...")

        # Stop existing process
        try:
            self.capture.stop()
        except Exception:
            pass

        time.sleep(self.restart_delay_s)

        # Start new process
        try:
            self.capture.start()
            with self._lock:
                self._stats["restarts"] += 1
            logger.info("tshark restarted successfully")

            if self.on_restart:
                self.on_restart()

        except Exception as e:
            logger.error(f"Failed to restart tshark: {e}")

    def _reset_interface(self):
        """Reset the WiFi interface to monitor mode on the correct channel."""
        logger.info(f"Resetting interface {self.interface} to channel {self.channel}")
        with self._lock:
            self._stats["interface_resets"] += 1

        is_root = os.geteuid() == 0
        commands = [
            ["ip", "link", "set", self.interface, "down"],
            ["iw", "dev", self.interface, "set", "type", "monitor"],
            ["ip", "link", "set", self.interface, "up"],
            ["iw", "dev", self.interface, "set", "channel", str(self.channel)],
        ]
        if not is_root:
            commands = [["sudo"] + cmd for cmd in commands]

        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    logger.warning(f"Command failed: {' '.join(cmd)} -> {result.stderr}")
            except subprocess.TimeoutExpired:
                logger.error(f"Command timed out: {' '.join(cmd)}")
            except FileNotFoundError:
                logger.error(f"Command not found: {cmd[0]}")

        logger.info(f"Interface {self.interface} reset complete")

    @property
    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
