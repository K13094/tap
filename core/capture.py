"""
nozyme-tap tshark capture manager.
Spawns tshark as a subprocess, reads NDJSON from stdout line-by-line,
feeds each line to the parser.

Key design:
- Auto monitor mode setup (iw/ip or airmon-ng fallback)
- Channel hopping across configured channel list
- tshark runs as a long-lived subprocess
- stdout is read line-by-line (one JSON per line with -T ek)
- stderr is logged for diagnostics
- Process is restarted automatically on crash (by watchdog)
- Non-blocking readline with configurable timeout
"""

import os
import signal
import subprocess
import threading
import logging
import time
import shutil
from typing import Callable, Dict, Optional, List

logger = logging.getLogger(__name__)


def _is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def _run_cmd(cmd: List[str], timeout: int = 10) -> tuple:
    """Run a shell command, return (success, stdout, stderr).
    Strips 'sudo' prefix when already running as root to avoid pam log noise.
    """
    if _is_root() and cmd and cmd[0] == "sudo":
        cmd = cmd[1:]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(cmd)}")
        return False, "", "timeout"
    except FileNotFoundError:
        return False, "", f"{cmd[0]} not found"


def setup_monitor_mode(interface: str, channel: int = None) -> str:
    """
    Put a WiFi interface into monitor mode.

    Tries iw/ip first, falls back to airmon-ng.
    Returns the monitor interface name (may differ from input if airmon-ng
    renames it, e.g. wlan1 -> wlan1mon).

    Args:
        interface: WiFi interface (e.g. "wlan1")
        channel: Optional channel to set after enabling monitor mode

    Returns:
        Name of the monitor-mode interface
    """
    logger.info(f"Setting up monitor mode on {interface}")

    # Check if already in monitor mode
    ok, stdout, _ = _run_cmd(["iw", "dev", interface, "info"])
    if ok and "type monitor" in stdout:
        logger.info(f"{interface} already in monitor mode")
        if channel:
            set_channel(interface, channel)
        return interface

    # Method 1: iw/ip (preferred - no rename)
    has_iw = shutil.which("iw") is not None
    has_ip = shutil.which("ip") is not None

    if has_iw and has_ip:
        logger.info(f"Using iw/ip to enable monitor mode on {interface}")

        # Release interface from NetworkManager (don't kill the service)
        if shutil.which("nmcli"):
            _run_cmd(["sudo", "nmcli", "device", "set", interface, "managed", "no"])
        # Kill wpa_supplicant which interferes with monitor mode
        _run_cmd(["sudo", "systemctl", "stop", "wpa_supplicant"])

        # Down -> monitor -> up
        ok1, _, err1 = _run_cmd(["sudo", "ip", "link", "set", interface, "down"])
        ok2, _, err2 = _run_cmd(["sudo", "iw", "dev", interface, "set", "type", "monitor"])
        ok3, _, err3 = _run_cmd(["sudo", "ip", "link", "set", interface, "up"])

        if ok1 and ok2 and ok3:
            logger.info(f"{interface} is now in monitor mode")
            if channel:
                set_channel(interface, channel)
            return interface
        else:
            logger.warning(f"iw/ip method failed: {err1} {err2} {err3}")

    # Method 2: airmon-ng fallback
    if shutil.which("airmon-ng"):
        logger.info(f"Falling back to airmon-ng for {interface}")
        # Release interface from NM before airmon-ng (avoid airmon-ng check kill which stops NM)
        if shutil.which("nmcli"):
            _run_cmd(["sudo", "nmcli", "device", "set", interface, "managed", "no"])
        _run_cmd(["sudo", "systemctl", "stop", "wpa_supplicant"])
        ok, stdout, stderr = _run_cmd(["sudo", "airmon-ng", "start", interface])

        if ok:
            # airmon-ng may rename: wlan1 -> wlan1mon
            mon_iface = interface + "mon"
            # Check if renamed interface exists
            ok_check, out, _ = _run_cmd(["iw", "dev", mon_iface, "info"])
            if ok_check:
                logger.info(f"airmon-ng created {mon_iface}")
                if channel:
                    set_channel(mon_iface, channel)
                return mon_iface

            # Maybe it kept the same name
            ok_check, out, _ = _run_cmd(["iw", "dev", interface, "info"])
            if ok_check and "type monitor" in out:
                logger.info(f"airmon-ng: {interface} in monitor mode (no rename)")
                if channel:
                    set_channel(interface, channel)
                return interface

        logger.error(f"airmon-ng failed: {stderr}")

    raise RuntimeError(
        f"Cannot enable monitor mode on {interface}. "
        f"Install iw+ip or airmon-ng, and run as root/sudo."
    )


# --- Frequency-to-channel mapping ---

# 2.4 GHz: channels 1-14
_FREQ_24GHZ = {2412 + 5 * (ch - 1): ch for ch in range(1, 14)}
_FREQ_24GHZ[2484] = 14  # Channel 14 is a special case

# 5 GHz: channels 32-177 (freq = 5000 + 5*ch)
_FREQ_5GHZ = {5000 + 5 * ch: ch for ch in
              [36, 40, 44, 48, 52, 56, 60, 64,
               100, 104, 108, 112, 116, 120, 124, 128,
               132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177]}

# 6 GHz: channels 1-233 (freq = 5950 + 5*ch)
_FREQ_6GHZ = {5950 + 5 * ch: ch for ch in range(1, 234)}

_FREQ_TO_CHANNEL = {}
_FREQ_TO_CHANNEL.update(_FREQ_24GHZ)
_FREQ_TO_CHANNEL.update(_FREQ_5GHZ)
_FREQ_TO_CHANNEL.update(_FREQ_6GHZ)

# Reverse lookup: channel number -> frequency in MHz.
# Built in 6→5→2.4 order so 2.4 GHz wins for overlapping channel numbers (1-13).
_CHANNEL_TO_FREQ = {}
_CHANNEL_TO_FREQ.update({ch: freq for freq, ch in _FREQ_6GHZ.items()})
_CHANNEL_TO_FREQ.update({ch: freq for freq, ch in _FREQ_5GHZ.items()})
_CHANNEL_TO_FREQ.update({ch: freq for freq, ch in _FREQ_24GHZ.items()})


# --- Interface index cache (for netlink) ---
_ifindex_cache: Dict[str, int] = {}


def _get_ifindex(interface: str) -> Optional[int]:
    """Get interface index from sysfs, cached."""
    cached = _ifindex_cache.get(interface)
    if cached is not None:
        return cached
    try:
        with open(f"/sys/class/net/{interface}/ifindex") as f:
            idx = int(f.read().strip())
        if len(_ifindex_cache) >= 100:
            _ifindex_cache.clear()
        _ifindex_cache[interface] = idx
        return idx
    except (OSError, ValueError):
        return None


# --- Netlink channel control (zero-fork fast path) ---
_nl80211 = None
try:
    from nozyme_tap.system.netlink import NL80211Channel
    _nl80211 = NL80211Channel()
except Exception as _e:
    logger.warning(f"Netlink init failed, using subprocess fallback: {_e}")


def set_channel(interface: str, channel: int) -> bool:
    """Set the WiFi channel on a monitor-mode interface.

    Uses raw nl80211 netlink when available (<1ms), falls back to subprocess iw (~50ms).
    """
    if _nl80211:
        freq = _CHANNEL_TO_FREQ.get(channel)
        ifindex = _get_ifindex(interface)
        if freq and ifindex:
            ok = _nl80211.set_channel(ifindex, freq)
            if ok:
                logger.debug(f"Set {interface} to channel {channel} (netlink)")
                return True
            logger.debug(f"Netlink set_channel failed for ch {channel} freq={freq} ifindex={ifindex}, falling back to iw")
        else:
            logger.warning(f"Netlink lookup failed: channel={channel} freq={freq} ifindex={ifindex}")
    # Fallback: subprocess iw
    ok, _, err = _run_cmd(["sudo", "iw", "dev", interface, "set", "channel", str(channel)])
    if ok:
        logger.debug(f"Set {interface} to channel {channel} (iw)")
    else:
        logger.warning(f"Failed to set channel {channel}: {err}")
    return ok


def freq_to_channel(freq_mhz: int) -> Optional[int]:
    """Convert a radiotap frequency (MHz) to a WiFi channel number.

    Returns None if the frequency doesn't map to a known channel.
    """
    if freq_mhz is None:
        return None
    return _FREQ_TO_CHANNEL.get(freq_mhz)


# Band scan frequency constants
_SCAN_FREQ_5GHZ = 3    # Scan 5 GHz every Nth cycle
_SCAN_FREQ_6GHZ = 10   # Scan 6 GHz every Nth cycle

# WiFi NAN RemoteID mandatory discovery channel (ASTM F3411)
_NAN_DISCOVERY_CH = 6
_NAN_DWELL_MULTIPLIER = 2.0  # Extra dwell on channel 6 for NAN discovery

# Adaptive behavior thresholds
_FAST_RR_MAX = 3        # <= this many channels: fast round-robin
_BAND_PRIORITY_MAX = 8  # <= this many channels: band-prioritized
# >8 channels: heavy priority weighting


class ChannelHopper:
    """
    Band-aware channel hopper with scanning and tracking modes.

    Scanning mode (no active drones):
      - 2.4 GHz channels visited every cycle
      - 5 GHz channels visited every 3rd cycle
      - 6 GHz channels visited every 10th cycle

    Tracking mode (1+ active drones):
      - Active channels get extended dwell (base * multiplier)
      - Idle channels in the same band as active ones: normal scan
      - All idle channels: periodic scan every scan_interval seconds

    Adaptive behavior by total channel count:
      1 channel:  pin (no hopping)
      2-3:        fast round-robin with aggressive tracking dwell
      4-8:        band-prioritized scanning + tracking
      9+:         heavy priority weighting, secondary bands scanned rarely
    """

    def __init__(
        self,
        interface: str,
        channels_by_band: Dict[str, List[int]],
        dwell_ms: int = 250,
        active_dwell_multiplier: float = 3.0,
        activity_timeout_s: float = 30.0,
        idle_scan_interval_s: float = 5.0,
    ):
        self.interface = interface
        self.channels_by_band = {
            b: list(chs) for b, chs in channels_by_band.items() if chs
        }
        self.dwell_ms = dwell_ms
        self.active_dwell_multiplier = active_dwell_multiplier
        self.activity_timeout_s = activity_timeout_s
        self.idle_scan_interval_s = idle_scan_interval_s

        # Flat channel list and reverse lookup
        self.all_channels: List[int] = []
        self.channel_band: Dict[int, str] = {}
        for band in ("24ghz", "5ghz", "6ghz"):
            for ch in channels_by_band.get(band, []):
                self.all_channels.append(ch)
                self.channel_band[ch] = band

        self._total = len(self.all_channels)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._current_channel = 0
        self._lock = threading.Lock()
        self._channel_activity: Dict[int, float] = {}  # channel -> last_activity_time
        self._mode = "scanning"  # "scanning" or "tracking"
        self._stats = {"hops": 0, "errors": 0, "active_dwells": 0}

    def report_activity(self, channel: int):
        """Report drone activity on a channel."""
        if channel is None:
            return
        with self._lock:
            self._channel_activity[channel] = time.time()

    def _get_active_channels(self) -> List[int]:
        """Return channels with activity within the timeout window."""
        now = time.time()
        cutoff = now - self.activity_timeout_s
        with self._lock:
            active = [ch for ch, t in self._channel_activity.items() if t > cutoff]
        return active

    def _set_channel(self, ch: int) -> bool:
        """Set channel on the interface, update current_channel and stats."""
        ok = set_channel(self.interface, ch)
        with self._lock:
            if ok:
                self._current_channel = ch
                self._stats["hops"] += 1
            else:
                self._stats["errors"] += 1
        return ok

    def start(self):
        """Start channel hopping in background thread."""
        if self._total <= 1:
            if self.all_channels:
                set_channel(self.interface, self.all_channels[0])
                self._current_channel = self.all_channels[0]
            return

        self._running = True

        # Choose loop strategy based on channel count
        if self._total <= _FAST_RR_MAX:
            target = self._hop_loop_fast_rr
        else:
            target = self._hop_loop_band_priority

        self._thread = threading.Thread(
            target=target,
            daemon=True,
            name="channel-hopper"
        )
        self._thread.start()

        band_summary = " ".join(
            f"{b.replace('ghz', ' GHz')}={chs}"
            for b, chs in self.channels_by_band.items()
        )
        logger.info(
            f"Channel hopper started: {band_summary} "
            f"(dwell={self.dwell_ms}ms, active_mult={self.active_dwell_multiplier}x, "
            f"strategy={'fast_rr' if self._total <= _FAST_RR_MAX else 'band_priority'})"
        )

    def stop(self):
        """Stop hopping."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    # --- Fast round-robin (2-3 channels) ---

    def _hop_loop_fast_rr(self):
        """Simple round-robin with aggressive tracking dwell for small channel sets."""
        base_dwell = self.dwell_ms / 1000.0
        last_idle_scan = time.time()

        while self._running:
            try:
                active = self._get_active_channels()

                if not active:
                    # Scanning: plain round-robin
                    self._mode = "scanning"
                    for ch in self.all_channels:
                        if not self._running:
                            return
                        self._set_channel(ch)
                        time.sleep(base_dwell)
                else:
                    # Tracking: extended dwell on active, periodic idle scan
                    self._mode = "tracking"
                    for ch in active:
                        if not self._running:
                            return
                        self._set_channel(ch)
                        with self._lock:
                            self._stats["active_dwells"] += 1
                        time.sleep(base_dwell * self.active_dwell_multiplier)

                    now = time.time()
                    if (now - last_idle_scan) >= self.idle_scan_interval_s:
                        active_set = set(active)
                        for ch in self.all_channels:
                            if not self._running:
                                return
                            if ch not in active_set:
                                self._set_channel(ch)
                                time.sleep(base_dwell)
                        last_idle_scan = time.time()
            except Exception as e:
                logger.error(f"Channel hopper error (fast_rr): {e}", exc_info=True)
                time.sleep(1)  # Avoid tight loop on persistent errors

    # --- Band-priority hopping (4+ channels) ---

    def _hop_loop_band_priority(self):
        """Band-aware scanning with priority tiers and tracking mode."""
        base_dwell = self.dwell_ms / 1000.0
        cycle_count = 0
        last_idle_scan = time.time()

        # For 9+ channels, slow down secondary band scanning
        heavy_mode = self._total > _BAND_PRIORITY_MAX
        freq_5 = _SCAN_FREQ_5GHZ * (2 if heavy_mode else 1)
        freq_6 = _SCAN_FREQ_6GHZ * (2 if heavy_mode else 1)

        while self._running:
            try:
                active = self._get_active_channels()

                if not active:
                    # --- Scanning mode ---
                    self._mode = "scanning"

                    # 2.4 GHz: every cycle (channel 6 gets extra NAN discovery dwell)
                    for ch in self.channels_by_band.get("24ghz", []):
                        if not self._running:
                            return
                        self._set_channel(ch)
                        dwell = base_dwell * _NAN_DWELL_MULTIPLIER if ch == _NAN_DISCOVERY_CH else base_dwell
                        time.sleep(dwell)

                    # 5 GHz: every Nth cycle
                    if cycle_count % freq_5 == 0:
                        for ch in self.channels_by_band.get("5ghz", []):
                            if not self._running:
                                return
                            self._set_channel(ch)
                            time.sleep(base_dwell)

                    # 6 GHz: every Nth cycle
                    if cycle_count % freq_6 == 0:
                        for ch in self.channels_by_band.get("6ghz", []):
                            if not self._running:
                                return
                            self._set_channel(ch)
                            time.sleep(base_dwell)

                    cycle_count += 1
                else:
                    # --- Tracking mode ---
                    self._mode = "tracking"

                    # Extended dwell on all active channels
                    for ch in active:
                        if not self._running:
                            return
                        self._set_channel(ch)
                        with self._lock:
                            self._stats["active_dwells"] += 1
                        time.sleep(base_dwell * self.active_dwell_multiplier)

                    # Also scan idle channels in the same band(s) as active ones
                    active_set = set(active)
                    active_bands = {self.channel_band.get(ch) for ch in active}
                    for band in active_bands:
                        if band is None:
                            continue
                        for ch in self.channels_by_band.get(band, []):
                            if not self._running:
                                return
                            if ch not in active_set:
                                self._set_channel(ch)
                                time.sleep(base_dwell)

                    # Periodic scan of idle channels in other bands
                    now = time.time()
                    if (now - last_idle_scan) >= self.idle_scan_interval_s:
                        for ch in self.all_channels:
                            if not self._running:
                                return
                            if ch not in active_set and self.channel_band.get(ch) not in active_bands:
                                self._set_channel(ch)
                                time.sleep(base_dwell)
                        last_idle_scan = time.time()
            except Exception as e:
                logger.error(f"Channel hopper error (band_priority): {e}", exc_info=True)
                time.sleep(1)  # Avoid tight loop on persistent errors

    @property
    def current_channel(self) -> int:
        with self._lock:
            return self._current_channel

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def stats(self) -> dict:
        now = time.time()
        cutoff = now - self.activity_timeout_s
        with self._lock:
            s = dict(self._stats)
            s["current_channel"] = self._current_channel
            s["active_channels"] = sum(
                1 for t in self._channel_activity.values() if t > cutoff
            )
            s["mode"] = self._mode
        return s


class TsharkCapture:
    """
    Manages tshark subprocess for drone detection capture.

    Captures three layers of drone traffic:
    1. OpenDroneID (RemoteID): Standard ASTM F3411 broadcast
    2. DJI DroneID: Proprietary vendor IE in beacons (always-on)
    3. WiFi fingerprint: Beacon/probe frames matching drone SSID/OUI patterns

    Command:
        tshark -i <interface> -Y "<filter>" -T ek -j "<protocols>" -n -l

    Flags:
        -i: Interface in monitor mode
        -Y: Display filter (RemoteID + beacons + probes)
        -T ek: NDJSON output (one JSON per line, Elasticsearch format)
        -j: Protocol layers to include in output
        -n: No DNS resolution (major speedup)
        -l: Line-buffered stdout (real-time output)
    """

    # BPF capture filter: runs in kernel, drops non-management frames before
    # they reach userspace. "type mgt" passes beacons, probes, action frames, NAN.
    # This is the biggest performance win — kernel discards data/control frames.
    DEFAULT_CAPTURE_FILTER = "type mgt"

    # No display filter — forward ALL management frames to the node.
    # The node's FrameRouter handles classification (RemoteID, DJI, fingerprint).
    DEFAULT_FILTER = None
    # No -j flag: tshark 4.0.x EK mode breaks field expansion with -j
    DEFAULT_PROTOCOLS = None

    def __init__(
        self,
        interface: str,
        tshark_path: str = "/usr/bin/tshark",
        on_line: Callable[[str], None] = None,
        display_filter: str = None,
        capture_filter: str = None,
        protocols: str = None,
    ):
        """
        Args:
            interface: WiFi interface name (e.g., "wlan1mon")
            tshark_path: Path to tshark binary
            on_line: Callback for each NDJSON line from stdout
            display_filter: Wireshark display filter (-Y)
            capture_filter: BPF capture filter (-f), runs in kernel
            protocols: Comma-separated list of protocols to include in EK output
        """
        self.interface = interface
        self.tshark_path = tshark_path
        self.on_line = on_line
        self.display_filter = display_filter if display_filter is not None else self.DEFAULT_FILTER
        self.capture_filter = capture_filter or self.DEFAULT_CAPTURE_FILTER
        self.protocols = protocols or self.DEFAULT_PROTOCOLS

        self._process: Optional[subprocess.Popen] = None
        self._running = False
        self._stderr_thread: Optional[threading.Thread] = None
        self._stats_lock = threading.Lock()  # Protects _stats

        self._stats = {
            "lines_read": 0,
            "start_time": 0.0,
            "last_line_time": 0.0,
            "restarts": 0,
        }

    def build_command(self) -> list:
        """Build the tshark command line."""
        cmd = [
            self.tshark_path,
            "-i", self.interface,
            "-T", "ek",
            "-n",
            "-l",
        ]
        if self.capture_filter:
            cmd.extend(["-f", self.capture_filter])
        if self.display_filter:
            cmd.extend(["-Y", self.display_filter])
        if self.protocols:
            cmd.extend(["-j", self.protocols])
        return cmd

    def start(self):
        """Start the tshark subprocess."""
        cmd = self.build_command()
        logger.info(f"Starting tshark: {' '.join(cmd)}")

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,  # Line-buffered
                text=True,
                encoding='utf-8',
                errors='replace',
            )
        except FileNotFoundError:
            logger.error(f"tshark not found at {self.tshark_path}")
            raise
        except PermissionError:
            logger.error(f"Permission denied running tshark. Need sudo/capabilities?")
            raise

        try:
            self._running = True
            self._stats["start_time"] = time.time()
            self._stats["restarts"] += 1

            # Start stderr reader thread
            self._stderr_thread = threading.Thread(
                target=self._read_stderr,
                daemon=True,
                name="tshark-stderr"
            )
            self._stderr_thread.start()

            logger.info(f"tshark started, PID={self._process.pid}")
        except Exception:
            # Clean up the subprocess if post-creation setup fails
            try:
                self._process.kill()
                self._process.wait(timeout=3)
            except Exception:
                pass
            self._process = None
            self._running = False
            raise

    def read_lines(self):
        """
        Generator: yields NDJSON lines from tshark stdout.
        Blocks on readline, yields each line as it arrives.
        Exits when process terminates or stop() is called.
        """
        if not self._process or not self._process.stdout:
            return

        try:
            for line in self._process.stdout:
                if not self._running:
                    break
                line = line.strip()
                if not line:
                    continue

                # GIL-safe integer/float assignment — no lock needed on hot path
                self._stats["lines_read"] += 1
                self._stats["last_line_time"] = time.time()

                # Call the callback if set
                if self.on_line:
                    self.on_line(line)

                yield line

        except Exception as e:
            if self._running:
                logger.error(f"Error reading tshark stdout: {e}")

    def run_blocking(self):
        """
        Run capture in blocking mode: read lines and call on_line callback.
        Returns when tshark exits or stop() is called.
        """
        for line in self.read_lines():
            pass  # on_line callback handles each line

        # Check exit code
        if self._process:
            rc = self._process.poll()
            if rc is not None and rc != 0 and self._running:
                logger.error(f"tshark exited with code {rc}")

    def stop(self):
        """Stop the tshark subprocess and join stderr thread."""
        self._running = False
        if self._process:
            logger.info(f"Stopping tshark PID={self._process.pid}")
            try:
                # Use SIGINT (not SIGTERM) — tshark handles SIGINT for graceful
                # capture shutdown (flushes buffers, closes pcap cleanly).
                self._process.send_signal(signal.SIGINT)
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning("tshark did not stop on SIGINT, killing")
                    self._process.kill()
                    self._process.wait(timeout=2)
            except Exception as e:
                logger.error(f"Error stopping tshark: {e}")
            self._process = None

        # Join stderr reader thread
        if self._stderr_thread and self._stderr_thread.is_alive():
            self._stderr_thread.join(timeout=3)
            self._stderr_thread = None

    def _read_stderr(self):
        """Read tshark stderr in background thread for logging."""
        if not self._process or not self._process.stderr:
            return
        try:
            for line in self._process.stderr:
                line = line.strip()
                if not line:
                    continue
                # tshark prints useful info to stderr
                if "Capturing on" in line:
                    logger.info(f"tshark: {line}")
                elif "packets captured" in line or "packets received" in line:
                    logger.info(f"tshark: {line}")
                else:
                    logger.debug(f"tshark stderr: {line}")
        except Exception:
            pass  # Expected when process is killed

    @property
    def is_running(self) -> bool:
        """Check if tshark is running."""
        if not self._process:
            return False
        return self._process.poll() is None

    @property
    def exit_code(self) -> Optional[int]:
        """Get tshark exit code (None if still running)."""
        if not self._process:
            return None
        return self._process.poll()

    @property
    def pid(self) -> Optional[int]:
        """Get tshark PID."""
        if not self._process:
            return None
        return self._process.pid

    @property
    def seconds_since_last_line(self) -> float:
        """Seconds since last NDJSON line was read."""
        if self._stats["last_line_time"] == 0:
            return time.time() - self._stats["start_time"]
        return time.time() - self._stats["last_line_time"]

    @property
    def stats(self) -> dict:
        """Capture statistics. Thread-safe."""
        with self._stats_lock:
            return dict(self._stats)
