"""
nozyme-tap system health reporting.
CPU, memory, temperature for heartbeat messages.
"""

import os
import logging
import time
from collections import deque

logger = logging.getLogger(__name__)


def get_system_health() -> dict:
    """
    Get system health metrics for tap heartbeat.

    Returns:
        Dict with: cpu_load, cpu_percent, memory_used, memory_total,
                    temperature, disk_free
    """
    result = {
        "cpu_load": 0.0,
        "cpu_percent": 0.0,
        "memory_used": 0,
        "memory_total": 0,
        "memory_percent": 0.0,
        "temperature": None,
        "disk_free": None,
        "disk_writes_total": None,
    }

    # CPU load (1-minute average)
    try:
        load = os.getloadavg()
        result["cpu_load"] = load[0]
        # Derive cpu_percent from load average / number of CPUs
        ncpu = os.cpu_count() or 1
        result["cpu_percent"] = round(min(load[0] / ncpu * 100.0, 100.0), 1)
    except (OSError, AttributeError):
        try:
            import psutil
            pct = psutil.cpu_percent(interval=0.1)
            result["cpu_load"] = pct / 100.0
            result["cpu_percent"] = pct
        except ImportError:
            pass

    # Memory
    try:
        import psutil
        mem = psutil.virtual_memory()
        result["memory_used"] = mem.used
        result["memory_total"] = mem.total
    except ImportError:
        # Fallback: read /proc/meminfo on Linux
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                mem_total = 0
                mem_available = 0
                found = 0
                for line in lines:
                    if line.startswith('MemTotal:'):
                        mem_total = int(line.split()[1]) * 1024  # kB to bytes
                        found += 1
                    elif line.startswith('MemAvailable:'):
                        mem_available = int(line.split()[1]) * 1024
                        found += 1
                    if found >= 2:
                        break
                result["memory_total"] = mem_total
                result["memory_used"] = mem_total - mem_available
        except Exception:
            pass

    # Memory percent
    if result["memory_total"] > 0:
        result["memory_percent"] = round(
            result["memory_used"] / result["memory_total"] * 100.0, 1
        )

    # CPU temperature (Raspberry Pi thermal_zone0)
    try:
        with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
            temp_millideg = int(f.read().strip())
            result["temperature"] = temp_millideg / 1000.0
    except Exception:
        pass

    # Disk free (root filesystem)
    try:
        import shutil
        usage = shutil.disk_usage("/")
        result["disk_free"] = usage.free
    except Exception:
        pass

    # Disk writes total (bytes written to SD card, from /proc/diskstats)
    # Tracks cumulative writes for SD card wear monitoring
    try:
        with open('/proc/diskstats', 'r') as f:
            total_sectors = 0
            for line in f:
                parts = line.split()
                if len(parts) >= 10:
                    dev_name = parts[2]
                    # Match mmcblk* (SD card) or sd* (USB/SATA), skip partitions
                    if (dev_name.startswith('mmcblk') and 'p' not in dev_name) or \
                       (dev_name.startswith('sd') and dev_name[-1].isalpha()):
                        # Field 10 (index 9) = sectors written
                        total_sectors += int(parts[9])
            if total_sectors > 0:
                result["disk_writes_total"] = total_sectors * 512  # sectors -> bytes
    except Exception:
        pass

    return result


class TapMetrics:
    """
    Aggregated tap metrics for observability.
    Collects stats from all subsystems (capture, pipeline, transport, correlator).
    Included in heartbeat payloads.
    """

    def __init__(self, max_samples: int = 100):
        self._frame_times: deque = deque(maxlen=max_samples)

    def record_frame(self):
        """Record a frame processing timestamp for rate calculation."""
        self._frame_times.append(time.time())

    @property
    def frames_per_second(self) -> float:
        """Calculate frames/sec from recent timestamps."""
        if len(self._frame_times) < 2:
            return 0.0
        newest = self._frame_times[-1]
        oldest = self._frame_times[0]
        dt = newest - oldest
        # Guard against clock jumps (NTP backward step or large forward jump)
        if dt <= 0 or dt > 3600:
            return 0.0
        return (len(self._frame_times) - 1) / dt

    def collect_all(
        self,
        capture_stats: dict = None,
        correlator_stats: dict = None,
        transport_stats: dict = None,
        pipeline_stats: dict = None,
    ) -> dict:
        """
        Collect all metrics into a single dict for heartbeat.

        Args:
            capture_stats: From TsharkCapture.stats
            correlator_stats: From Correlator.stats
            transport_stats: From ZmqTransport.stats
            pipeline_stats: From FrameQueue.stats + ProcessingThread.stats
        """
        health = get_system_health()
        metrics = {
            "system": health,
            "frames_per_second": round(self.frames_per_second, 1),
        }
        if capture_stats:
            metrics["capture"] = capture_stats
        if correlator_stats:
            metrics["correlator"] = correlator_stats
        if transport_stats:
            metrics["transport"] = transport_stats
        if pipeline_stats:
            metrics["pipeline"] = pipeline_stats
        return metrics
