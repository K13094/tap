"""
nozyme-tap configuration loader.
Reads tap_config.json, provides defaults for all settings.
Validates config values at load time for fail-fast behavior.
"""

import json
import os
import uuid
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Valid WiFi channels per band
VALID_CHANNELS_24GHZ = set(range(1, 15))     # 1-14
VALID_CHANNELS_5GHZ = {36, 40, 44, 48, 52, 56, 60, 64,
                       100, 104, 108, 112, 116, 120, 124, 128,
                       132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177}
VALID_CHANNELS_6GHZ = set(range(1, 234))     # 6GHz: channels 1-233 (UNII-5 through UNII-8)
VALID_CHANNELS = VALID_CHANNELS_24GHZ | VALID_CHANNELS_5GHZ | VALID_CHANNELS_6GHZ

BAND_NAMES = ("24ghz", "5ghz", "6ghz")
VALID_BY_BAND = {
    "24ghz": VALID_CHANNELS_24GHZ,
    "5ghz": VALID_CHANNELS_5GHZ,
    "6ghz": VALID_CHANNELS_6GHZ,
}


def classify_channel_band(ch: int) -> str:
    """Classify a channel number into a band name.

    For the legacy flat "channels" key: channels 1-14 are 2.4GHz,
    channels 32-177 are 5GHz. There is no unambiguous way to auto-classify
    6GHz channels from the legacy format (they overlap with 2.4GHz numbering),
    so channels outside 1-14 and 32-177 are dropped with a warning.
    """
    if ch in VALID_CHANNELS_24GHZ:
        return "24ghz"
    if ch in VALID_CHANNELS_5GHZ:
        return "5ghz"
    return None


DEFAULT_CONFIG = {
    "tap_uuid": None,
    "tap_name": "nozyme-tap",
    "node_host": "127.0.0.1",
    "node_port": 5590,
    "interface": "wlan1",
    "auto_monitor": True,
    "channels_24ghz": [1, 6, 11],
    "channels_5ghz": [],
    "channels_6ghz": [],
    "channel_dwell_ms": 350,
    "tshark_path": "/usr/bin/tshark",
    "latitude": 0.0,
    "longitude": 0.0,
    "heartbeat_interval_s": 10,
    "log_level": "INFO",
    "zmq_buffer_size": 1000,
    "zmq_hwm": 1000,
    "starvation_timeout_s": 30,
    "tshark_restart_delay_s": 1,
    "update_throttle_s": 0.5,
    "rssi_history_size": 50,
    "spoof_history_size": 20,
    "stale_cleanup_interval_s": 60,
    "watchdog_check_interval_s": 2,
    "memory_percent_threshold": 90.0,
    "pcap_enabled": False,
    "pcap_path": "/var/lib/nozyme/pcap",
    "pcap_ring_filesize_kb": 10240,
    "pcap_ring_files": 10,
}


class TapConfig:
    """Tap configuration with validation and auto-generated UUID persistence."""

    def __init__(self, config_path: str = None):
        self.config_path = Path(config_path) if config_path else None
        self.data: Dict[str, Any] = dict(DEFAULT_CONFIG)
        self._loaded_keys: set = set()  # Track which keys came from the file

    def load(self, path: str = None) -> 'TapConfig':
        """Load config from JSON file, merge with defaults, validate."""
        if path:
            self.config_path = Path(path)

        if self.config_path and self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    loaded = json.load(f)
                self._loaded_keys = set(loaded.keys())
                for key, value in loaded.items():
                    self.data[key] = value
                logger.info(f"Config loaded from {self.config_path}")
            except Exception as e:
                logger.error(f"Failed to load config: {e}, using defaults")
        else:
            logger.info("No config file found, using defaults")

        # Auto-generate UUID if missing, with fallback persistence
        if not self.data.get("tap_uuid"):
            # Try loading from dedicated UUID file first (survives config overwrites)
            self.data["tap_uuid"] = self._load_persisted_uuid()
        if not self.data.get("tap_uuid"):
            self.data["tap_uuid"] = str(uuid.uuid4())
            logger.info(f"Generated new tap UUID: {self.data['tap_uuid']}")
        # Always persist UUID to both config file and dedicated file
        self._save()
        self._save_persisted_uuid(self.data["tap_uuid"])

        # Validate
        self._validate()

        return self

    def _migrate_legacy_channels(self):
        """Migrate legacy flat 'channels' key into per-band lists."""
        legacy = self.data.get("channels")
        if legacy is None:
            return
        # Only migrate if no band-specific keys were explicitly provided
        has_band_keys = any(
            f"channels_{b}" in self._loaded_keys for b in BAND_NAMES
        )
        if has_band_keys:
            # Band keys take precedence; drop legacy key
            logger.info("Both legacy 'channels' and band keys found; using band keys")
            self.data.pop("channels", None)
            return

        logger.info(f"Migrating legacy channels={legacy} to per-band config")
        bands: Dict[str, List[int]] = {"24ghz": [], "5ghz": [], "6ghz": []}
        for ch in legacy:
            band = classify_channel_band(ch)
            if band:
                bands[band].append(ch)
            else:
                logger.warning(f"Legacy channel {ch} cannot be classified to a band, dropping")
        for band_name in BAND_NAMES:
            self.data[f"channels_{band_name}"] = bands[band_name]
        self.data.pop("channels", None)

    def _validate(self):
        """Validate config values, warn on issues."""
        # Port
        port = self.data.get("node_port", 5590)
        if not (1 <= port <= 65535):
            logger.warning(f"Invalid node_port {port}, using 5590")
            self.data["node_port"] = 5590

        # Band-based channel validation
        self._migrate_legacy_channels()
        total_valid = 0
        for band_name in BAND_NAMES:
            key = f"channels_{band_name}"
            channels = self.data.get(key, [])
            if not isinstance(channels, list):
                logger.warning(f"{key} is not a list, resetting to []")
                channels = []
            valid_set = VALID_BY_BAND[band_name]
            invalid = [ch for ch in channels if ch not in valid_set]
            if invalid:
                logger.warning(f"Invalid {band_name} channels removed: {invalid}")
                channels = [ch for ch in channels if ch in valid_set]
            self.data[key] = channels
            total_valid += len(channels)

        if total_valid == 0:
            logger.warning("No valid channels configured, defaulting to 2.4GHz channel 6")
            self.data["channels_24ghz"] = [6]

        # Timeouts (must be positive)
        for key in ["starvation_timeout_s", "tshark_restart_delay_s",
                     "heartbeat_interval_s", "channel_dwell_ms",
                     "update_throttle_s"]:
            val = self.data.get(key)
            if val is not None and val <= 0:
                default = DEFAULT_CONFIG.get(key, 1)
                logger.warning(f"Invalid {key}={val}, using {default}")
                self.data[key] = default

        # File paths (warn if not found, don't block)
        for key in ["tshark_path"]:
            path = self.data.get(key, "")
            if path and not Path(path).exists():
                # Also check PATH
                if not shutil.which(Path(path).name):
                    logger.warning(f"{key}={path} not found (may be OK if not needed yet)")

        # PCAP ring buffer validation
        if self.data.get("pcap_enabled"):
            pcap_path = Path(self.data.get("pcap_path", "/var/lib/nozyme/pcap"))
            try:
                pcap_path.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                logger.warning(f"Cannot create pcap_path {pcap_path}: {e}")
        for key in ("pcap_ring_filesize_kb", "pcap_ring_files"):
            val = self.data.get(key)
            if val is not None and val <= 0:
                default = DEFAULT_CONFIG[key]
                logger.warning(f"Invalid {key}={val}, using {default}")
                self.data[key] = default

    # Fallback UUID file locations (checked in order)
    _UUID_PATHS = [
        Path("/home/tap/.tap_uuid"),
        Path("/var/lib/nozyme/tap_uuid"),
        Path.home() / ".nozyme_tap_uuid",
    ]

    def _load_persisted_uuid(self) -> str:
        """Try to load tap_uuid from a dedicated persistence file."""
        for path in self._UUID_PATHS:
            try:
                if path.exists():
                    uid = path.read_text().strip()
                    if uid:
                        logger.info(f"Loaded tap UUID from {path}")
                        return uid
            except Exception:
                continue
        return None

    def _save_persisted_uuid(self, uid: str):
        """Save tap_uuid to the first writable persistence location.
        Uses atomic write (temp + rename) to survive power loss.
        """
        for path in self._UUID_PATHS:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                self._atomic_write(path, uid + "\n")
                logger.debug(f"Persisted tap UUID to {path}")
                return
            except Exception:
                continue
        logger.warning("Could not persist tap UUID to any fallback location")

    def _save(self):
        """Persist config back to file (to save auto-generated UUID).
        Uses atomic write (temp + rename) to survive power loss.
        """
        if not self.config_path:
            return
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            content = json.dumps(self.data, indent=4)
            self._atomic_write(self.config_path, content)
            logger.info(f"Config saved to {self.config_path}")
        except Exception as e:
            logger.warning(f"Could not save config: {e}")

    @staticmethod
    def _atomic_write(path: Path, content: str):
        """Write content to path atomically via temp file + rename.
        Survives power loss — either old or new content, never partial.
        """
        parent = path.parent
        fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".tmp_", suffix=".nozyme")
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp_path, str(path))
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def __getattr__(self, name):
        if name in ('data', 'config_path') or name.startswith('_'):
            return super().__getattribute__(name)
        return self.data.get(name)

    def get(self, key, default=None):
        return self.data.get(key, default)

    @property
    def channels_by_band(self) -> Dict[str, List[int]]:
        """Return channel lists organized by band."""
        return {
            band: self.data.get(f"channels_{band}", [])
            for band in BAND_NAMES
        }

    @property
    def all_channels(self) -> List[int]:
        """Return flat list of all configured channels across all bands."""
        result = []
        for band in BAND_NAMES:
            result.extend(self.data.get(f"channels_{band}", []))
        return result
