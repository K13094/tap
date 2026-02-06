"""
nozyme-tap WiFi fingerprint detector.
Detects drones by WiFi beacon/probe SSID patterns and MAC OUI prefixes.

This provides a third detection layer beyond RemoteID and DJI DroneID:

- RemoteID: Full telemetry (GPS, serial, operator). Requires compliance.
- DJI DroneID: GPS + serial. DJI-only, always on.
- WiFi Fingerprint: Presence + RSSI only. Works on ANY drone with WiFi radio.

Detection is based on:
1. SSID patterns: "DJI-MINI4PRO-726", "TELLO-XXXX", "ANAFI-XXXX", etc.
2. MAC OUI prefixes: Known drone manufacturer OUI ranges.

Performance:
- Positive matches cached by MAC (O(1) for repeat beacons from same drone)
- OUI check is O(1) dict lookup
- SSID patterns are pre-compiled regexes tested in priority order

Model extraction:
- DJI SSIDs parsed for specific model: "DJI-MINI4PRO-726" -> "DJI Mini 4 Pro"
- Controller SSIDs flagged: "DJI_RCN1_XXXX" -> "DJI Controller"
"""

import json
import re
import logging
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Optional, Dict, List, Tuple

logger = logging.getLogger(__name__)

# Regex to extract model code from DJI SSIDs
# Matches: "DJI-MINI4PRO-726", "DJI_MAVIC3_1234", "DJI AVATA2 ABC"
_DJI_SSID_RE = re.compile(r'^DJI[-_ ]([A-Z0-9]+?)(?:[-_ ]\w+)?$', re.IGNORECASE)


class WiFiFingerprint:
    """
    Matches WiFi beacon/probe frames against known drone signatures.
    Thread-safe: lock protects mutable caches and stats.
    """

    def __init__(self, models_path: str = None):
        self._lock = threading.Lock()

        # Pattern data (loaded once, read-only after init)
        self._ssid_patterns: List[Tuple[re.Pattern, str, str, bool]] = []
        self._oui_drone_set: set = set()
        self._oui_info: Dict[str, str] = {}
        self._dji_ssid_models: Dict[str, str] = {}

        # Positive match cache: MAC -> result dict (OrderedDict for O(1) LRU eviction)
        self._match_cache: OrderedDict = OrderedDict()
        self._match_cache_cap = 5000

        # Negative cache: MACs confirmed as non-drone (avoids repeat regex checks)
        self._negative_cache: set = set()
        self._negative_cache_cap = 10000

        self._stats = {
            "checked": 0,
            "ssid_matches": 0,
            "oui_matches": 0,
            "cache_hits": 0,
            "controller_matches": 0,
        }
        self._load(models_path)

    def _load(self, models_path: str = None):
        """Load patterns from drone_models.json."""
        if models_path is None:
            models_path = Path(__file__).parent / "drone_models.json"
        else:
            models_path = Path(models_path)

        if not models_path.exists():
            logger.warning(f"drone_models.json not found at {models_path}")
            return

        try:
            with open(models_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load drone_models.json: {e}")
            return

        # Load DJI SSID model map (for precise model extraction from SSID)
        self._dji_ssid_models = {
            k.upper(): v for k, v in data.get("dji_ssid_models", {}).items()
        }

        # Load SSID patterns (order matters — first match wins)
        for entry in data.get("ssid_patterns", []):
            pattern_str = entry.get("pattern")
            if not pattern_str:
                continue
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE)
                manufacturer = entry.get("manufacturer", "Unknown")
                model = entry.get("model", entry.get("model_hint", "Unknown"))
                is_controller = entry.get("is_controller", False)
                self._ssid_patterns.append((compiled, manufacturer, model, is_controller))
            except re.error as e:
                logger.warning(f"Invalid SSID pattern '{pattern_str}': {e}")

        # Load OUI map — only drone entries (not controllers)
        for oui, desc in data.get("oui_map", {}).items():
            oui_upper = oui.upper()
            self._oui_info[oui_upper] = desc
            if "(drone)" in desc.lower():
                self._oui_drone_set.add(oui_upper)

        logger.info(
            f"WiFi fingerprint loaded: {len(self._ssid_patterns)} SSID patterns, "
            f"{len(self._oui_drone_set)} drone OUIs, "
            f"{len(self._dji_ssid_models)} DJI SSID models"
        )

    def check(self, mac: str = None, ssid: str = None) -> Optional[dict]:
        """
        Check if a WiFi frame matches a known drone signature.

        Args:
            mac: Source MAC address (e.g., "60:60:1F:AA:BB:CC")
            ssid: SSID from beacon/probe frame

        Returns:
            Dict with match info if drone detected, None otherwise.
            Keys: manufacturer, model, designation, match_type, is_controller
        """
        mac_upper = mac.upper().replace("-", ":") if mac else ""

        with self._lock:
            self._stats["checked"] += 1

            # Fast path: cached positive match for this MAC
            if mac_upper and mac_upper in self._match_cache:
                self._stats["cache_hits"] += 1
                return self._match_cache[mac_upper]

            # Fast path: known non-drone MAC (skip regex entirely)
            if mac_upper and not ssid and mac_upper in self._negative_cache:
                self._stats["cache_hits"] += 1
                return None

        # --- Full check (pattern matching is read-only, no lock needed) ---

        # SSID match is more specific — check first
        if ssid:
            result = self._check_ssid(ssid)
            if result:
                with self._lock:
                    self._stats["ssid_matches"] += 1
                    if result.get("is_controller"):
                        self._stats["controller_matches"] += 1
                    if mac_upper:
                        self._cache_positive(mac_upper, result)
                return result

        # OUI match — catches drones with hidden/generic SSIDs
        if mac_upper:
            result = self._check_oui(mac_upper)
            if result:
                with self._lock:
                    self._stats["oui_matches"] += 1
                    self._cache_positive(mac_upper, result)
                return result

        # No match — cache as negative if we have both MAC and SSID
        # (only cache when we had full info to avoid false negatives
        #  from seeing a MAC in a probe-req before its beacon arrives)
        if mac_upper and ssid:
            with self._lock:
                self._cache_negative(mac_upper)

        return None

    def _check_ssid(self, ssid: str) -> Optional[dict]:
        """Check SSID against known drone patterns."""
        for compiled, manufacturer, model, is_controller in self._ssid_patterns:
            if not compiled.search(ssid):
                continue

            # Try to extract specific model from DJI SSID
            if manufacturer == "DJI" and not is_controller:
                extracted = self._extract_dji_model(ssid)
                if extracted:
                    model = extracted

            if is_controller:
                designation = f"{manufacturer} Controller"
            elif model and model not in ("Unknown", "generic"):
                designation = f"{manufacturer} {model}"
            else:
                designation = manufacturer

            return {
                "manufacturer": manufacturer,
                "model": model,
                "designation": designation,
                "match_type": "ssid",
                "ssid": ssid,
                "is_controller": is_controller,
            }

        return None

    def _check_oui(self, mac_upper: str) -> Optional[dict]:
        """Check MAC OUI against known drone manufacturers."""
        oui = mac_upper[:8]
        if oui not in self._oui_drone_set:
            return None

        desc = self._oui_info.get(oui, "Unknown")
        manufacturer = desc.split(" (")[0] if " (" in desc else desc
        return {
            "manufacturer": manufacturer,
            "model": "Unknown",
            "designation": f"{manufacturer} (WiFi)",
            "match_type": "oui",
            "oui": oui,
            "is_controller": False,
        }

    def _extract_dji_model(self, ssid: str) -> Optional[str]:
        """
        Extract specific DJI model from SSID.

        Examples:
            "DJI-MINI4PRO-726"  -> "Mini 4 Pro"
            "DJI_MAVIC3_1234"   -> "Mavic 3"
            "DJI-AVATA2-ABC"    -> "Avata 2"
            "DJI_RCN1_XXXX"    -> None (controller, handled separately)
        """
        m = _DJI_SSID_RE.match(ssid)
        if not m:
            return None

        raw_code = m.group(1).upper()

        # Direct lookup in model map
        if raw_code in self._dji_ssid_models:
            return self._dji_ssid_models[raw_code]

        # Try progressively shorter prefixes (handles codes with trailing chars)
        for length in range(len(raw_code) - 1, 2, -1):
            prefix = raw_code[:length]
            if prefix in self._dji_ssid_models:
                return self._dji_ssid_models[prefix]

        return None

    def _cache_positive(self, mac_upper: str, result: dict):
        """Cache a positive match with LRU eviction."""
        if mac_upper in self._match_cache:
            self._match_cache.move_to_end(mac_upper)
        elif len(self._match_cache) >= self._match_cache_cap:
            evict = self._match_cache_cap // 4
            for _ in range(evict):
                self._match_cache.popitem(last=False)
        self._match_cache[mac_upper] = result
        # Remove from negative cache if present
        self._negative_cache.discard(mac_upper)

    def _cache_negative(self, mac_upper: str):
        """Cache a confirmed non-drone MAC. Evicts oldest 25% when full."""
        self._negative_cache.add(mac_upper)
        if len(self._negative_cache) >= self._negative_cache_cap:
            evict = self._negative_cache_cap // 4
            to_remove = list(self._negative_cache)[:evict]
            for k in to_remove:
                self._negative_cache.discard(k)

    def cleanup_stale(self):
        """Periodic cleanup — clear negative cache to allow re-detection."""
        self._negative_cache.clear()

    @property
    def stats(self) -> dict:
        s = dict(self._stats)
        s["cached_drones"] = len(self._match_cache)
        s["cached_non_drones"] = len(self._negative_cache)
        return s
