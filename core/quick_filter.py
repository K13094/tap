"""
Fast frame classification for the new "tap = sensor" architecture.

Performs minimal classification of tshark -T ek NDJSON lines.
No deep field extraction — just enough to determine if the frame is
drone-related and what type it is.  The raw NDJSON line is forwarded
to the node for full parsing.

5 checks (short-circuit on first match):
  1. NAN + OpenDroneID  → "remoteid_nan"
  2. Action frame RemoteID → "remoteid_action"
  3. DJI vendor IE       → "dji_droneid"
  4. Beacon/Probe SSID   → "wifi_fingerprint"
  5. Beacon/Probe OUI    → "wifi_fingerprint"

Performance: a raw-string pre-filter rejects ~99% of lines (normal WiFi
beacons) WITHOUT JSON parsing.  Only lines containing a drone protocol
keyword, a known OUI prefix, or a drone manufacturer SSID substring get
parsed.
"""

import json
import logging
import math
import re
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import orjson
    _loads = orjson.loads
except ImportError:
    _loads = json.loads

# ── Module-level state (loaded once) ────────────────────────────────

_ssid_patterns = None     # List[(compiled_re, mfr, model, is_ctrl)]
_oui_drone_set = None     # set of "XX:XX:XX" OUI strings
_raw_triggers = None      # frozenset of raw-string triggers for pre-filter
_trigger_re = None        # compiled regex for single-pass pre-filter


def _ensure_patterns():
    """Load patterns and build the raw-string trigger set on first call."""
    global _ssid_patterns, _oui_drone_set, _raw_triggers, _trigger_re
    if _raw_triggers is not None:
        return

    try:
        from nozyme_tap.intel.wifi_fingerprint import WiFiFingerprint
        fp = WiFiFingerprint()
        _ssid_patterns = fp._ssid_patterns
        _oui_drone_set = fp._oui_drone_set
    except Exception as e:
        logger.error("Failed to load WiFi fingerprint patterns: %s", e)
        _ssid_patterns = []
        _oui_drone_set = set()

    # Build raw-string pre-filter triggers.
    # A tshark NDJSON line must contain at least one of these substrings
    # to possibly be a drone frame.  Lines that don't match skip JSON
    # parsing entirely.
    triggers = set()

    # Protocol-layer keywords (checks 1-3)
    triggers.update((
        "opendroneid", "open_drone_id", "dji_drone_id",
        "remoteid", "droneid",
    ))

    # Drone OUI prefixes in lowercase — they appear in MAC address strings
    # inside the JSON, e.g. "60:60:1f:aa:bb:cc"
    for oui in (_oui_drone_set or set()):
        triggers.add(oui.lower())

    # SSID manufacturer keywords — extract unique short substrings that
    # appear in drone SSIDs but rarely in normal WiFi.  These are the
    # literal prefixes from our regex patterns.
    _SSID_TRIGGERS = (
        # Protocol / generic RemoteID
        "RID-", "default-ssid", "remoteid",
        # DJI (including new models)
        "DJI", "Tello", "TELLO", "MAVIC", "PHANTOM", "INSPIRE",
        "MATRICE", "AGRAS", "FLYCART", "AVATA", "LITO", "FLIP",
        "FlightHub",
        # Parrot
        "ANAFI", "ANAFIThermal", "ANAFIUsa", "ANAFIAi",
        "Parrot", "DISCO", "Bebop", "SkyController",
        # Autel
        "Autel", "EVO", "Dragonfish", "Alpha", "Titan",
        # Skydio
        "Skydio", "X10D", "X10",
        # Yuneec
        "Yuneec", "YUNEEC", "Typhoon", "Mantis", "Breeze",
        "H520", "H850",
        # Other major manufacturers
        "FIMI", "PowerEgg", "PowerVision", "PowerEye",
        "Hubsan", "Holy", "Xiaomi",
        "BETAFPV", "BetaFPV", "Cetus", "Meteor",
        "iFlight", "Nazgul", "Chimera", "Cinewhoop",
        "Walksnail", "Caddx", "GEPRC", "CineLog", "MARK5", "DarkStar",
        "Diatone", "Flywoo", "Explorer", "HappyModel", "Mobula", "Crux",
        "SpeedyBee", "Eachine", "EMAX", "TinyHawk", "HDZero",
        "Fatshark", "TBS", "CROSSFIRE",
        # Budget consumer drones
        "Potensic", "Ruko", "Bwine", "SJRC", "MJX", "JJRC",
        "Syma", "Snaptain", "Contixo", "Force1", "FORCE1", "Ryze",
        "DEERC", "SIMREX", "Tomzon", "NEHEME", "ATTOP",
        "AOVO", "HOVERAir", "HOVER", "Loolinn",
        "Dragon Touch",
        # Enterprise / industrial
        "Wing", "EHang", "Matternet", "Zipline", "Joby",
        "Wisk", "Volansi", "Wingtra", "senseFly", "SENSEFLY", "Delair",
        "AgEagle", "eBee", "PrecisionHawk", "DroneDeploy",
        "Brinc", "Lemur", "Responder", "Guardian",
        "Teal", "GoldenEagle", "Freefly", "ASTRO", "ALTA",
        "ModalAI", "Sentinel", "VOXL",
        "InspiredFlight", "IF750", "IF800", "IF1200",
        "Draganfly", "Commander", "Quantix",
        "Flyability", "Elios", "SkyRanger", "FLIR", "SIRAS",
        "Percepto", "Airobotics", "Censys", "Sentaero",
        "Prodrone", "ACSL", "SOTEN", "Doosan",
        "MicroDrone", "Trinity", "Quantum",
        "Wingcopter", "ArduPilot", "PX4",
        # Military / law enforcement
        "BlackHornet", "RAVEN", "AeroVironment", "Switchblade",
        "InstantEye",
        # DIY / open-source
        "ESP-DRONE", "PixRacer", "QGroundControl", "MissionPlanner",
        # Additional manufacturers
        "Walkera", "Vitus", "ZeroTech", "Dobby",
        "Wingsland", "XDynamics", "Evolve",
        "Volatus", "InDro", "Herelink", "CubePilot",
        "Kespry", "Lancaster", "XAG",
        "Vantage", "Vesper", "ImpossibleAero",
        "HarrisAerial",
    )
    triggers.update(_SSID_TRIGGERS)

    _raw_triggers = frozenset(triggers)

    # Compile a single regex for single-pass pre-filtering (much faster than
    # iterating all triggers with `in` substring checks).
    escaped = [re.escape(t) for t in sorted(triggers, key=len, reverse=True)]
    _trigger_re = re.compile("|".join(escaped))

    logger.info(
        "Quick filter loaded: %d SSID patterns, %d drone OUIs, "
        "%d raw triggers",
        len(_ssid_patterns), len(_oui_drone_set), len(_raw_triggers),
    )


# ── Helpers for tshark EK value extraction ──────────────────────────

def _ek_val(obj: dict, *keys):
    """Get a scalar from tshark EK JSON (values wrapped in arrays)."""
    for key in keys:
        v = obj.get(key)
        if v is not None:
            return v[0] if isinstance(v, list) else v
    return None


def _ek_float(obj: dict, *keys) -> Optional[float]:
    v = _ek_val(obj, *keys)
    if v is None:
        return None
    try:
        f = float(v)
        return f if math.isfinite(f) else None
    except (ValueError, TypeError):
        return None


def _ek_str(obj: dict, *keys) -> Optional[str]:
    v = _ek_val(obj, *keys)
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


# ── SSID hex decode ─────────────────────────────────────────────────

def _decode_ssid(raw: str) -> str:
    """Decode hex-encoded SSID (tshark 4.0 format: '48:69:6c:74:6f:6e')."""
    if ':' in raw and all(len(b) == 2 for b in raw.split(':')):
        try:
            return bytes.fromhex(raw.replace(':', '')).decode('utf-8', errors='replace')
        except (ValueError, UnicodeDecodeError):
            pass
    return raw


# ── Public API ──────────────────────────────────────────────────────

def classify_frame(line: str) -> Optional[dict]:
    """
    Classify a single tshark NDJSON line.

    Returns {"mac", "rssi", "channel", "frame_type", "raw_json"} if the
    frame is drone-related, or None if it should be dropped.
    """
    _ensure_patterns()

    # ── Fast reject: skip index lines ───────────────────────────
    if not line or line[0] != '{' or line[1] == '"' and line[2] == 'i':
        # Catches empty, non-JSON, and '{"index"...' lines
        return None

    # ── Raw-string pre-filter: reject lines that can't be drones ──
    # This skips JSON parsing for ~99% of normal WiFi beacons.
    # Single compiled regex is much faster than iterating all triggers.
    if not _trigger_re.search(line):
        return None

    # ── JSON parse (only for lines that passed pre-filter) ──────
    try:
        data = _loads(line)
    except Exception:
        return None

    layers = data.get("layers")
    if not layers or not isinstance(layers, dict):
        return None

    # ── Extract 802.11 header fields (always available) ─────────
    wlan = layers.get("wlan", {})
    mac = _ek_str(wlan,
        "wlan_wlan_sa", "wlan_sa", "wlan.sa",
        "wlan_wlan_ta", "wlan_ta", "wlan.ta",
    )
    if not mac:
        return None

    rt = layers.get("radiotap", {})
    rssi = _ek_float(rt,
        "radiotap_radiotap_dbm_antsignal",
        "radiotap_dbm_antsignal",
        "radiotap.dbm_antsignal",
    )
    channel_freq = _ek_float(rt,
        "radiotap_radiotap_channel_freq",
        "radiotap_channel_freq",
        "radiotap.channel.freq",
    )
    channel = _FREQ_CHAN.get(int(channel_freq)) if channel_freq else None

    frame_type = None

    # ── Check 1: NAN + OpenDroneID ──────────────────────────────
    if ("opendroneid" in layers or "open_drone_id" in layers
            or "droneid" in layers or "remoteid" in layers):
        frame_type = "remoteid_nan"

    # ── Check 2: Action frame RemoteID (subtype 0x000d) ─────────
    if frame_type is None:
        subtype = _ek_val(wlan,
            "wlan_wlan_fc_type_subtype",
            "wlan_fc_type_subtype",
            "wlan.fc.type_subtype",
        )
        if subtype is not None:
            try:
                st = int(subtype, 0) if isinstance(subtype, str) else int(subtype)
            except (ValueError, TypeError):
                st = None
            if st == 0x000d:
                if ("opendroneid" in layers or "open_drone_id" in layers
                        or "droneid" in layers or "remoteid" in layers):
                    frame_type = "remoteid_action"

    # ── Check 3: DJI vendor IE ──────────────────────────────────
    if frame_type is None and "dji_drone_id" in layers:
        frame_type = "dji_droneid"

    # ── Checks 4 & 5: Beacon/probe SSID and OUI ────────────────
    if frame_type is None:
        wlan_mgt = layers.get("wlan_wlan_mgt") or layers.get("wlan_mgt") or {}
        ssid = _ek_str(wlan_mgt,
            "wlan_wlan_ssid", "wlan_mgt_wlan_mgt_ssid",
            "wlan_mgt_ssid", "wlan.mgt.ssid",
        )
        if not ssid:
            ssid = _ek_str(wlan,
                "wlan_wlan_ssid", "wlan_ssid", "wlan.ssid",
            )
        if ssid:
            ssid = _decode_ssid(ssid)

        # Check 4: SSID match
        if ssid and _ssid_patterns:
            for compiled, _mfr, _model, _is_ctrl in _ssid_patterns:
                if compiled.search(ssid):
                    frame_type = "wifi_fingerprint"
                    break

        # Check 5: OUI match
        if frame_type is None and _oui_drone_set:
            oui = mac.upper().replace("-", ":")[:8]
            if oui in _oui_drone_set:
                frame_type = "wifi_fingerprint"

    if frame_type is None:
        return None

    return {
        "mac": mac,
        "rssi": rssi,
        "channel": channel,
        "frame_type": frame_type,
        "raw_json": line,
        "layers": layers,
    }


# ── Freq → channel map (shared with capture.py for 2.4 + 5 + 6 GHz) ──

from nozyme_tap.core.capture import _FREQ_TO_CHANNEL as _FREQ_CHAN
