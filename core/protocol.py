"""
Shared protocol definitions for nozyme tap <-> command center communication.
Message types, field names, and serialization helpers.
Used by both nozyme_tap (sender) and CC node_receiver (receiver).
"""

from datetime import datetime, timezone

# Protocol version for compatibility checking
PROTOCOL_VERSION = 1

# ZMQ topics
TOPIC_UAV = b"uav"
TOPIC_HEARTBEAT = b"heartbeat"
TOPIC_ALERT = b"alert"
TOPIC_FRAME = b"frame"

# Message types
MSG_UAV_REPORT = "uav_report"
MSG_TAP_HEARTBEAT = "tap_heartbeat"
MSG_TAP_ALERT = "tap_alert"
MSG_WIFI_FRAME = "wifi_frame"

# OpenDroneID message types (ASTM F3411)
DRONEID_BASIC_ID = 0
DRONEID_LOCATION = 1
DRONEID_AUTH = 2
DRONEID_SELF_ID = 3
DRONEID_SYSTEM = 4
DRONEID_OPERATOR_ID = 5
DRONEID_MESSAGE_PACK = 0xF

MESSAGE_TYPE_NAMES = {
    DRONEID_BASIC_ID: "BasicID",
    DRONEID_LOCATION: "Location",
    DRONEID_AUTH: "Auth",
    DRONEID_SELF_ID: "SelfID",
    DRONEID_SYSTEM: "System",
    DRONEID_OPERATOR_ID: "OperatorID",
    DRONEID_MESSAGE_PACK: "MessagePack",
}

# UA types (ASTM F3411 Table 1)
UA_TYPE_NONE = 0
UA_TYPE_AEROPLANE = 1
UA_TYPE_HELICOPTER_OR_MULTIROTOR = 2
UA_TYPE_GYROPLANE = 3
UA_TYPE_HYBRID_LIFT = 4
UA_TYPE_ORNITHOPTER = 5
UA_TYPE_GLIDER = 6
UA_TYPE_KITE = 7
UA_TYPE_FREE_BALLOON = 8
UA_TYPE_CAPTIVE_BALLOON = 9
UA_TYPE_AIRSHIP = 10
UA_TYPE_FREE_FALL_PARACHUTE = 11
UA_TYPE_ROCKET = 12
UA_TYPE_TETHERED = 13
UA_TYPE_GROUND_OBSTACLE = 14
UA_TYPE_OTHER = 15

UA_TYPE_NAMES = {
    UA_TYPE_NONE: "OTHER",
    UA_TYPE_AEROPLANE: "AEROPLANE",
    UA_TYPE_HELICOPTER_OR_MULTIROTOR: "HELICOPTER_OR_MULTIROTOR",
    UA_TYPE_GYROPLANE: "GYROPLANE",
    UA_TYPE_HYBRID_LIFT: "HYBRID_LIFT",
    UA_TYPE_ORNITHOPTER: "ORNITHOPTER",
    UA_TYPE_GLIDER: "GLIDER",
    UA_TYPE_KITE: "KITE",
    UA_TYPE_FREE_BALLOON: "FREE_BALLOON",
    UA_TYPE_CAPTIVE_BALLOON: "CAPTIVE_BALLOON",
    UA_TYPE_AIRSHIP: "AIRSHIP",
    UA_TYPE_FREE_FALL_PARACHUTE: "FREE_FALL_PARACHUTE",
    UA_TYPE_ROCKET: "ROCKET",
    UA_TYPE_TETHERED: "TETHERED_POWERED_AIRCRAFT",
    UA_TYPE_GROUND_OBSTACLE: "GROUND_OBSTACLE",
    UA_TYPE_OTHER: "OTHER",
}

# ID types
ID_TYPE_NONE = 0
ID_TYPE_SERIAL = 1
ID_TYPE_CAA_REGISTRATION = 2
ID_TYPE_UTM_ASSIGNED = 3
ID_TYPE_SPECIFIC_SESSION = 4

# Operational status
OP_STATUS_UNDECLARED = 0
OP_STATUS_GROUND = 1
OP_STATUS_AIRBORNE = 2
OP_STATUS_EMERGENCY = 3
OP_STATUS_REMOTE_ID_FAILURE = 4

OP_STATUS_NAMES = {
    OP_STATUS_UNDECLARED: "UNKNOWN",
    OP_STATUS_GROUND: "Ground",
    OP_STATUS_AIRBORNE: "Airborne",
    OP_STATUS_EMERGENCY: "Emergency",
    OP_STATUS_REMOTE_ID_FAILURE: "RemoteIDFailure",
}

# Height types
HEIGHT_ABOVE_TAKEOFF = 0
HEIGHT_AGL = 1

# Operator location types
OPERATOR_LOCATION_TAKEOFF = 0
OPERATOR_LOCATION_LIVE_GNSS = 1
OPERATOR_LOCATION_FIXED = 2


def utcnow_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def make_wifi_frame(
    tap_uuid: str,
    mac: str,
    rssi: float,
    channel: int,
    frame_type: str,
    raw_fields: dict,
) -> dict:
    """Build a wifi_frame message for the new fast-sensor pipeline.

    raw_fields contains all tshark-parsed layers — the node's FrameRouter
    inspects these to detect RemoteID, DJI DroneID, and WiFi fingerprint
    frames and routes them accordingly.
    """
    return {
        "type": MSG_WIFI_FRAME,
        "protocol_version": PROTOCOL_VERSION,
        "tap_uuid": tap_uuid,
        "timestamp": utcnow_iso(),
        "mac": mac,
        "rssi": rssi,
        "channel": channel,
        "frame_type": frame_type,
        "raw_fields": raw_fields,
    }


def make_uav_report(
    tap_uuid: str,
    mac: str,
    identifier: str,
    raw_fields: dict = None,
    **kwargs
) -> dict:
    """
    Build a UAV report message for ZMQ transport.

    Args:
        tap_uuid: UUID of the sending tap
        mac: Source MAC address from the WiFi frame
        identifier: Best available drone identifier (serial > operator_id > MAC hash)
        raw_fields: Complete dict of ALL tshark-parsed fields (stored as JSONB)
        **kwargs: Any UAV fields (latitude, longitude, speed, etc.)

    Returns:
        Dict ready for msgpack serialization
    """
    report = {
        "type": MSG_UAV_REPORT,
        "protocol_version": PROTOCOL_VERSION,
        "tap_uuid": tap_uuid,
        "timestamp": utcnow_iso(),
        "mac": mac,
        "identifier": identifier,
        "detection_source": kwargs.get("detection_source", "RemoteIdWiFi"),
        # Position
        "latitude": kwargs.get("latitude"),
        "longitude": kwargs.get("longitude"),
        "altitude_geodetic": kwargs.get("altitude_geodetic"),
        "altitude_pressure": kwargs.get("altitude_pressure"),
        "height": kwargs.get("height"),
        "height_type": kwargs.get("height_type"),
        # Movement
        "ground_track": kwargs.get("ground_track"),
        "speed": kwargs.get("speed"),
        "vertical_speed": kwargs.get("vertical_speed"),
        # Status
        "uav_type": kwargs.get("uav_type", "OTHER"),
        "operational_status": kwargs.get("operational_status"),
        # Signal
        "rssi": kwargs.get("rssi"),
        # Identity
        "id_serial": kwargs.get("id_serial"),
        "id_registration": kwargs.get("id_registration"),
        "id_utm": kwargs.get("id_utm"),
        "id_session": kwargs.get("id_session"),
        # Operator
        "operator_latitude": kwargs.get("operator_latitude"),
        "operator_longitude": kwargs.get("operator_longitude"),
        "operator_altitude": kwargs.get("operator_altitude"),
        "operator_id": kwargs.get("operator_id"),
        "operator_location_type": kwargs.get("operator_location_type"),
        # Accuracy
        "accuracy_horizontal": kwargs.get("accuracy_horizontal"),
        "accuracy_vertical": kwargs.get("accuracy_vertical"),
        "accuracy_barometer": kwargs.get("accuracy_barometer"),
        "accuracy_speed": kwargs.get("accuracy_speed"),
        # Message tracking
        "message_types_seen": kwargs.get("message_types_seen", []),
        # Self-ID
        "self_id_description": kwargs.get("self_id_description"),
        "self_id_type": kwargs.get("self_id_type"),
        # Auth
        "auth_type": kwargs.get("auth_type"),
        "auth_data": kwargs.get("auth_data"),
        # EU classification
        "category_eu": kwargs.get("category_eu"),
        "class_eu": kwargs.get("class_eu"),
        # Area
        "area_count": kwargs.get("area_count"),
        "area_radius": kwargs.get("area_radius"),
        "area_ceiling": kwargs.get("area_ceiling"),
        "area_floor": kwargs.get("area_floor"),
        # Spoof detection flags (set by spoof_detector)
        "spoof_flags": kwargs.get("spoof_flags", []),
        "trust_score": kwargs.get("trust_score", 100),
        # Raw fields for JSONB storage (everything tshark gave us)
        "raw_fields": raw_fields or {},
        # Designation (set by enrichment)
        "designation": kwargs.get("designation"),
        # WiFi SSID (from beacon/probe fingerprinting)
        "ssid": kwargs.get("ssid"),
    }
    return report


def make_heartbeat(
    tap_uuid: str,
    tap_name: str,
    interface: str,
    channel: int,
    cpu_load: float = 0.0,
    memory_used: int = 0,
    latitude: float = 0.0,
    longitude: float = 0.0,
    frames_total: int = 0,
    frames_parsed: int = 0,
    tshark_running: bool = True,
    cpu_percent: float = 0.0,
    temperature: float = None,
    disk_free: int = None,
    tap_uptime: float = 0.0,
    channels: list = None,
    capture_errors: int = 0,
    memory_percent: float = 0.0,
    disk_writes_total: int = None,
) -> dict:
    """Build a tap heartbeat message."""
    return {
        "type": MSG_TAP_HEARTBEAT,
        "protocol_version": PROTOCOL_VERSION,
        "tap_uuid": tap_uuid,
        "tap_name": tap_name,
        "timestamp": utcnow_iso(),
        "version": "0.2.0",
        "interface": interface,
        "channel": channel,
        "cpu_load": cpu_load,
        "cpu_percent": cpu_percent,
        "memory_used": memory_used,
        "memory_percent": memory_percent,
        "temperature": temperature,
        "disk_free": disk_free,
        "disk_writes_total": disk_writes_total,
        "latitude": latitude,
        "longitude": longitude,
        "frames_total": frames_total,
        "frames_parsed": frames_parsed,
        "tshark_running": tshark_running,
        "tap_uptime": round(tap_uptime, 1),
        "channels": channels or [],
        "capture_errors": capture_errors,
    }
