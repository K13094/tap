# nozyme Protocol Specification v1

Interface contract between nozyme_tap and nozyme_node.
Both sides MUST read this before making transport/protocol changes.

## Architecture

```
[tap] --ZMQ PUB--> [node] --sqlite--> [command_center]
       msgpack          receiver/writer     Flask UI
```

## ZMQ Transport

- Pattern: PUB/SUB (tap=PUB connects, node=SUB binds)
- Serialization: msgpack (use_bin_type=True)
- Multipart: [topic_bytes, payload_bytes]
- Default port: 5590

## Topics

| Topic | Bytes | Sender | Content |
|-------|-------|--------|---------|
| uav | `b"uav"` | tap | UAV detection report |
| heartbeat | `b"heartbeat"` | tap | Tap health/status |
| alert | `b"alert"` | tap | Reserved for future |

## UAV Report Fields

All fields sent by tap in every uav_report message.
The node MUST accept unknown fields gracefully (ignore, don't crash).
The tap MUST send all fields even if None.

### Required (always present)

| Field | Type | Description |
|-------|------|-------------|
| type | str | Always "uav_report" |
| protocol_version | int | Currently 1 |
| tap_uuid | str | UUID of sending tap |
| timestamp | str | ISO 8601 UTC |
| mac | str | Source MAC (XX:XX:XX:XX:XX:XX) |
| identifier | str | Best ID (serial > reg > utm > operator > mac_hash) |
| detection_source | str | "RemoteIdWiFi", "DJIProprietaryDroneID", or "WiFiFingerprint" |

### Position

| Field | Type | Description |
|-------|------|-------------|
| latitude | float/null | WGS84 degrees |
| longitude | float/null | WGS84 degrees |
| altitude_geodetic | float/null | Meters above WGS84 ellipsoid |
| altitude_pressure | float/null | Meters pressure altitude |
| height | float/null | Meters above ground/takeoff |
| height_type | int/null | 0=above_takeoff, 1=AGL |

### Movement

| Field | Type | Description |
|-------|------|-------------|
| ground_track | float/null | Degrees (0-359) |
| speed | float/null | m/s horizontal |
| vertical_speed | float/null | m/s (positive=up) |

### Identity

| Field | Type | Description |
|-------|------|-------------|
| id_serial | str/null | ANSI/CTA-2063-A serial |
| id_registration | str/null | CAA registration |
| id_utm | str/null | UTM assigned UUID |
| id_session | str/null | Session ID |
| uav_type | str | UA type name (e.g. "HELICOPTER_OR_MULTIROTOR") |
| operational_status | str/null | "Ground", "Airborne", etc |

### Operator

| Field | Type | Description |
|-------|------|-------------|
| operator_latitude | float/null | WGS84 degrees |
| operator_longitude | float/null | WGS84 degrees |
| operator_altitude | float/null | Meters |
| operator_id | str/null | Operator ID string |
| operator_location_type | int/null | 0=takeoff, 1=live_gnss, 2=fixed |

### Signal

| Field | Type | Description |
|-------|------|-------------|
| rssi | int/null | dBm |
| ssid | str/null | WiFi SSID (from beacon/probe) |

### Accuracy

| Field | Type | Description |
|-------|------|-------------|
| accuracy_horizontal | float/null | Meters |
| accuracy_vertical | float/null | Meters |
| accuracy_barometer | float/null | Meters |
| accuracy_speed | float/null | m/s |

### Classification

| Field | Type | Description |
|-------|------|-------------|
| category_eu | str/null | EU category |
| class_eu | str/null | EU class |

### Area

| Field | Type | Description |
|-------|------|-------------|
| area_count | int/null | Number of UA in area |
| area_radius | float/null | Meters |
| area_ceiling | float/null | Meters |
| area_floor | float/null | Meters |

### Security

| Field | Type | Description |
|-------|------|-------------|
| spoof_flags | list[str] | e.g. ["teleportation", "impossible_speed"] |
| trust_score | int | 0-100 (100=fully trusted) |
| auth_type | int/null | ASTM auth type |
| auth_data | str/null | ASTM auth data |

### Enrichment

| Field | Type | Description |
|-------|------|-------------|
| designation | str/null | e.g. "DJI Mini 4 Pro" |
| message_types_seen | list[int] | ASTM message types received |
| self_id_description | str/null | Pilot-entered description |
| self_id_type | int/null | Self-ID type |

### Raw

| Field | Type | Description |
|-------|------|-------------|
| raw_fields | dict | ALL tshark-parsed fields (stored as JSONB) |

## Heartbeat Fields

| Field | Type | Description |
|-------|------|-------------|
| type | str | Always "tap_heartbeat" |
| protocol_version | int | Currently 1 |
| tap_uuid | str | UUID of sending tap (persisted across restarts) |
| tap_name | str | Human-readable name (from config, unique per tap) |
| timestamp | str | ISO 8601 UTC |
| version | str | Tap software version |
| interface | str | WiFi interface name |
| channel | int | Current WiFi channel |
| cpu_load | float | 1-min load average (0.0+) |
| cpu_percent | float | CPU usage as percentage (0.0-100.0) |
| memory_used | int | Bytes |
| memory_percent | float | Memory usage as percentage (0.0-100.0) |
| temperature | float/null | CPU temperature in Celsius (from thermal_zone0) |
| disk_free | int/null | Free disk space in bytes (root filesystem) |
| disk_writes_total | int/null | Cumulative bytes written to disk (SD card wear tracking) |
| latitude | float | Tap physical location |
| longitude | float | Tap physical location |
| frames_total | int | Total tshark lines read (all frame types) |
| frames_parsed | int | Drone frames processed by correlator |
| tshark_running | bool | tshark process alive |
| tap_uptime | float | Seconds since tap process started |
| channels | list[int] | All configured channels merged from band config (e.g. [1, 6, 11, 36, 149]) |
| capture_errors | int | Number of tshark restarts (crash recovery count) |

## Change Log

When either side changes the protocol, add an entry here.

| Date | Side | Change | Breaking? |
|------|------|--------|-----------|
| 2026-01-31 | tap | Added detection_source field (was hardcoded "RemoteIdWiFi") | No |
| 2026-01-31 | tap | Added ssid field | No |
| 2026-01-31 | tap | Added WiFiFingerprint detection_source value | No |
| 2026-01-31 | node | Synced protocol.py to accept detection_source + ssid | No |
| 2026-01-31 | tap | Added heartbeat fields: cpu_percent, temperature, disk_free, tap_uptime, channels, capture_errors | No |
| 2026-01-31 | tap | Fixed frames_total to report tshark line count (was incorrectly reporting drone-only count) | No |
| 2026-01-31 | tap | tap_uuid now persisted to /opt/nozyme/.tap_uuid fallback file | No |
| 2026-01-31 | tap | Config: channels now per-band (channels_24ghz/5ghz/6ghz), old "channels" key auto-migrated | No |
| 2026-01-31 | tap | Heartbeat channels field now sends merged all_channels from band config | No |
| 2026-01-31 | tap | Added heartbeat fields: memory_percent, disk_writes_total | No |
| 2026-01-31 | tap | Removed pcap_writer (tap is now pure sense-and-send, no local data storage) | No |
| 2026-01-31 | tap | Added Action frames (0x000d) to tshark display filter for ASTM F3411 RemoteID | No |
| 2026-01-31 | tap | ZMQ SNDHWM lowered to 1000 (configurable via zmq_hwm) to prevent memory blowup | No |
| 2026-01-31 | tap | Added memory pressure watchdog (exits at 90% threshold, systemd restarts) | No |
| 2026-01-31 | tap | Default log_level changed to WARNING for production deployment | No |

## Rules for Changes

1. Adding a new field: NOT breaking. Add to protocol.py on sender first, then update receiver.
2. Removing a field: BREAKING. Both sides must update simultaneously.
3. Changing field type: BREAKING. Coordinate.
4. New topic: NOT breaking. Receiver ignores unknown topics.
5. Protocol version bump: Only for breaking changes.
