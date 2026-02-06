"""
nozyme-tap entry point.
Usage: python -m nozyme_tap [--config tap_config.json] [--stdout] [--interface wlan1mon]

Fast sensor pipeline:
  tshark → classify_frame (5 checks) → wifi_frame → ZMQ to node
  (parallel: watchdog monitors tshark health, channel hopper hops)
"""

import sys
import json
import signal
import logging
import argparse
import time
import threading

from nozyme_tap.system.config import TapConfig
from nozyme_tap.core.capture import TsharkCapture, setup_monitor_mode, ChannelHopper, freq_to_channel
from nozyme_tap.core.protocol import make_heartbeat, make_wifi_frame
from nozyme_tap.core.quick_filter import classify_frame
from nozyme_tap.system.health import get_system_health

try:
    import orjson
    _loads = orjson.loads
except ImportError:
    _loads = json.loads

logger = logging.getLogger("nozyme_tap")

# Global state for signal handler
_shutdown = threading.Event()
_capture = None


def setup_logging(level: str = "INFO"):
    """Configure logging."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    global _capture
    logger.info("Shutting down...")
    _shutdown.set()
    if _capture:
        _capture.stop()


def main():
    global _capture

    parser = argparse.ArgumentParser(
        description="nozyme-tap: WiFi drone detection sensor"
    )
    parser.add_argument(
        "--config", "-c",
        default="tap_config.json",
        help="Path to tap_config.json (default: tap_config.json)"
    )
    parser.add_argument(
        "--interface", "-i",
        help="Override WiFi interface (e.g., wlan1mon)"
    )
    parser.add_argument(
        "--stdout", "-s",
        action="store_true",
        help="Print classified frames to stdout as JSON (testing mode)"
    )
    parser.add_argument(
        "--no-zmq",
        action="store_true",
        help="Disable ZMQ transport (stdout only)"
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level override"
    )
    args = parser.parse_args()

    # Load config
    config = TapConfig(args.config).load()
    log_level = args.log_level or config.get("log_level", "INFO")
    setup_logging(log_level)

    _start_time = time.time()
    logger.info("nozyme-tap v0.2.0 starting (fast sensor mode)")
    logger.info(f"Config: {config.config_path}")
    logger.info(f"Tap UUID: {config.tap_uuid}")

    # Override interface from CLI
    interface = args.interface or config.interface
    logger.info(f"Interface: {interface}")
    logger.info(f"Node: {config.node_host}:{config.node_port}")

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ---- Monitor mode setup ----

    channels_by_band = config.channels_by_band
    all_channels = config.all_channels
    channel_dwell_ms = config.get("channel_dwell_ms", 250)
    auto_monitor = config.get("auto_monitor", True)

    if auto_monitor:
        try:
            first_channel = all_channels[0] if all_channels else None
            interface = setup_monitor_mode(interface, channel=first_channel)
            logger.info(f"Monitor mode active on {interface}")
        except RuntimeError as e:
            logger.error(f"Monitor mode setup failed: {e}")
            logger.error("Run as root/sudo or set auto_monitor=false and configure manually")
            sys.exit(1)
    else:
        logger.info("auto_monitor disabled, assuming interface is already in monitor mode")

    band_info = " ".join(
        f"{band.replace('ghz', ' GHz')}={chs}"
        for band, chs in channels_by_band.items()
    )
    logger.info(f"Channels: {band_info} (dwell={channel_dwell_ms}ms)")

    # Frame stats
    frames_parsed = 0
    frames_forwarded = 0

    # ---- ZMQ transport ----

    transport = None
    if not args.no_zmq and not args.stdout:
        try:
            from nozyme_tap.core.transport import ZmqTransport
            transport = ZmqTransport(
                host=config.node_host,
                port=config.node_port,
                tap_uuid=config.tap_uuid,
                tap_name=config.tap_name,
                buffer_size=config.get("zmq_buffer_size", 1000),
                sndhwm=config.get("zmq_hwm", 1000),
            )
            transport.start()
            logger.info("ZMQ transport started")
        except ImportError:
            logger.warning("ZMQ not available. Using stdout mode.")
            args.stdout = True
        except Exception as e:
            logger.warning(f"ZMQ failed to start: {e}. Using stdout mode.")
            args.stdout = True

    # ---- PCAP recorder ----

    pcap_recorder = None
    if config.get("pcap_enabled", False):
        try:
            from nozyme_tap.core.pcap import PcapRecorder
            pcap_recorder = PcapRecorder(
                interface=interface,
                pcap_path=config.get("pcap_path", "/var/lib/nozyme/pcap"),
                filesize_kb=config.get("pcap_ring_filesize_kb", 10240),
                num_files=config.get("pcap_ring_files", 10),
            )
            pcap_recorder.start()
        except Exception as e:
            logger.warning(f"PCAP recorder failed to start: {e}")

    # ---- Capture callback (the hot path) ----

    def on_capture_line(line: str):
        """Classify frame and forward only drone-related frames."""
        nonlocal frames_parsed, frames_forwarded

        result = classify_frame(line)
        if result is None:
            return

        frames_parsed += 1

        if transport:
            try:
                transport.send_wifi_frame(make_wifi_frame(
                    tap_uuid=config.tap_uuid,
                    mac=result["mac"],
                    rssi=result["rssi"],
                    channel=result["channel"],
                    frame_type=result["frame_type"],
                    raw_fields=result["layers"],
                ))
                frames_forwarded += 1
            except Exception as e:
                logger.error(f"ZMQ send failed: {e}")

        if args.stdout:
            print(json.dumps({
                "frame_type": result["frame_type"],
                "mac": result["mac"],
                "rssi": result["rssi"],
                "channel": result["channel"],
            }, default=str))

        # Report channel activity to hopper for adaptive dwell
        if channel_hopper and result["channel"]:
            channel_hopper.report_activity(result["channel"])

    _capture = TsharkCapture(
        interface=interface,
        tshark_path=config.tshark_path,
        on_line=on_capture_line,
    )

    # ---- Channel hopper ----

    channel_hopper = None
    if len(all_channels) > 1:
        channel_hopper = ChannelHopper(
            interface=interface,
            channels_by_band=channels_by_band,
            dwell_ms=channel_dwell_ms,
            active_dwell_multiplier=config.get("active_dwell_multiplier", 3.0),
            activity_timeout_s=config.get("activity_timeout_s", 30.0),
        )
        channel_hopper.start()
    elif all_channels:
        logger.info(f"Single channel mode: channel {all_channels[0]}")

    # ---- Watchdog (monitors tshark, auto-restarts) ----

    watchdog = None
    try:
        from nozyme_tap.system.watchdog import Watchdog
        watchdog = Watchdog(
            capture=_capture,
            interface=interface,
            channel=all_channels[0] if all_channels else 6,
            starvation_timeout_s=config.get("starvation_timeout_s", 30),
            restart_delay_s=config.get("tshark_restart_delay_s", 1),
            transport=transport,
            correlator=None,
            buffer_warn_threshold=config.get("buffer_warn_threshold", 500),
            memory_percent_threshold=config.get("memory_percent_threshold", 90.0),
            shutdown_event=_shutdown,
            check_interval_s=config.get("watchdog_check_interval_s", 2),
        )
    except Exception as e:
        logger.warning(f"Watchdog failed to start: {e}")

    # ---- Main capture loop ----

    last_heartbeat = 0
    last_stats = 0
    heartbeat_interval = config.get("heartbeat_interval_s", 10)
    restart_delay = config.get("tshark_restart_delay_s", 1)
    watchdog_started = False

    logger.info("Starting capture...")

    try:
        while not _shutdown.is_set():
            try:
                _capture.start()
                logger.info("tshark capture running")

                if watchdog and not watchdog_started:
                    watchdog.start()
                    logger.info("Watchdog started")
                    watchdog_started = True

                for line in _capture.read_lines():
                    if _shutdown.is_set():
                        break

                    now = time.time()

                    # Periodic heartbeat
                    if transport and (now - last_heartbeat) >= heartbeat_interval:
                        try:
                            health = get_system_health()
                        except Exception:
                            health = {"cpu_load": 0.0, "memory_used": 0}

                        current_ch = channel_hopper.current_channel if channel_hopper else (all_channels[0] if all_channels else 6)
                        cap_stats_hb = _capture.stats
                        hb = make_heartbeat(
                            tap_uuid=config.tap_uuid,
                            tap_name=config.tap_name,
                            interface=interface,
                            channel=current_ch,
                            cpu_load=health.get("cpu_load", 0.0),
                            memory_used=health.get("memory_used", 0),
                            memory_percent=health.get("memory_percent", 0.0),
                            latitude=config.latitude,
                            longitude=config.longitude,
                            frames_total=cap_stats_hb.get("lines_read", 0),
                            frames_parsed=frames_parsed,
                            tshark_running=_capture.is_running,
                            cpu_percent=health.get("cpu_percent", 0.0),
                            temperature=health.get("temperature"),
                            disk_free=health.get("disk_free"),
                            disk_writes_total=health.get("disk_writes_total"),
                            tap_uptime=now - _start_time,
                            channels=all_channels,
                            capture_errors=cap_stats_hb.get("restarts", 0) - 1,
                        )
                        transport.send_heartbeat(hb)
                        last_heartbeat = now

                    # Periodic stats log (every 60s)
                    if (now - last_stats) >= 60:
                        last_stats = now
                        cap_stats = _capture.stats
                        hopper_info = ""
                        if channel_hopper:
                            hs = channel_hopper.stats
                            hopper_info = (
                                f", hopper: {hs['mode']} "
                                f"(hops={hs['hops']}, active_ch={hs['active_channels']}, "
                                f"active_dwells={hs['active_dwells']})"
                            )
                        zmq_info = ""
                        if transport:
                            ts = transport.stats
                            zmq_info = (
                                f", zmq: {ts['sent']} sent"
                                f"/{ts['buffered']} buffered"
                                f"/{ts['errors']} errors"
                                f" ({ts['buffer_count']} queued)"
                            )
                        lines_total = cap_stats.get('lines_read', 0)
                        logger.info(
                            f"Stats: {lines_total} lines, "
                            f"{frames_parsed} drone ({frames_forwarded} fwd), "
                            f"{lines_total - frames_parsed} filtered"
                            f"{hopper_info}"
                            f"{zmq_info}"
                        )

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Capture error: {e}", exc_info=True)

            # tshark ended — cleanup and retry
            try:
                _capture.stop()
            except Exception as e:
                logger.debug(f"Error stopping capture: {e}")

            if not _shutdown.is_set():
                logger.warning(f"tshark exited, restarting in {restart_delay}s...")
                _shutdown.wait(timeout=restart_delay)

    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutting down...")
        if _capture:
            _capture.stop()
        if channel_hopper:
            try:
                channel_hopper.stop()
            except Exception as e:
                logger.debug(f"Error stopping channel hopper: {e}")
        if watchdog:
            try:
                watchdog.stop()
            except Exception as e:
                logger.debug(f"Error stopping watchdog: {e}")
        if pcap_recorder:
            try:
                pcap_recorder.stop()
            except Exception as e:
                logger.debug(f"Error stopping PCAP recorder: {e}")
        if transport:
            try:
                transport.stop()
            except Exception as e:
                logger.debug(f"Error stopping transport: {e}")

    logger.info("nozyme-tap stopped.")


if __name__ == "__main__":
    main()
