"""
nozyme-tap ZeroMQ transport.
PUB socket that sends UAV reports and heartbeats to the command center.

Features:
- Auto-reconnect on disconnect
- Offline buffer (deque, max 1000 messages)
- Replay buffered messages on reconnect
- Topic-based routing (uav, heartbeat)
"""

import logging
import time
import threading
from collections import deque
from typing import Optional

try:
    import zmq
    import msgpack
    HAS_ZMQ = True
except ImportError:
    HAS_ZMQ = False

from nozyme_tap.core.protocol import TOPIC_UAV, TOPIC_HEARTBEAT, TOPIC_FRAME

logger = logging.getLogger(__name__)


class ZmqTransport:
    """
    ZeroMQ PUB transport for sending tap messages to CC.

    The tap connects to the CC's SUB socket.
    ZMQ PUB/SUB pattern:
    - Tap: PUB connects to tcp://<host>:<port>
    - CC: SUB binds on tcp://*:<port>
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5590,
        tap_uuid: str = "",
        tap_name: str = "nozyme-tap",
        buffer_size: int = 1000,
        sndhwm: int = 1000,
    ):
        self.host = host
        self.port = port
        self.tap_uuid = tap_uuid
        self.tap_name = tap_name
        self.buffer_size = buffer_size
        self.sndhwm = sndhwm

        self._context: Optional[zmq.Context] = None
        self._socket: Optional[zmq.Socket] = None
        self._running = False
        self._connected = False
        self._buffer = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        self._buffer_bytes = 0
        self._stats = {
            "sent": 0,
            "buffered": 0,
            "replayed": 0,
            "errors": 0,
            "bytes_sent": 0,
        }

    def start(self):
        """Initialize ZMQ context and connect."""
        if not HAS_ZMQ:
            raise ImportError("pyzmq not installed. Install with: pip install pyzmq msgpack")

        self._context = zmq.Context()
        self._socket = self._context.socket(zmq.PUB)

        # Set high water mark to prevent memory blowup when node is unreachable
        self._socket.setsockopt(zmq.SNDHWM, self.sndhwm)
        # Linger: wait up to 5s for messages to send on close
        self._socket.setsockopt(zmq.LINGER, 5000)
        # Reconnect intervals for resilience
        self._socket.setsockopt(zmq.RECONNECT_IVL, 1000)
        self._socket.setsockopt(zmq.RECONNECT_IVL_MAX, 30000)
        # TCP keepalive to detect dead connections
        self._socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
        self._socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, 60)
        self._socket.setsockopt(zmq.TCP_KEEPALIVE_INTVL, 10)
        self._socket.setsockopt(zmq.TCP_KEEPALIVE_CNT, 3)

        endpoint = f"tcp://{self.host}:{self.port}"
        logger.info(f"ZMQ PUB connecting to {endpoint}")

        try:
            self._socket.connect(endpoint)
            self._connected = True
            self._running = True
            logger.info(f"ZMQ PUB connected to {endpoint}")

            # Give ZMQ a moment to establish connection
            time.sleep(0.5)

            # Replay any buffered messages
            self._replay_buffer()

        except Exception as e:
            logger.error(f"ZMQ connect failed: {e}")
            self._connected = False
            raise

    def send_uav_report(self, report: dict):
        """Send a UAV report via ZMQ."""
        self._send(TOPIC_UAV, report)

    def send_heartbeat(self, heartbeat: dict):
        """Send a tap heartbeat via ZMQ."""
        self._send(TOPIC_HEARTBEAT, heartbeat)

    def send_wifi_frame(self, frame: dict):
        """Send a wifi_frame message via ZMQ (new fast-sensor pipeline)."""
        self._send(TOPIC_FRAME, frame)

    def _send(self, topic: bytes, payload: dict):
        """Send a message, buffering if disconnected."""
        data = msgpack.packb(payload, use_bin_type=True)

        with self._lock:
            if self._socket and self._connected:
                try:
                    self._socket.send_multipart([topic, data], zmq.NOBLOCK)
                    self._stats["sent"] += 1
                    self._stats["bytes_sent"] += len(data)
                    return
                except zmq.Again:
                    # HWM reached, buffer
                    logger.debug("ZMQ HWM reached, buffering message")
                except zmq.ZMQError as e:
                    logger.warning(f"ZMQ send error: {e}")
                    self._stats["errors"] += 1

            # Buffer the message for later replay (with byte tracking)
            # If buffer is full, deque silently evicts oldest — adjust bytes
            if len(self._buffer) >= self._buffer.maxlen:
                _, evicted_data = self._buffer[0]
                self._buffer_bytes -= len(evicted_data)
                logger.warning(
                    "Transport buffer full (%d), evicting oldest message (%d bytes)",
                    self._buffer.maxlen, len(evicted_data),
                )

            msg_size = len(data)
            self._buffer.append((topic, data))
            self._buffer_bytes += msg_size
            self._stats["buffered"] += 1

    def _replay_buffer(self):
        """Replay buffered messages after reconnection."""
        with self._lock:
            count = len(self._buffer)
            if count == 0:
                return

            logger.info(f"Replaying {count} buffered messages")
            replayed = 0

            while self._buffer:
                topic, data = self._buffer.popleft()
                self._buffer_bytes -= len(data)
                try:
                    self._socket.send_multipart([topic, data], zmq.NOBLOCK)
                    self._stats["bytes_sent"] += len(data)
                    replayed += 1
                except Exception as e:
                    # Re-buffer if send fails
                    self._buffer.appendleft((topic, data))
                    self._buffer_bytes += len(data)
                    remaining = len(self._buffer)
                    logger.warning(
                        f"Replay failed after {replayed}/{count}: {e} "
                        f"({remaining} still buffered)"
                    )
                    break

            self._stats["replayed"] += replayed
            logger.info(f"Replayed {replayed}/{count} messages")

    def stop(self):
        """Close ZMQ socket and context."""
        self._running = False
        self._connected = False

        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                logger.debug(f"Error closing ZMQ socket: {e}")
            self._socket = None

        if self._context:
            try:
                self._context.term()
            except Exception as e:
                logger.debug(f"Error terminating ZMQ context: {e}")
            self._context = None

        logger.info(f"ZMQ transport stopped. Stats: {self._stats}")

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def buffered_count(self) -> int:
        with self._lock:
            return len(self._buffer)

    @property
    def buffered_bytes(self) -> int:
        with self._lock:
            return self._buffer_bytes

    @property
    def stats(self) -> dict:
        with self._lock:
            s = dict(self._stats)
            s["buffer_count"] = len(self._buffer)
            s["buffer_bytes"] = self._buffer_bytes
        return s
