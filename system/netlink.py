"""
Raw nl80211 netlink channel control.

Sets WiFi monitor-mode channel via AF_NETLINK socket — zero subprocess forks.
Typical channel switch: <1ms (vs ~50ms for subprocess `iw`).

Uses only stdlib (socket, struct). No external dependencies.
"""

import socket
import struct
import logging
import threading

logger = logging.getLogger(__name__)

# Netlink constants
NETLINK_GENERIC = 16
NLM_F_REQUEST = 0x0001
NLM_F_ACK = 0x0004

# Netlink message types
NLMSG_ERROR = 2
NLMSG_DONE = 3

# Generic netlink controller
GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_FAMILY_ID = 1

# nl80211 constants (from /usr/include/linux/nl80211.h)
# NL80211_CMD_SET_WIPHY (2) works with active monitor captures;
# NL80211_CMD_SET_WIPHY (64) fails with -EOPNOTSUPP when dumpcap holds the VIF.
NL80211_CMD_SET_WIPHY = 2
NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_WIPHY_FREQ = 38
NL80211_ATTR_CHANNEL_WIDTH = 159
NL80211_ATTR_CENTER_FREQ1 = 160
NL80211_CHAN_WIDTH_20_NOHT = 0


def _nlattr(attr_type: int, data: bytes) -> bytes:
    """Build a single netlink attribute (nla_len, nla_type, payload, padding)."""
    nla_len = 4 + len(data)  # 2 bytes len + 2 bytes type + payload
    # Pad to 4-byte alignment
    padded = nla_len + ((4 - (nla_len % 4)) % 4)
    return struct.pack("HH", nla_len, attr_type) + data + b'\x00' * (padded - nla_len)


def _nlattr_u32(attr_type: int, value: int) -> bytes:
    """Build a U32 netlink attribute."""
    return _nlattr(attr_type, struct.pack("I", value))


def _nlattr_str(attr_type: int, value: str) -> bytes:
    """Build a NUL-terminated string netlink attribute."""
    return _nlattr(attr_type, value.encode("ascii") + b'\x00')


class NL80211Channel:
    """Direct nl80211 channel control via raw netlink socket."""

    def __init__(self):
        self._sock = None
        self._family_id = None
        self._seq = 0
        self._lock = threading.Lock()

        try:
            self._sock = socket.socket(
                socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC
            )
            self._sock.bind((0, 0))
            self._sock.settimeout(2.0)

            self._family_id = self._resolve_family("nl80211")
            if self._family_id is None:
                raise RuntimeError("Failed to resolve nl80211 family ID")
        except Exception:
            self.close()
            raise

        logger.info(
            f"nl80211 netlink initialized (family_id={self._family_id})"
        )

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _resolve_family(self, name: str) -> int:
        """Resolve a generic netlink family name to its numeric ID."""
        seq = self._next_seq()
        payload = _nlattr_str(CTRL_ATTR_FAMILY_NAME, name)

        # genlmsghdr: cmd(1) + version(1) + reserved(2)
        genlhdr = struct.pack("BBH", CTRL_CMD_GETFAMILY, 1, 0)

        msg_len = 16 + len(genlhdr) + len(payload)  # nlmsghdr is 16 bytes
        nlhdr = struct.pack(
            "IHHII",
            msg_len,              # nlmsg_len
            GENL_ID_CTRL,         # nlmsg_type
            NLM_F_REQUEST | NLM_F_ACK,  # nlmsg_flags
            seq,                  # nlmsg_seq
            0,                    # nlmsg_pid
        )

        self._sock.sendto(nlhdr + genlhdr + payload, (0, 0))

        # Read response(s)
        while True:
            data = self._sock.recv(4096)
            if len(data) < 16:
                break

            msg_len, msg_type, msg_flags, msg_seq, msg_pid = struct.unpack(
                "IHHII", data[:16]
            )

            if msg_type == NLMSG_ERROR:
                error_code = struct.unpack("i", data[16:20])[0]
                if error_code == 0:
                    continue  # ACK, not error
                logger.error(f"Netlink error resolving {name}: {error_code}")
                return None

            if msg_type == NLMSG_DONE:
                break

            if msg_type == GENL_ID_CTRL:
                # Parse attributes from response (skip nlmsghdr + genlmsghdr)
                attrs_data = data[20:]
                return self._parse_family_id(attrs_data)

        return None

    def _parse_family_id(self, data: bytes) -> int:
        """Extract CTRL_ATTR_FAMILY_ID from netlink attributes."""
        offset = 0
        while offset + 4 <= len(data):
            nla_len, nla_type = struct.unpack("HH", data[offset:offset + 4])
            if nla_len < 4:
                break
            if nla_type == CTRL_ATTR_FAMILY_ID:
                return struct.unpack("H", data[offset + 4:offset + 6])[0]
            # Advance to next attr (4-byte aligned)
            offset += (nla_len + 3) & ~3
        return None

    def set_channel(self, ifindex: int, freq_mhz: int) -> bool:
        """
        Set channel on an interface by frequency.

        Args:
            ifindex: Network interface index (from /sys/class/net/<iface>/ifindex)
            freq_mhz: Channel center frequency in MHz (e.g., 2437 for channel 6)

        Returns:
            True if channel was set successfully.
        """
        if self._sock is None:
            return False

        with self._lock:
            seq = self._next_seq()

            # Build attributes
            attrs = (
                _nlattr_u32(NL80211_ATTR_IFINDEX, ifindex) +
                _nlattr_u32(NL80211_ATTR_WIPHY_FREQ, freq_mhz) +
                _nlattr_u32(NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_20_NOHT) +
                _nlattr_u32(NL80211_ATTR_CENTER_FREQ1, freq_mhz)
            )

            # genlmsghdr: cmd + version + reserved
            genlhdr = struct.pack("BBH", NL80211_CMD_SET_WIPHY, 0, 0)

            msg_len = 16 + len(genlhdr) + len(attrs)
            nlhdr = struct.pack(
                "IHHII",
                msg_len,
                self._family_id,
                NLM_F_REQUEST | NLM_F_ACK,
                seq,
                0,
            )

            try:
                self._sock.sendto(nlhdr + genlhdr + attrs, (0, 0))

                # Wait for ACK
                data = self._sock.recv(4096)
                if len(data) < 20:
                    return False

                msg_len, msg_type, msg_flags, msg_seq, msg_pid = struct.unpack(
                    "IHHII", data[:16]
                )

                if msg_type == NLMSG_ERROR:
                    error_code = struct.unpack("i", data[16:20])[0]
                    if error_code == 0:
                        return True  # ACK = success
                    logger.debug(
                        f"nl80211 set_channel failed: ifindex={ifindex} "
                        f"freq={freq_mhz} error={error_code}"
                    )
                    return False

                return True

            except socket.timeout:
                logger.warning("nl80211 set_channel timed out")
                return False
            except OSError as e:
                logger.warning(f"nl80211 set_channel error: {e}")
                return False

    def close(self):
        """Close the netlink socket."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
