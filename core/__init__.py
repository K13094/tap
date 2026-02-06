"""nozyme-tap core: capture → classify → forward."""
from .capture import TsharkCapture, setup_monitor_mode, ChannelHopper, set_channel
from .quick_filter import classify_frame


def __getattr__(name):
    """Lazy import for ZmqTransport (avoids loading zmq/msgpack at import time)."""
    if name == "ZmqTransport":
        from .transport import ZmqTransport
        return ZmqTransport
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
