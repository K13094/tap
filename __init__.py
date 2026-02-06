"""
nozyme-tap: WiFi RemoteID drone detection tap.
Captures OpenDroneID frames via tshark, parses all 65+ ASTM F3411 fields,
correlates by MAC, and sends UAV reports via ZeroMQ to the command center.
"""

__version__ = "0.2.0"
