import json
import time
from pathlib import Path


# ============================================================
# SMARTVNC - LIVE DATA HANDLER
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[1]

LIVE_DATA_DIR = BASE_DIR / "live_data"

LIVE_DATA_FILE = LIVE_DATA_DIR / "vnc_live_data_v2.json"


# ============================================================
# INITIALIZE DIRECTORY
# ============================================================

LIVE_DATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# WRITE LIVE VNC DATA
# ============================================================

def write_live_data(
    vnc_active=False,
    devices=None,
    session_duration=0.0,
    forward_packets=0,
    backward_packets=0,
    bytes_per_second=0.0,
    packets_per_second=0.0,
    protocol=6,
    client_ip="None"
):

    if devices is None:
        devices = {}

    if devices:
        vnc_active = True
        # The monitor reports the single active client.
        primary_ip = list(devices.keys())[0]
        p_dev = devices[primary_ip]
        session_duration = p_dev.get("session_duration", 0.0)
        forward_packets = p_dev.get("forward_packets", 0)
        backward_packets = p_dev.get("backward_packets", 0)
        bytes_per_second = p_dev.get("bytes_per_second", 0.0)
        packets_per_second = p_dev.get("packets_per_second", 0.0)
        protocol = p_dev.get("protocol", 6)
        client_ip = p_dev.get("client_ip", primary_ip)
        client_port = p_dev.get("client_port", 0)
    else:
        vnc_active = bool(vnc_active)
        client_port = 0

    data = {
        "vnc_active": vnc_active,
        "active_devices_count": len(devices),
        "client_ip": client_ip,
        "client_port": int(client_port),
        "session_duration": float(session_duration),
        "forward_packets": int(forward_packets),
        "backward_packets": int(backward_packets),
        "bytes_per_second": float(bytes_per_second),
        "packets_per_second": float(packets_per_second),
        "protocol": int(protocol),
        "devices": devices,
        "last_updated": time.strftime("%H:%M:%S"),
        "timestamp": time.time()
    }

    # --------------------------------------------------------
    # Atomic write JSON to prevent partial reads by dashboard
    # Supports nested workspace folders (e.g. C:\SmartVNC\SmartVNC)
    # --------------------------------------------------------

    target_files = [LIVE_DATA_FILE]
    nested_dir = BASE_DIR / "SmartVNC" / "live_data"
    if nested_dir.exists():
        target_files.append(nested_dir / "vnc_live_data_v2.json")
    if BASE_DIR.parent.name.lower() == "smartvnc" and (BASE_DIR.parent / "live_data").exists():
        target_files.append(BASE_DIR.parent / "live_data" / "vnc_live_data_v2.json")

    for tf in target_files:
        try:
            temp_file = tf.with_suffix(".tmp")
            with open(temp_file, "w", encoding="utf-8") as file:
                json.dump(data, file, indent=4)
            temp_file.replace(tf)
        except Exception:
            pass


# ============================================================
# READ LIVE VNC DATA
# ============================================================

def read_live_data():

    if not LIVE_DATA_FILE.exists():

        return {

            "vnc_active": False,

            "session_duration": 0.0,

            "forward_packets": 0,

            "backward_packets": 0,

            "bytes_per_second": 0.0,

            "packets_per_second": 0.0,

            "protocol": 6,

            "last_updated": ""
        }


    try:

        with open(
            LIVE_DATA_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError
    ):

        return {

            "vnc_active": False,

            "session_duration": 0.0,

            "forward_packets": 0,

            "backward_packets": 0,

            "bytes_per_second": 0.0,

            "packets_per_second": 0.0,

            "protocol": 6,

            "last_updated": ""
        }