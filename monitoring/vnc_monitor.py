import time
from collections import defaultdict

from scapy.all import sniff, IP, TCP

from live_data import write_live_data


import sys
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))

from config import VNC_PORT

# ============================================================
# SMARTVNC - LIVE VNC NETWORK MONITOR
# ============================================================

MONITOR_INTERVAL = 1
IDLE_TIMEOUT = 5.0  # seconds without packets to consider session dead

# ============================================================
# MULTI-DEVICE SESSION TRACKING
# ============================================================

active_sessions = {}


# ============================================================
# PACKET PROCESSOR
# ============================================================

def process_packet(packet):

    global active_sessions

    try:
        # --------------------------------------------------------
        # Check IP and TCP
        # --------------------------------------------------------

        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip = packet[IP]
        tcp = packet[TCP]

        # --------------------------------------------------------
        # Only monitor VNC TCP port 5900
        # --------------------------------------------------------

        if (
            tcp.sport != VNC_PORT
            and tcp.dport != VNC_PORT
        ):
            return

        packet_size = len(packet)
        current_time = time.time()

        # Determine peer/client IP, port and direction
        if tcp.dport == VNC_PORT:
            c_ip = str(ip.src)
            c_port = int(tcp.sport)
            is_forward = True
        else:
            c_ip = str(ip.dst)
            c_port = int(tcp.dport)
            is_forward = False

        # Initialize new device session if needed
        if c_ip not in active_sessions:
            print("\n" + "=" * 70)
            print(f"[+] SMARTVNC: NEW VNC CLIENT DETECTED: {c_ip}:{c_port}")
            print("=" * 70)
            active_sessions[c_ip] = {
                "session_start": current_time,
                "last_packet_time": current_time,
                "client_port": c_port,
                "forward_packets": 0,
                "backward_packets": 0,
                "forward_bytes": 0,
                "backward_bytes": 0,
                "last_update_time": None,
                "last_total_bytes": 0,
                "last_total_packets": 0,
                "bytes_per_second": 0.0,
                "packets_per_second": 0.0,
                "protocol": 6
            }

        session = active_sessions[c_ip]
        session["last_packet_time"] = current_time
        session["client_port"] = c_port

        if is_forward:
            session["forward_packets"] += 1
            session["forward_bytes"] += packet_size
        else:
            session["backward_packets"] += 1
            session["backward_bytes"] += packet_size

    except Exception:
        # Prevent any packet parsing anomaly from crashing the sniffer
        return


# ============================================================
# UPDATE LIVE DATA
# ============================================================

def update_live_data():

    global active_sessions

    try:
        current_time = time.time()

        # --------------------------------------------------------
        # Per-device Idle Timeout Logic (use list to prevent mutation during iteration)
        # --------------------------------------------------------
        timed_out_clients = [
            c_ip for c_ip, s in list(active_sessions.items())
            if (current_time - s.get("last_packet_time", current_time)) > IDLE_TIMEOUT
        ]

        for c_ip in timed_out_clients:
            print(f"\n[-] Client {c_ip} Session Timed Out (Inactive)")
            if c_ip in active_sessions:
                del active_sessions[c_ip]

        # --------------------------------------------------------
        # No active VNC sessions
        # --------------------------------------------------------
        if not active_sessions:
            write_live_data(
                vnc_active=False,
                devices={}
            )
            return

        # --------------------------------------------------------
        # Calculate statistics per active client
        # --------------------------------------------------------
        devices_data = {}

        for c_ip, session in active_sessions.items():
            session_duration = max(0.0, current_time - session["session_start"])
            total_packets = session["forward_packets"] + session["backward_packets"]
            total_bytes = session["forward_bytes"] + session["backward_bytes"]

            if session["last_update_time"] is None:
                window_duration = max(session_duration, 0.001)
                bytes_in_window = total_bytes
                packets_in_window = total_packets
            else:
                window_duration = max(current_time - session["last_update_time"], 0.001)
                bytes_in_window = total_bytes - session["last_total_bytes"]
                packets_in_window = total_packets - session["last_total_packets"]

            instant_bps = max(0.0, bytes_in_window / window_duration)
            instant_pps = max(0.0, packets_in_window / window_duration)

            # Smooth bandwidth to avoid zero-drops during TCP window ACKs in file transfers
            if session.get("bytes_per_second", 0.0) > 0 and instant_bps > 0:
                bytes_per_second = 0.75 * instant_bps + 0.25 * session["bytes_per_second"]
                packets_per_second = 0.75 * instant_pps + 0.25 * session["packets_per_second"]
            else:
                bytes_per_second = instant_bps
                packets_per_second = instant_pps

            session["last_update_time"] = current_time
            session["last_total_bytes"] = total_bytes
            session["last_total_packets"] = total_packets
            session["bytes_per_second"] = bytes_per_second
            session["packets_per_second"] = packets_per_second

            devices_data[c_ip] = {
                "session_duration": session_duration,
                "client_port": session.get("client_port", 0),
                "forward_packets": session["forward_packets"],
                "backward_packets": session["backward_packets"],
                "forward_bytes": session["forward_bytes"],
                "backward_bytes": session["backward_bytes"],
                "bytes_per_second": bytes_per_second,
                "packets_per_second": packets_per_second,
                "protocol": 6
            }

        # ========================================================
        # WRITE MULTI-DEVICE DATA FOR DASHBOARD
        # ========================================================
        write_live_data(
            vnc_active=True,
            devices=devices_data
        )

    except Exception:
        pass


# ============================================================
# RESET SESSION
# ============================================================

def reset_session():

    global active_sessions
    active_sessions = {}


# ============================================================
# MAIN MONITOR
# ============================================================

def main():

    print("=" * 70)
    print("SMARTVNC - LIVE VNC NETWORK MONITOR (DYNAMIC IP)")
    print("=" * 70)

    print(
        f"\nMonitoring ANY incoming VNC traffic on Port: {VNC_PORT}"
    )

    print(
        "\nWaiting for VNC traffic..."
    )

    print(
        "Press CTRL+C to stop."
    )


    # --------------------------------------------------------
    # Initially mark VNC as inactive
    # --------------------------------------------------------

    reset_session()

    update_live_data()

    last_check = time.time()

    try:

        while True:

            # =================================================
            # CAPTURE VNC TRAFFIC
            # =================================================

            try:
                sniff(
                    filter=f"tcp port {VNC_PORT}",
                    prn=process_packet,
                    store=False,
                    timeout=MONITOR_INTERVAL
                )
            except Exception:
                time.sleep(0.1)

            current_time = time.time()

            # =================================================
            # UPDATE EVERY MONITOR INTERVAL
            # =================================================

            if (
                current_time - last_check
                >= MONITOR_INTERVAL
            ):
                try:
                    update_live_data()
                except Exception:
                    pass

                last_check = current_time


    except KeyboardInterrupt:

        print(
            "\n\nStopping SMARTVNC monitor..."
        )


        # ----------------------------------------------------
        # Mark session inactive
        # ----------------------------------------------------

        reset_session()

        update_live_data()


        print(
            "VNC session marked as INACTIVE."
        )

        print(
            "SMARTVNC monitor stopped."
        )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()