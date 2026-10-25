import time
from collections import defaultdict

from scapy.all import sniff, IP, TCP, send

from live_data import write_live_data


import sys
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))

from config import VNC_PORT
from database.db_manager import is_device_blocked

# ============================================================
# SMARTVNC - LIVE VNC NETWORK MONITOR
# ============================================================

MONITOR_INTERVAL = 1
IDLE_TIMEOUT = 60.0  # Allow natural client idle pauses without dropping session
TRANSFER_RATE_THRESHOLD = 250000
TRANSFER_CONFIRM_TICKS = 3
TRANSFER_IDLE_TICKS = 3

# ============================================================
# SINGLE CLIENT SESSION TRACKING
# ============================================================

active_sessions = {}


def update_transfer_burst(session, instant_bps, bytes_in_window):
    """Accumulate bytes only after sustained transfer-speed samples."""
    if instant_bps >= TRANSFER_RATE_THRESHOLD:
        session["transfer_rate_ticks"] = session.get("transfer_rate_ticks", 0) + 1
        session["transfer_candidate_bytes"] = (
            session.get("transfer_candidate_bytes", 0) + bytes_in_window
        )
        session["transfer_idle_ticks"] = 0

        if session["transfer_rate_ticks"] >= TRANSFER_CONFIRM_TICKS:
            session["burst_bytes"] = (
                session.get("burst_bytes", 0)
                + session["transfer_candidate_bytes"]
            )
            session["transfer_candidate_bytes"] = 0
    else:
        session["transfer_rate_ticks"] = 0
        session["transfer_candidate_bytes"] = 0
        session["transfer_idle_ticks"] = session.get("transfer_idle_ticks", 0) + 1

        if session["transfer_idle_ticks"] >= TRANSFER_IDLE_TICKS:
            session["burst_bytes"] = 0
            session["transfer_idle_ticks"] = 0

    return session.get("burst_bytes", 0)


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

        # Determine the client address and traffic direction.
        if tcp.dport == VNC_PORT:
            c_ip = str(ip.src)
            c_port = int(tcp.sport)
            s_ip = str(ip.dst)
            is_forward = True
        else:
            c_ip = str(ip.dst)
            c_port = int(tcp.dport)
            s_ip = str(ip.src)
            is_forward = False

        # --------------------------------------------------------
        # ACTIVE DEFENSE ENFORCEMENT DROP
        # If client IP is registered as blocked, actively reject and drop!
        # --------------------------------------------------------
        if is_device_blocked(c_ip):
            active_sessions.pop(c_ip, None)
            try:
                # Inject bidirectional TCP RST to immediately sever socket
                send(IP(src=s_ip, dst=c_ip)/TCP(sport=VNC_PORT, dport=c_port, flags="RA", seq=tcp.ack, ack=tcp.seq+1), verbose=False)
                send(IP(src=c_ip, dst=s_ip)/TCP(sport=c_port, dport=VNC_PORT, flags="RA", seq=tcp.seq, ack=tcp.ack+1), verbose=False)
            except Exception:
                pass
            return

        flags = int(tcp.flags)
        # --------------------------------------------------------
        # TCP FIN or RST Flag -> Clean Session Teardown
        # --------------------------------------------------------
        if (flags & 0x01) or (flags & 0x04):  # FIN or RST
            if (
                c_ip in active_sessions
                and active_sessions[c_ip]["client_port"] == c_port
            ):
                print(f"\n[-] Client {c_ip}:{c_port} disconnected cleanly (TCP FIN/RST)")
                del active_sessions[c_ip]
            return

        # Reject new VNC connections while the single monitored client is active.
        if active_sessions and (
            c_ip not in active_sessions
            or active_sessions[c_ip]["client_port"] != c_port
        ):
            if (flags & 0x02) and not (flags & 0x10):
                try:
                    send(
                        IP(src=s_ip, dst=c_ip)
                        / TCP(
                            sport=VNC_PORT,
                            dport=c_port,
                            flags="RA",
                            seq=0,
                            ack=tcp.seq + 1,
                        ),
                        verbose=False,
                    )
                except Exception:
                    pass
            return

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
                "last_update_time": current_time,
                "last_total_bytes": 0,
                "last_total_packets": 0,
                "bytes_per_second": 0.0,
                "packets_per_second": 0.0,
                "burst_bytes": 0,
                "transfer_rate_ticks": 0,
                "transfer_candidate_bytes": 0,
                "transfer_idle_ticks": 0,
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
        # Check active sessions against blocked devices
        # --------------------------------------------------------
        blocked_clients = [
            client_ip
            for client_ip in active_sessions
            if is_device_blocked(client_ip)
        ]
        for client_ip in blocked_clients:
            print(f"\n[🛑] Purging blocked client session: {client_ip}")
            del active_sessions[client_ip]

        # --------------------------------------------------------
        # Per-client idle timeout
        # --------------------------------------------------------
        timed_out_clients = [
            client_ip for client_ip, s in list(active_sessions.items())
            if (current_time - s.get("last_packet_time", current_time)) > IDLE_TIMEOUT
        ]

        for client_ip in timed_out_clients:
            print(f"\n[-] Client {client_ip} Session Timed Out (Inactive > {IDLE_TIMEOUT}s)")
            if client_ip in active_sessions:
                del active_sessions[client_ip]

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
        # Calculate statistics for the single active client.
        # --------------------------------------------------------
        devices_data = {}

        for c_ip, session in active_sessions.items():
            session_duration = max(0.0, current_time - session["session_start"])
            total_packets = session["forward_packets"] + session["backward_packets"]
            total_bytes = session["forward_bytes"] + session["backward_bytes"]

            last_up = session.get("last_update_time")
            if last_up is None:
                elapsed = max(session_duration, 1.0)
                bytes_in_window = total_bytes
                packets_in_window = total_packets
            else:
                elapsed = max(current_time - last_up, 1.0)
                bytes_in_window = max(0, total_bytes - session.get("last_total_bytes", 0))
                packets_in_window = max(0, total_packets - session.get("last_total_packets", 0))

            # Direct throughput calculation from captured bytes without suppressing file downloads
            if bytes_in_window == 0:
                instant_bps = 0.0
                instant_pps = 0.0
            else:
                instant_bps = max(0.0, bytes_in_window / elapsed)
                instant_pps = max(0.0, packets_in_window / elapsed)

            # Decay throughput to 0 if client is idle
            prev_bps = session.get("bytes_per_second", 0.0)
            prev_pps = session.get("packets_per_second", 0.0)

            if instant_bps == 0.0:
                bytes_per_second = 0.0
                packets_per_second = 0.0
            else:
                if prev_bps > 0:
                    bytes_per_second = 0.75 * instant_bps + 0.25 * prev_bps
                    packets_per_second = 0.75 * instant_pps + 0.25 * prev_pps
                else:
                    bytes_per_second = instant_bps
                    packets_per_second = instant_pps

            session["last_update_time"] = current_time
            session["last_total_bytes"] = total_bytes
            session["last_total_packets"] = total_packets
            session["bytes_per_second"] = bytes_per_second
            session["packets_per_second"] = packets_per_second

            burst_bytes = update_transfer_burst(
                session,
                instant_bps,
                bytes_in_window,
            )

            devices_data[c_ip] = {
                "session_duration": session_duration,
                "client_ip": c_ip,
                "client_port": session.get("client_port", 0),
                "forward_packets": session["forward_packets"],
                "backward_packets": session["backward_packets"],
                "forward_bytes": session["forward_bytes"],
                "backward_bytes": session["backward_bytes"],
                "bytes_per_second": bytes_per_second,
                "packets_per_second": packets_per_second,
                "burst_bytes": burst_bytes,
                "protocol": 6
            }

        # ========================================================
        # WRITE ACTIVE CLIENT DATA FOR DASHBOARD
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