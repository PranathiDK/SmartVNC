import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
import sys
import subprocess

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))
from config import CLIENT_IP, VNC_PORT


# ============================================================
# SMARTVNC - VNC PREVENTION ENGINE
# ============================================================
#
# Simulation-mode enforcement layer.
#
# Reads:
#   host_decisions.csv
#   network_decisions.csv
#
# Produces:
#   prevention_log.csv
#
# IMPORTANT:
# This version DOES NOT actually block VNC connections.
# It only simulates the security action and creates an audit log.
#
# ============================================================


BASE_DIR = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------
# Input files
# ------------------------------------------------------------

RISK_DIR = (
    BASE_DIR
    / "datasets"
    / "risk"
)

HOST_FILE = (
    RISK_DIR
    / "host_decisions.csv"
)

NETWORK_FILE = (
    RISK_DIR
    / "network_decisions.csv"
)


# ------------------------------------------------------------
# Output file
# ------------------------------------------------------------

OUTPUT_FILE = (
    RISK_DIR
    / "prevention_log.csv"
)


# ============================================================
# Configuration
# ============================================================

# IMPORTANT:
# Keep this True during testing.
#
# True  -> simulate actions only
# False -> reserved for future enforcement implementation
#
SIMULATION_MODE = False


# ============================================================
# Action Mapping
# ============================================================

ACTION_MAP = {
    "ALLOW": "PERMIT",
    "MONITOR": "ALERT_AND_LOG",
    "BLOCK": "BLOCK_VNC",
    "INVALID_DATA": "REJECT_INVALID_DATA"
}

# ============================================================
# ACTIVE DEFENSE ENFORCEMENT FUNCTIONS
# ============================================================

import ctypes
import socket
import struct
import base64

def is_admin():
    """Check if the current process is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ('dwState', ctypes.c_ulong),
        ('dwLocalAddr', ctypes.c_ulong),
        ('dwLocalPort', ctypes.c_ulong),
        ('dwRemoteAddr', ctypes.c_ulong),
        ('dwRemotePort', ctypes.c_ulong)
    ]

def send_tcp_rst(remote_ip, remote_port=0, local_port=VNC_PORT):
    """
    Crafts and transmits TCP Reset (RST) packets using Scapy.
    Injects TCP Reset packets for the active client.
    Works independently of administrative privileges.
    """
    try:
        from scapy.all import IP, TCP, send

        # If specific port is known, send targeted burst
        if remote_port and remote_port > 0:
            for seq_offset in [0, 1000, 50000, 1000000]:
                p1 = IP(dst=remote_ip) / TCP(sport=local_port, dport=remote_port, flags="RA", seq=seq_offset, ack=1)
                p2 = IP(dst=remote_ip) / TCP(sport=local_port, dport=remote_port, flags="R", seq=seq_offset)
                send(p1, verbose=False)
                send(p2, verbose=False)
            print(f"[+] Injected bidirectional TCP RST packets to {remote_ip}:{remote_port}")
            return True
        else:
            # Broadcast RST to remote IP on VNC port
            p = IP(dst=remote_ip) / TCP(sport=local_port, dport=VNC_PORT, flags="RA", seq=0)
            send(p, verbose=False)
            return True
    except Exception as e:
        print(f"[!] Scapy RST injection error: {e}")
        return False

def terminate_tcp_connection(remote_ip, local_port=VNC_PORT, remote_port=0):
    """
    Terminates active TCP socket using multiple defense layers:
      Layer 1: Scapy TCP RST packet injection
      Layer 2: Windows SetTcpEntry (if elevated)
      No server-wide disconnect command is used; other VNC clients stay connected.
    """
    terminated_count = 0

    # 1. Scapy RST packet injection
    if send_tcp_rst(remote_ip, remote_port, local_port):
        terminated_count += 1

    # 2. Kernel SetTcpEntry (if elevated)
    try:
        iphlpapi = ctypes.windll.iphlpapi
        iphlpapi.SetTcpEntry.argtypes = [ctypes.POINTER(MIB_TCPROW)]
        iphlpapi.SetTcpEntry.restype = ctypes.c_ulong

        buf_size = ctypes.c_ulong(0)
        iphlpapi.GetExtendedTcpTable(None, ctypes.byref(buf_size), True, socket.AF_INET, 5, 0)
        buf = ctypes.create_string_buffer(buf_size.value)
        if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(buf_size), True, socket.AF_INET, 5, 0) == 0:
            num_entries = struct.unpack('<I', buf[:4])[0]
            for i in range(num_entries):
                offset = 4 + i * 24
                state, l_addr, l_port_raw, r_addr, r_port_raw, pid = struct.unpack('<IIIIII', buf[offset:offset+24])
                l_port = socket.ntohs(l_port_raw & 0xFFFF)
                r_ip = socket.inet_ntoa(struct.pack('<I', r_addr))
                r_port = socket.ntohs(r_port_raw & 0xFFFF)
                if (
                    l_port == local_port
                    and r_ip == remote_ip
                    and (not remote_port or r_port == remote_port)
                ):
                    row = MIB_TCPROW(12, l_addr, l_port_raw, r_addr, r_port_raw)
                    res = iphlpapi.SetTcpEntry(ctypes.byref(row))
                    if res == 0:
                        terminated_count += 1
                        print(f"[+] Kernel TCP socket {remote_ip}:{r_port} severed via SetTcpEntry.")
    except Exception:
        pass

    return terminated_count

def apply_firewall_block(client_ip):
    """
    Applies Windows Firewall rules using native PowerShell NetSecurity cmdlets.
    Handles elevated execution or dispatches background UAC elevation.
    """
    rule_in = f"SmartVNC_Block_{client_ip}"
    rule_out = f"SmartVNC_Block_Out_{client_ip}"

    # Treat firewall rule creation failures as errors instead of silently
    # accepting a successful PowerShell process exit.
    ps_cmd = (
        f"Get-NetFirewallRule | Where-Object {{ "
        f"$_.DisplayName -eq '{rule_in}' -or "
        f"$_.DisplayName -eq '{rule_out}' -or "
        f"$_.DisplayName -like '{rule_in}_*' -or "
        f"$_.DisplayName -like '{rule_out}_*' "
        f"}} | Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
        f'New-NetFirewallRule -DisplayName "{rule_in}" -Direction Inbound -Action Block -RemoteAddress "{client_ip}" -Protocol TCP -LocalPort {VNC_PORT} -ErrorAction Stop; '
        f'New-NetFirewallRule -DisplayName "{rule_out}" -Direction Outbound -Action Block -RemoteAddress "{client_ip}" -Protocol TCP -LocalPort {VNC_PORT} -ErrorAction Stop; '
        f'if (-not (Get-NetFirewallRule -DisplayName "{rule_in}" -ErrorAction SilentlyContinue)) {{ throw "Inbound firewall rule was not created" }}; '
        f'if (-not (Get-NetFirewallRule -DisplayName "{rule_out}" -ErrorAction SilentlyContinue)) {{ throw "Outbound firewall rule was not created" }}'
    )

    if is_admin():
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                print(f"[+] Windows Firewall rules applied for {client_ip}")
                return True, "Firewall rules applied directly (Admin)"
        except Exception as e:
            print(f"[!] Direct firewall error: {e}")

    # If not admin or direct execution failed, wait for the elevated command
    # and propagate its exit code so UAC cancellation/failures are visible.
    encoded_command = base64.b64encode(
        ps_cmd.encode("utf-16le")
    ).decode("ascii")
    elevated_cmd = (
        f"$process = Start-Process powershell -Verb RunAs -Wait -PassThru "
        f"-ArgumentList '-NoProfile -EncodedCommand {encoded_command}'; "
        "exit $process.ExitCode"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", elevated_cmd],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode == 0:
            print(f"[+] Elevated firewall rules applied for {client_ip}")
            return True, "Firewall rules applied through elevation"
        error = res.stderr.strip() or res.stdout.strip() or f"exit code {res.returncode}"
        return False, f"Elevated firewall command failed: {error}"
    except Exception as e:
        print(f"[!] Elevated dispatch error: {e}")
        return False, f"Firewall dispatch error: {e}"

def remove_firewall_block(client_ip):
    """Removes the VNC firewall rules for a client IP."""
    ps_cmd = (
        f"Get-NetFirewallRule | Where-Object {{ "
        f"$_.DisplayName -eq 'SmartVNC_Block_{client_ip}' -or "
        f"$_.DisplayName -eq 'SmartVNC_Block_Out_{client_ip}' -or "
        f"$_.DisplayName -like 'SmartVNC_Block_{client_ip}_*' -or "
        f"$_.DisplayName -like 'SmartVNC_Block_Out_{client_ip}_*' "
        f"}} | Remove-NetFirewallRule -ErrorAction SilentlyContinue"
    )
    if is_admin():
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return True, "Firewall rules removed"
            error = result.stderr.strip() or result.stdout.strip()
            return False, f"Firewall rule removal failed: {error or result.returncode}"
        except Exception as error:
            return False, f"Firewall rule removal failed: {error}"

    encoded_command = base64.b64encode(
        ps_cmd.encode("utf-16le")
    ).decode("ascii")
    elevated_cmd = (
        f"$process = Start-Process powershell -Verb RunAs -Wait -PassThru "
        f"-ArgumentList '-NoProfile -EncodedCommand {encoded_command}'; "
        "exit $process.ExitCode"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", elevated_cmd],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            return True, "Firewall rules removed through elevation"
        error = result.stderr.strip() or result.stdout.strip()
        return False, f"Elevated firewall rule removal failed: {error or result.returncode}"
    except Exception as error:
        return False, f"Firewall rule removal failed: {error}"

def enforce_block(client_ip, client_port=0, reason="Critical Exfiltration Risk"):
    """
    Terminates the active session and blocks the client IP.
    """
    if not client_ip or client_ip in ["Unknown", "None"]:
        return False, "Cannot block unknown or empty IP address"

    print(f"\n" + "=" * 70)
    print(f"[!] SMARTVNC ACTIVE DEFENSE: Terminating & Blocking {client_ip}:{client_port}")
    print(f"    Reason: {reason}")
    print("=" * 70)

    # 1. Record the client block so the monitor rejects its traffic.
    try:
        from database.db_manager import record_blocked_device
        record_blocked_device(client_ip, client_port, reason)
    except Exception as e:
        print(f"[!] Warning: could not record to db: {e}")
        database_error = str(e)
    else:
        database_error = None

    # 2. Terminate the active VNC connection using targeted TCP controls.
    terminated_count = terminate_tcp_connection(client_ip, VNC_PORT)

    # 3. Add Windows Firewall Block Rules (skip IP firewall rule for localhost to keep system loopback healthy)
    fw_status = "Skipped on localhost"
    fw_success = True
    if client_ip not in ["127.0.0.1", "localhost", "::1"]:
        fw_success, fw_status = apply_firewall_block(client_ip)

    try:
        execution_status = "ENFORCED" if fw_success else "FIREWALL_FAILED"
        log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{client_ip},{client_port},CRITICAL,BLOCK_VNC,{reason},{execution_status}\n"
        if not OUTPUT_FILE.exists():
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write("timestamp,client_ip,client_port,risk_level,action,reason,execution_status\n")
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception:
        pass

    if terminated_count == 0 and not fw_success:
        return False, f"Could not terminate or firewall-block {client_ip}. {fw_status}"
    if database_error:
        return False, (
            f"Client {client_ip} was targeted, but its block "
            f"could not be persisted: {database_error}"
        )

    msg = f"Client {client_ip} targeted for termination and blocking. {fw_status}."
    return fw_success, msg

def enforce_unblock(client_ip):
    """
    Removes Windows Firewall block rules and marks device unblocked in DB.
    """
    if not client_ip or client_ip in ["Unknown", "None"]:
        return False, "Invalid IP"

    if client_ip not in ["127.0.0.1", "localhost", "::1"]:
        success, message = remove_firewall_block(client_ip)
        if not success:
            return False, message

    try:
        from database.db_manager import record_unblocked_device
        record_unblocked_device(client_ip)
    except Exception as error:
        return False, f"Firewall rules removed, but database update failed: {error}"

    print(f"[+] Device {client_ip} unblocked successfully.")
    return True, f"Client {client_ip} unblocked."

def is_ip_blocked(client_ip):
    """
    Checks if client_ip has an active block rule in DB or Windows Firewall.
    """
    if not client_ip or client_ip in ["Unknown", "None"]:
        return False
    try:
        from database.db_manager import is_device_blocked
        if is_device_blocked(client_ip):
            return True
    except Exception:
        pass

    return False

# ============================================================
# Main
# ============================================================

def main():

    print("=" * 70)
    print("SMARTVNC - VNC PREVENTION ENGINE")
    print("SIMULATION MODE")
    print("=" * 70)


    # --------------------------------------------------------
    # 1. Check input files
    # --------------------------------------------------------

    if not HOST_FILE.exists():

        raise FileNotFoundError(
            f"Host decision file not found:\n{HOST_FILE}"
        )


    if not NETWORK_FILE.exists():

        raise FileNotFoundError(
            f"Network decision file not found:\n{NETWORK_FILE}"
        )


    # --------------------------------------------------------
    # 2. Load Host Decisions
    # --------------------------------------------------------

    print("\nLoading host decisions...")

    host_df = pd.read_csv(
        HOST_FILE
    )

    print(
        f"Host decision records: {len(host_df):,}"
    )


    # --------------------------------------------------------
    # 3. Load Network Decisions
    # --------------------------------------------------------

    print("\nLoading network decisions...")

    network_df = pd.read_csv(
        NETWORK_FILE
    )

    print(
        f"Network decision records: {len(network_df):,}"
    )


    # --------------------------------------------------------
    # 4. Validate Host Columns
    # --------------------------------------------------------

    required_host_columns = [
        "timestamp",
        "user",
        "computer",
        "host_risk",
        "risk_level",
        "host_decision"
    ]


    for column in required_host_columns:

        if column not in host_df.columns:

            raise ValueError(
                f"Missing host column: {column}"
            )


    # --------------------------------------------------------
    # 5. Validate Network Columns
    # --------------------------------------------------------

    required_network_columns = [
        "network_risk",
        "risk_level",
        "network_decision"
    ]


    for column in required_network_columns:

        if column not in network_df.columns:

            raise ValueError(
                f"Missing network column: {column}"
            )


    # ========================================================
    # HOST PREVENTION ACTIONS
    # ========================================================

    print(
        "\nGenerating host prevention actions..."
    )


    host_actions = pd.DataFrame(
        index=host_df.index
    )


    # --------------------------------------------------------
    # Host event source
    # --------------------------------------------------------

    host_actions["event_source"] = "CERT_HOST"


    # --------------------------------------------------------
    # Host event information
    # --------------------------------------------------------

    host_actions["timestamp"] = (
        host_df["timestamp"].values
    )

    host_actions["user"] = (
        host_df["user"].values
    )

    host_actions["computer"] = (
        host_df["computer"].values
    )


    # --------------------------------------------------------
    # Host risk information
    # --------------------------------------------------------

    host_actions["risk_score"] = (
        host_df["host_risk"].values
    )

    host_actions["risk_level"] = (
        host_df["risk_level"].values
    )

    host_actions["decision"] = (
        host_df["host_decision"].values
    )


    # --------------------------------------------------------
    # Host security action
    # --------------------------------------------------------

    host_actions["action"] = (
        host_df["host_decision"]
        .map(ACTION_MAP)
        .values
    )


    # --------------------------------------------------------
    # Host reason
    # --------------------------------------------------------

    if "risk_reason" in host_df.columns:

        host_actions["reason"] = (
            host_df["risk_reason"].values
        )

    else:

        host_actions["reason"] = (
            "CERT host risk decision"
        )


    # ========================================================
    # NETWORK PREVENTION ACTIONS
    # ========================================================

    print(
        "Generating network prevention actions..."
    )


    network_actions = pd.DataFrame(
        index=network_df.index
    )


    # --------------------------------------------------------
    # Network event source
    # --------------------------------------------------------

    network_actions["event_source"] = (
        "CICIDS_NETWORK"
    )


    # --------------------------------------------------------
    # Network identity information
    # --------------------------------------------------------
    #
    # The current CICIDS dataset does not contain:
    #
    #   user
    #   computer
    #   source IP
    #   destination IP
    #   timestamp
    #
    # Therefore we explicitly mark them unavailable.
    #
    # We DO NOT invent a host mapping.
    # --------------------------------------------------------

    network_actions["timestamp"] = (
        "NOT_AVAILABLE"
    )

    network_actions["user"] = (
        "NOT_AVAILABLE"
    )

    network_actions["computer"] = (
        "NOT_AVAILABLE"
    )


    # --------------------------------------------------------
    # Network risk information
    # --------------------------------------------------------

    network_actions["risk_score"] = (
        network_df["network_risk"].values
    )

    network_actions["risk_level"] = (
        network_df["risk_level"].values
    )

    network_actions["decision"] = (
        network_df["network_decision"].values
    )


    # --------------------------------------------------------
    # Network security action
    # --------------------------------------------------------

    network_actions["action"] = (
        network_df["network_decision"]
        .map(ACTION_MAP)
        .values
    )


    # --------------------------------------------------------
    # Network reason
    # --------------------------------------------------------

    if "risk_reason" in network_df.columns:

        network_actions["reason"] = (
            network_df["risk_reason"].values
        )

    else:

        network_actions["reason"] = (
            "XGBoost network risk decision"
        )


    # ========================================================
    # COMBINE ACTIONS
    # ========================================================

    print(
        "\nCombining security actions..."
    )


    actions = pd.concat(
        [
            host_actions,
            network_actions
        ],
        ignore_index=True
    )


    # --------------------------------------------------------
    # Add engine timestamp
    # --------------------------------------------------------

    actions["engine_timestamp"] = (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )


    # --------------------------------------------------------
    # Execution mode
    # --------------------------------------------------------

    if SIMULATION_MODE:

        actions["execution_mode"] = (
            "SIMULATION"
        )

        actions["execution_status"] = (
            "SIMULATED_ONLY"
        )

    else:

        actions["execution_mode"] = (
            "ENFORCEMENT"
        )

        # Check if we need to block VNC
        needs_block = any(actions["action"] == "BLOCK_VNC")

        if needs_block:
            try:
                # Fetch the dynamic client IP of the latest attacker from the database
                import sqlite3
                conn = sqlite3.connect(BASE_DIR / 'database' / 'smartvnc.db')
                cursor = conn.cursor()
                cursor.execute("SELECT client_ip, client_port FROM alerts WHERE risk_level IN ('HIGH', 'CRITICAL') ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                conn.close()

                target_ip = row[0] if row and row[0] != "Unknown" else CLIENT_IP
                target_port = row[1] if row and len(row) > 1 else 0

                enforce_block(target_ip, target_port, reason="Offline batch prevention run")
                actions["execution_status"] = "ENFORCED"
            except Exception as e:
                print(f"[ERROR] Failed to execute prevention block: {e}")
                actions["execution_status"] = "ENFORCEMENT_FAILED"
        else:
            actions["execution_status"] = "NO_ACTION_REQUIRED"


    # ========================================================
    # SAVE PREVENTION LOG
    # ========================================================

    actions.to_csv(
        OUTPUT_FILE,
        index=False
    )


    # ========================================================
    # STATISTICS
    # ========================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "PREVENTION ACTION SUMMARY"
    )

    print(
        "=" * 70
    )


    # --------------------------------------------------------
    # All actions
    # --------------------------------------------------------

    print(
        "\nAll actions:"
    )

    print(
        actions["action"]
        .value_counts()
        .to_string()
    )


    # --------------------------------------------------------
    # Host actions
    # --------------------------------------------------------

    print(
        "\nHost actions:"
    )

    print(
        host_actions["action"]
        .value_counts()
        .to_string()
    )


    # --------------------------------------------------------
    # Network actions
    # --------------------------------------------------------

    print(
        "\nNetwork actions:"
    )

    print(
        network_actions["action"]
        .value_counts()
        .to_string()
    )


    # --------------------------------------------------------
    # Total simulated blocks
    # --------------------------------------------------------

    block_actions = actions[
        actions["action"] == "BLOCK_VNC"
    ]


    print(
        "\nTotal simulated VNC blocks:",
        len(block_actions)
    )


    # ========================================================
    # HOST BLOCK SUMMARY
    # ========================================================

    host_block_actions = host_actions[
        host_actions["action"] == "BLOCK_VNC"
    ]


    print(
        "\nHost BLOCK actions:",
        len(host_block_actions)
    )


    # ========================================================
    # NETWORK BLOCK SUMMARY
    # ========================================================

    network_block_actions = network_actions[
        network_actions["action"] == "BLOCK_VNC"
    ]


    print(
        "Network BLOCK actions:",
        len(network_block_actions)
    )


    # ========================================================
    # SAMPLE BLOCKED EVENTS
    # ========================================================

    if len(block_actions) > 0:

        print(
            "\nSample BLOCK actions:"
        )


        display_columns = [
            "event_source",
            "timestamp",
            "user",
            "computer",
            "risk_score",
            "risk_level",
            "decision",
            "action",
            "reason"
        ]


        print(
            block_actions[
                display_columns
            ]
            .head(10)
            .to_string(index=False)
        )


    # ========================================================
    # Verify Event Sources
    # ========================================================

    print(
        "\nEvent source distribution:"
    )

    print(
        actions["event_source"]
        .value_counts()
        .to_string()
    )


    # ========================================================
    # COMPLETION
    # ========================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "VNC PREVENTION ENGINE COMPLETED"
    )

    print(
        "=" * 70
    )


    print(
        "\nExecution mode: SIMULATION"
    )


    print(
        "\nIMPORTANT:"
    )

    print(
        "No VNC connection was actually blocked."
    )

    print(
        "No firewall rules were modified."
    )


    print(
        "\nOutput file:"
    )

    print(
        OUTPUT_FILE
    )


# ============================================================
# Program Entry Point
# ============================================================

if __name__ == "__main__":

    main()
