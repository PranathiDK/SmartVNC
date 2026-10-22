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

TIGHTVNC_EXECUTABLES = [
    r"C:\Program Files\TightVNC\tvnserver.exe",
    r"C:\Program Files (x86)\TightVNC\tvnserver.exe"
]

def disconnect_vnc_sessions():
    """Immediately sever all active VNC client connections via TightVNC control."""
    success = False
    for exe in TIGHTVNC_EXECUTABLES:
        if Path(exe).exists():
            try:
                subprocess.run([exe, "-controlservice", "-disconnectall"], capture_output=True, timeout=3)
                subprocess.run([exe, "-controlapp", "-disconnectall"], capture_output=True, timeout=3)
                success = True
            except Exception:
                pass
    return success

def enforce_block(client_ip, client_port=0, reason="Critical Exfiltration Risk"):
    """
    Terminates the active connection and adds Windows Firewall Inbound & Outbound block rules for the client IP.
    """
    if not client_ip or client_ip in ["Unknown", "None", "127.0.0.1", "localhost"]:
        return False, "Cannot block localhost or unknown IP"
        
    print(f"\n" + "=" * 70)
    print(f"[!] SMARTVNC ACTIVE DEFENSE: Terminating & Blocking {client_ip}:{client_port}")
    print(f"    Reason: {reason}")
    print("=" * 70)
    
    # 1. Sever the active VNC connection immediately
    disconnect_vnc_sessions()
    
    # 2. Add Windows Firewall Inbound and Outbound Block Rules for VNC
    rule_in = f"SmartVNC_Block_{client_ip}"
    rule_out = f"SmartVNC_Block_Out_{client_ip}"
    
    del_in = f'netsh advfirewall firewall delete rule name="{rule_in}"'
    del_out = f'netsh advfirewall firewall delete rule name="{rule_out}"'
    cmd_in = f'netsh advfirewall firewall add rule name="{rule_in}" dir=in action=block protocol=TCP localport={VNC_PORT} remoteip={client_ip}'
    cmd_out = f'netsh advfirewall firewall add rule name="{rule_out}" dir=out action=block protocol=TCP remoteip={client_ip}'
    
    # Clean previous rules if any
    subprocess.run(del_in, shell=True, capture_output=True)
    subprocess.run(del_out, shell=True, capture_output=True)
    
    res = subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
    subprocess.run(cmd_out, shell=True, capture_output=True)
    
    if res.returncode == 0:
        print(f"[+] Successfully applied Windows Firewall block rule for {client_ip}")
    else:
        print(f"[!] Direct netsh requires elevation ({res.stderr.strip()}). Invoking elevated PowerShell...")
        elevated_ps = (
            f'Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '
            f'\'-NoProfile -Command netsh advfirewall firewall add rule name="{rule_in}" dir=in action=block protocol=TCP localport={VNC_PORT} remoteip={client_ip}; '
            f'netsh advfirewall firewall add rule name="{rule_out}" dir=out action=block protocol=TCP remoteip={client_ip}\''
        )
        try:
            subprocess.run(["powershell", "-Command", elevated_ps], shell=True, capture_output=True, timeout=5)
            print(f"[+] Dispatched elevated firewall block for {client_ip}")
        except Exception as e:
            print(f"[ERROR] Failed to execute elevated firewall block: {e}")
            
    # 3. Disconnect sessions again to ensure no hanging packets
    disconnect_vnc_sessions()
    
    # 4. Record in database and audit log
    try:
        from database.db_manager import record_blocked_device
        record_blocked_device(client_ip, client_port, reason)
    except Exception as e:
        print(f"[!] Warning: could not record to db: {e}")
        
    try:
        log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{client_ip},{client_port},CRITICAL,BLOCK_VNC,{reason},ENFORCED\n"
        if not OUTPUT_FILE.exists():
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write("timestamp,client_ip,client_port,risk_level,action,reason,execution_status\n")
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception:
        pass
        
    return True, f"Device {client_ip} connection terminated and blocked at firewall."

def enforce_unblock(client_ip):
    """
    Removes Windows Firewall block rules and marks device unblocked in DB.
    """
    if not client_ip or client_ip in ["Unknown", "None"]:
        return False, "Invalid IP"
        
    rule_in = f"SmartVNC_Block_{client_ip}"
    rule_out = f"SmartVNC_Block_Out_{client_ip}"
    
    del_in = f'netsh advfirewall firewall delete rule name="{rule_in}"'
    del_out = f'netsh advfirewall firewall delete rule name="{rule_out}"'
    
    res = subprocess.run(del_in, shell=True, capture_output=True, text=True)
    subprocess.run(del_out, shell=True, capture_output=True)
    
    if res.returncode != 0:
        elevated_ps = (
            f'Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '
            f'\'-NoProfile -Command netsh advfirewall firewall delete rule name="{rule_in}"; '
            f'netsh advfirewall firewall delete rule name="{rule_out}"\''
        )
        try:
            subprocess.run(["powershell", "-Command", elevated_ps], shell=True, capture_output=True, timeout=5)
        except Exception:
            pass
            
    try:
        from database.db_manager import record_unblocked_device
        record_unblocked_device(client_ip)
    except Exception:
        pass
        
    print(f"[+] Device {client_ip} unblocked successfully.")
    return True, f"Device {client_ip} unblocked."

def is_ip_blocked(client_ip):
    """
    Checks if client_ip has an active block rule in DB or Windows Firewall.
    """
    if not client_ip or client_ip in ["Unknown", "None", "127.0.0.1", "localhost"]:
        return False
    try:
        from database.db_manager import is_device_blocked
        if is_device_blocked(client_ip):
            return True
    except Exception:
        pass
        
    # Check Windows Firewall
    try:
        res = subprocess.run(
            f'netsh advfirewall firewall show rule name="SmartVNC_Block_{client_ip}"',
            shell=True,
            capture_output=True,
            text=True,
            timeout=3
        )
        if "SmartVNC_Block" in res.stdout:
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
