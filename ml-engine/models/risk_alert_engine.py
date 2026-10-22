import csv
from pathlib import Path
from datetime import datetime

from risk_predictor import predict_risk

# ============================================================
# SMARTVNC - RISK SCORING AND ALERT ENGINE
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

RISK_DIR = (
    BASE_DIR
    / "datasets"
    / "risk"
)

RISK_DIR.mkdir(
    parents=True,
    exist_ok=True
)

ALERT_FILE = (
    RISK_DIR
    / "smartvnc_alerts.csv"
)

# ============================================================
# RISK RESPONSE RULES
# ============================================================

def get_recommended_action(risk_level):

    if risk_level == "LOW":
        return "MONITOR"

    elif risk_level == "MEDIUM":
        return "MONITOR"

    elif risk_level == "HIGH":
        return "ALERT_AND_LOG"

    elif risk_level == "CRITICAL":
        return "TERMINATE_AND_BLOCK"

    return "MONITOR"


import sys
import threading
import time
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "ml-engine"))
from database.db_manager import log_alert

_last_notification_time = 0
_auto_blocked_ips = set()

def clear_blocked_cache(client_ip=None):
    global _auto_blocked_ips
    if client_ip:
        _auto_blocked_ips.discard(client_ip)
    else:
        _auto_blocked_ips.clear()

def _trigger_automated_block(client_ip, client_port, risk_score):
    global _auto_blocked_ips
    if client_ip in _auto_blocked_ips:
        return
    _auto_blocked_ips.add(client_ip)

    def _worker():
        try:
            from vnc_prevention import enforce_block
            enforce_block(
                client_ip=client_ip,
                client_port=client_port,
                reason=f"Automated Defense: CRITICAL exfiltration risk ({risk_score:.2f}%)"
            )
            _safe_os_notify(
                title=f"SMARTVNC ACTIVE DEFENSE: {client_ip}",
                message=f"CRITICAL risk ({risk_score:.2f}%) detected! Active VNC connection severed and device blocked at firewall."
            )
        except Exception as e:
            print(f"[ERROR] Automated block worker error: {e}")

    threading.Thread(target=_worker, daemon=True).start()

def _safe_os_notify(title, message):
    global _last_notification_time
    now = time.time()
    if now - _last_notification_time < 10.0:
        return
    _last_notification_time = now

    def _worker():
        try:
            from plyer import notification
            notification.notify(
                title=title,
                message=message,
                app_name="SmartVNC",
                timeout=5
            )
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()

# ============================================================
# SAVE ALERT
# ============================================================

def save_alert(
    result,
    session_duration,
    forward_packets,
    backward_packets,
    bytes_per_second,
    packets_per_second,
    protocol,
    client_ip,
    client_port=0
):
    alert_data = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'client_ip': client_ip,
        'client_port': int(client_port),
        'session_duration': session_duration,
        'forward_packets': forward_packets,
        'backward_packets': backward_packets,
        'bytes_per_second': bytes_per_second,
        'packets_per_second': packets_per_second,
        'protocol': protocol,
        'prediction': result["prediction"],
        'status': result["status"],
        'normal_probability': result["normal_probability"],
        'threat_probability': result["threat_probability"],
        'risk_score': result["risk_score"],
        'risk_level': result["risk_level"],
        'recommended_action': get_recommended_action(result["risk_level"])
    }
    
    # Save to SQLite DB
    log_alert(alert_data)
    
    # OS Notification for the user (non-blocking daemon thread with 10s cooldown)
    if alert_data['risk_level'] == 'CRITICAL':
        _safe_os_notify(
            title=f"SMARTVNC: CRITICAL EXFILTRATION DETECTED",
            message=f"Risk Score {result['risk_score']:.2f}%. Terminating connection and blocking device {client_ip}."
        )
    elif alert_data['risk_level'] == 'HIGH':
        _safe_os_notify(
            title=f"SMARTVNC SECURITY: HIGH RISK",
            message=f"Elevated risk activity detected ({result['risk_score']:.2f}% risk) on {client_ip}. Monitoring closely."
        )


# ============================================================
# PROCESS NETWORK SESSION
# ============================================================

def process_session(

    session_duration,
    forward_packets,
    backward_packets,
    bytes_per_second,
    packets_per_second,
    protocol,
    client_ip="Unknown",
    client_port=0
):

    # --------------------------------------------------------
    # Run ML prediction
    # --------------------------------------------------------

    result = predict_risk(

        session_duration=session_duration,

        forward_packets=forward_packets,

        backward_packets=backward_packets,

        bytes_per_second=bytes_per_second,

        packets_per_second=packets_per_second,

        protocol=protocol
    )

    # --------------------------------------------------------
    # Determine security action
    # --------------------------------------------------------

    action = get_recommended_action(
        result["risk_level"]
    )

    # --------------------------------------------------------
    # AUTOMATED ACTIVE DEFENSE FOR CRITICAL RISK
    # --------------------------------------------------------
    if result["risk_level"] == "CRITICAL" and client_ip and client_ip not in ["Unknown", "None", "127.0.0.1", "localhost"]:
        _trigger_automated_block(client_ip, client_port, result["risk_score"])

    # --------------------------------------------------------
    # Save alert/detection (ONLY IF ACTION != MONITOR)
    # --------------------------------------------------------

    if action != "MONITOR":
        save_alert(
            result,
            session_duration,
            forward_packets,
            backward_packets,
            bytes_per_second,
            packets_per_second,
            protocol,
            client_ip,
            client_port
        )

    # --------------------------------------------------------
    # Return complete result
    # --------------------------------------------------------

    result["recommended_action"] = action

    return result


# ============================================================
# DISPLAY SECURITY ALERT
# ============================================================

def display_alert(result):

    print("\n")
    print("=" * 70)
    print("SMARTVNC SECURITY ALERT")
    print("=" * 70)

    print(
        f"\nStatus               : "
        f"{result['status']}"
    )

    print(
        f"Prediction           : "
        f"{result['prediction']}"
    )

    print(
        f"Normal Probability   : "
        f"{result['normal_probability']:.2f}%"
    )

    print(
        f"Threat Probability   : "
        f"{result['threat_probability']:.2f}%"
    )

    print(
        f"Risk Score           : "
        f"{result['risk_score']:.2f}/100"
    )

    print(
        f"Risk Level           : "
        f"{result['risk_level']}"
    )

    print(
        f"Recommended Action   : "
        f"{result['recommended_action']}"
    )

    print("\n" + "=" * 70)


# ============================================================
# TEST SMARTVNC ALERT ENGINE
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("SMARTVNC - RISK SCORING AND ALERT ENGINE")
    print("=" * 70)

    print("\nProcessing test network session...")

    # --------------------------------------------------------
    # Test network session
    # --------------------------------------------------------

    result = process_session(

        session_duration=120.0,

        forward_packets=150,

        backward_packets=100,

        bytes_per_second=50000,

        packets_per_second=20,

        protocol=6
    )

    # --------------------------------------------------------
    # Display result
    # --------------------------------------------------------

    display_alert(result)

    print("\nAlert record saved to:")

    print(ALERT_FILE)

    print("\n" + "=" * 70)
    print("SMARTVNC ALERT ENGINE TEST COMPLETED")
    print("=" * 70)