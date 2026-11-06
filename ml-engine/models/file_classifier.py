import sys
import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "ml-engine"))

from database.db_manager import (
    DB_PATH,
    init_db,
    log_file_transfer,
    is_device_blocked
)
from vnc_prevention import enforce_block

# ============================================================
# SMARTVNC - FILE TRANSFER CLASSIFICATION & ACCESS ENGINE
# ============================================================
# Classifies file transfer requests as:
#   1. ACCESS_ALLOWED     -> Permitted according to server policy
#   2. ACCESS_NOT_ALLOWED -> Violation! Device is immediately blocked
# ============================================================

RESTRICTED_SYSTEM_PATHS = [
    "windows", "system32", "syswow64", "program files", "appdata",
    ".ssh", ".aws", "sam", "etc/passwd", "etc/shadow"
]

def get_server_policy_sets():
    """Queries SQLite directly for server-configured allowed and restricted policies."""
    allowed_exts = set()
    blocked_exts = set()
    blocked_keywords = set()

    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT policy_type, value, is_allowed FROM file_policies")
        for ptype, val, is_allowed in cursor.fetchall():
            ptype = str(ptype).upper()
            val = str(val).lower().strip()
            is_allowed = int(is_allowed)

            if ptype == "EXTENSION":
                if not val.startswith("."):
                    val = "." + val
                if is_allowed == 1:
                    allowed_exts.add(val)
                else:
                    blocked_exts.add(val)
            elif ptype == "KEYWORD":
                if is_allowed == 0:
                    blocked_keywords.add(val)
        conn.close()
    except Exception as e:
        print(f"[!] Warning fetching file policies: {e}")

    # Fallback safety defaults if policy table is unreachable
    if not allowed_exts:
        allowed_exts = {".txt", ".pdf", ".docx", ".png", ".jpg", ".csv"}
    if not blocked_exts:
        blocked_exts = {".exe", ".bat", ".sh", ".zip", ".rar", ".env", ".sql", ".key"}
    if not blocked_keywords:
        blocked_keywords = {"password", "secret", "confidential", "salary"}

    return allowed_exts, blocked_exts, blocked_keywords

def classify_file_transfer(
    file_name: str,
    client_ip: str,
    client_port: int = 0,
    file_path: str = "",
    file_size_bytes: int = 0
) -> dict:
    """
    Classifies a file transfer attempt based on server policies.
    If unauthorized (ACCESS_NOT_ALLOWED), the client device is blocked immediately.
    """
    if not file_name:
        return {
            "success": False,
            "error": "File name is required"
        }

    clean_name = Path(file_name).name
    ext = Path(clean_name).suffix.lower()
    lower_name = clean_name.lower()
    lower_path = str(file_path).lower().replace("\\", "/")

    # Fetch current server-defined policies
    allowed_exts, blocked_exts, blocked_keywords = get_server_policy_sets()

    classification = "ACCESS_ALLOWED"
    risk_score = 10.0
    reason = "File matches server allowed policy"

    # ------------------------------------------------------------
    # 1. Check Protected System Paths Traversal
    # ------------------------------------------------------------
    for sp in RESTRICTED_SYSTEM_PATHS:
        if sp in lower_path:
            classification = "ACCESS_NOT_ALLOWED"
            risk_score = 98.0
            reason = f"Access to sensitive system path '{sp}' is prohibited"
            break

    # ------------------------------------------------------------
    # 2. Check Prohibited Keywords in Filename
    # ------------------------------------------------------------
    if classification == "ACCESS_ALLOWED":
        for kw in blocked_keywords:
            if kw in lower_name:
                classification = "ACCESS_NOT_ALLOWED"
                risk_score = 95.0
                reason = f"Restricted sensitive keyword detected in filename: '{kw}'"
                break

    # ------------------------------------------------------------
    # 3. Check Explicitly Blocked Extensions
    # ------------------------------------------------------------
    if classification == "ACCESS_ALLOWED":
        if ext in blocked_exts:
            classification = "ACCESS_NOT_ALLOWED"
            risk_score = 90.0
            reason = f"Prohibited file extension '{ext}' (High Exfiltration Risk)"

    # ------------------------------------------------------------
    # 4. Check Allowed Whitelist
    # ------------------------------------------------------------
    if classification == "ACCESS_ALLOWED":
        if ext not in allowed_exts and ext != "":
            classification = "ACCESS_NOT_ALLOWED"
            risk_score = 85.0
            reason = f"Extension '{ext}' is not on the server-approved whitelist"
        else:
            classification = "ACCESS_ALLOWED"
            risk_score = 8.0
            reason = f"File '{clean_name}' ({ext}) is approved for access by server policy"

    # ------------------------------------------------------------
    # 5. Active Defense Enforcement for Not Allowed Files
    # ------------------------------------------------------------
    if classification == "ACCESS_NOT_ALLOWED":
        action_taken = "DEVICE_BLOCKED"
        block_reason = f"Unauthorized File Access: {reason} on '{clean_name}'"
        print("\n" + "!" * 70)
        print(f"[!] SMARTVNC SECURITY VIOLATION: Unauthorized file access by {client_ip}")
        print(f"    File: {clean_name}")
        print(f"    Reason: {reason}")
        print(f"    ACTION: Severing connection and blocking device {client_ip}!")
        print("!" * 70)

        # Sever socket and inject firewall block
        enforce_block(client_ip=client_ip, client_port=client_port, reason=block_reason)
    else:
        action_taken = "PERMITTED"

    # ------------------------------------------------------------
    # 6. Log File Transfer Record in Database
    # ------------------------------------------------------------
    transfer_record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": client_ip,
        "client_port": client_port,
        "file_name": clean_name,
        "file_path": file_path or clean_name,
        "file_size_bytes": file_size_bytes,
        "classification": classification,
        "risk_score": risk_score,
        "action_taken": action_taken,
        "reason": reason
    }

    try:
        log_file_transfer(transfer_record)
    except Exception as e:
        print(f"[!] Warning: could not log file transfer to db: {e}")

    return {
        "success": True,
        "client_ip": client_ip,
        "client_port": client_port,
        "file_name": clean_name,
        "file_size_bytes": file_size_bytes,
        "classification": classification,
        "risk_score": risk_score,
        "action_taken": action_taken,
        "reason": reason
    }

    # ------------------------------------------------------------
    # 1. Check Protected System Paths Traversal
    # ------------------------------------------------------------
    for sp in RESTRICTED_SYSTEM_PATHS:
        if sp in lower_path:
            classification = "ACCESS_NOT_ALLOWED"
            risk_score = 98.0
            reason = f"Access to sensitive system path '{sp}' is prohibited"
            break

    # ------------------------------------------------------------
    # 2. Check Prohibited Keywords in Filename
    # ------------------------------------------------------------
    if classification == "ACCESS_ALLOWED":
        for kw in blocked_keywords:
            if kw in lower_name:
                classification = "ACCESS_NOT_ALLOWED"
                risk_score = 95.0
                reason = f"Restricted sensitive keyword detected in filename: '{kw}'"
                break

    # ------------------------------------------------------------
    # 3. Check Explicitly Blocked Extensions
    # ------------------------------------------------------------
    if classification == "ACCESS_ALLOWED":
        if ext in blocked_exts:
            classification = "ACCESS_NOT_ALLOWED"
            risk_score = 90.0
            reason = f"Prohibited file extension '{ext}' (High Exfiltration Risk)"

    # ------------------------------------------------------------
    # 4. Check Allowed Whitelist
    # ------------------------------------------------------------
    if classification == "ACCESS_ALLOWED":
        if ext not in allowed_exts and ext != "":
            classification = "ACCESS_NOT_ALLOWED"
            risk_score = 85.0
            reason = f"Extension '{ext}' is not on the server-approved whitelist"
        else:
            classification = "ACCESS_ALLOWED"
            risk_score = 8.0
            reason = f"File '{clean_name}' ({ext}) is approved for access by server policy"

    # ------------------------------------------------------------
    # 5. Active Defense Enforcement for Not Allowed Files
    # ------------------------------------------------------------
    if classification == "ACCESS_NOT_ALLOWED":
        action_taken = "DEVICE_BLOCKED"
        block_reason = f"Unauthorized File Access: {reason} on '{clean_name}'"
        print("\n" + "!" * 70)
        print(f"[!] SMARTVNC SECURITY VIOLATION: Unauthorized file access by {client_ip}")
        print(f"    File: {clean_name}")
        print(f"    Reason: {reason}")
        print(f"    ACTION: Severing connection and blocking device {client_ip}!")
        print("!" * 70)

        # Sever socket and inject firewall block
        enforce_block(client_ip=client_ip, client_port=client_port, reason=block_reason)
    else:
        action_taken = "PERMITTED"

    # ------------------------------------------------------------
    # 6. Log File Transfer Record in Database
    # ------------------------------------------------------------
    transfer_record = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": client_ip,
        "client_port": client_port,
        "file_name": clean_name,
        "file_path": file_path or clean_name,
        "file_size_bytes": file_size_bytes,
        "classification": classification,
        "risk_score": risk_score,
        "action_taken": action_taken,
        "reason": reason
    }

    try:
        log_file_transfer(transfer_record)
    except Exception as e:
        print(f"[!] Warning: could not log file transfer to db: {e}")

    return {
        "success": True,
        "client_ip": client_ip,
        "client_port": client_port,
        "file_name": clean_name,
        "file_size_bytes": file_size_bytes,
        "classification": classification,
        "risk_score": risk_score,
        "action_taken": action_taken,
        "reason": reason
    }
