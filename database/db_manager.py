import sqlite3
try:
    import pandas as pd
except ImportError:
    pd = None
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]

def get_db_path():
    candidates = [
        BASE_DIR / "database" / "smartvnc.db",
        BASE_DIR.parent / "database" / "smartvnc.db",
        BASE_DIR / "SmartVNC" / "database" / "smartvnc.db",
    ]
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]

DB_PATH = get_db_path()

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            client_port INTEGER DEFAULT 0,
            session_duration REAL,
            forward_packets INTEGER,
            backward_packets INTEGER,
            bytes_per_second REAL,
            packets_per_second REAL,
            protocol INTEGER,
            prediction INTEGER,
            status TEXT,
            normal_probability REAL,
            threat_probability REAL,
            risk_score REAL,
            risk_level TEXT,
            recommended_action TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT UNIQUE,
            client_port INTEGER DEFAULT 0,
            reason TEXT,
            status TEXT DEFAULT 'BLOCKED'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_type TEXT,
            value TEXT UNIQUE,
            is_allowed INTEGER,
            description TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            client_port INTEGER DEFAULT 0,
            file_name TEXT,
            file_path TEXT,
            file_size_bytes INTEGER DEFAULT 0,
            classification TEXT,
            risk_score REAL,
            action_taken TEXT,
            reason TEXT
        )
    ''')
    
    # Seed default file transfer access policies if table is empty
    cursor.execute("SELECT COUNT(*) FROM file_policies")
    if cursor.fetchone()[0] == 0:
        default_policies = [
            # Allowed file extensions
            ("EXTENSION", ".txt", 1, "Plain Text Documents"),
            ("EXTENSION", ".pdf", 1, "PDF Documents"),
            ("EXTENSION", ".docx", 1, "Office Word Documents"),
            ("EXTENSION", ".png", 1, "PNG Images"),
            ("EXTENSION", ".jpg", 1, "JPEG Images"),
            ("EXTENSION", ".csv", 1, "Data Spreadsheets"),
            # Not allowed / blocked extensions
            ("EXTENSION", ".exe", 0, "Executable Binaries (Restricted)"),
            ("EXTENSION", ".bat", 0, "Batch Shell Scripts (Restricted)"),
            ("EXTENSION", ".zip", 0, "Compressed Archives (Restricted)"),
            ("EXTENSION", ".env", 0, "Environment & Secret Files (Restricted)"),
            ("EXTENSION", ".sql", 0, "Database Dumps & Scripts (Restricted)"),
            ("EXTENSION", ".key", 0, "Cryptographic Private Keys (Restricted)"),
            # Not allowed sensitive keywords in filename
            ("KEYWORD", "password", 0, "Credential / Password Keywords"),
            ("KEYWORD", "secret", 0, "Sensitive / Secret Data"),
            ("KEYWORD", "confidential", 0, "Confidential Company Assets"),
            ("KEYWORD", "salary", 0, "Payroll & Financial Records")
        ]
        cursor.executemany(
            "INSERT OR IGNORE INTO file_policies (policy_type, value, is_allowed, description) VALUES (?, ?, ?, ?)",
            default_policies
        )
        
    conn.commit()
    conn.close()

def log_alert(alert_data):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO alerts (
            timestamp, client_ip, client_port, session_duration, forward_packets, backward_packets,
            bytes_per_second, packets_per_second, protocol, prediction,
            status, normal_probability, threat_probability, risk_score,
            risk_level, recommended_action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        alert_data['timestamp'],
        alert_data.get('client_ip', 'Unknown'),
        int(alert_data.get('client_port', 0)),
        float(alert_data['session_duration']),
        int(alert_data['forward_packets']),
        int(alert_data['backward_packets']),
        float(alert_data['bytes_per_second']),
        float(alert_data['packets_per_second']),
        int(alert_data['protocol']),
        int(alert_data['prediction']),
        alert_data['status'],
        float(alert_data['normal_probability']),
        float(alert_data['threat_probability']),
        float(alert_data['risk_score']),
        alert_data['risk_level'],
        alert_data['recommended_action']
    ))
    conn.commit()
    conn.close()

def record_blocked_device(client_ip, client_port=0, reason="Critical Exfiltration Risk"):
    from datetime import datetime
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO blocked_devices (timestamp, client_ip, client_port, reason, status)
        VALUES (?, ?, ?, ?, 'BLOCKED')
        ON CONFLICT(client_ip) DO UPDATE SET
            timestamp = excluded.timestamp,
            client_port = excluded.client_port,
            reason = excluded.reason,
            status = 'BLOCKED'
    ''', (now, client_ip, int(client_port), reason))
    conn.commit()
    conn.close()

def record_unblocked_device(client_ip):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE blocked_devices SET status = 'UNBLOCKED' WHERE client_ip = ?",
        (client_ip,),
    )
    conn.commit()
    conn.close()

def is_device_blocked(client_ip):
    if not client_ip or client_ip in [
        "None",
        "Unknown",
        "127.0.0.1",
        "localhost",
    ]:
        return False
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM blocked_devices "
        "WHERE client_ip = ? AND status = 'BLOCKED' LIMIT 1",
        (client_ip,),
    )
    row = cursor.fetchone()
    conn.close()
    return row is not None

def get_blocked_devices():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(
            "SELECT timestamp, client_ip, client_port, reason, status "
            "FROM blocked_devices WHERE status = 'BLOCKED' ORDER BY id DESC",
            conn
        )
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df

def get_recent_alerts(limit=5, client_ip=None):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    if client_ip and client_ip not in ["None", "Unknown", "All Devices"]:
        query = (
            "SELECT * FROM alerts WHERE client_ip = ? "
            f"ORDER BY id DESC LIMIT {int(limit)}"
        )
        params = (client_ip,)
        df = pd.read_sql_query(query, conn, params=params)
    else:
        query = f"SELECT * FROM alerts ORDER BY id DESC LIMIT {int(limit)}"
        df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def get_high_risk_alerts(client_ip=None):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    if client_ip and client_ip not in ["None", "Unknown", "All Devices"]:
        query = (
            "SELECT * FROM alerts WHERE risk_level IN ('HIGH', 'CRITICAL') "
            "AND client_ip = ? ORDER BY id DESC"
        )
        params = (client_ip,)
        df = pd.read_sql_query(query, conn, params=params)
    else:
        query = "SELECT * FROM alerts WHERE risk_level IN ('HIGH', 'CRITICAL') ORDER BY id DESC"
        df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# ============================================================
# FILE TRANSFER ACCESS POLICY & LOGGING
# ============================================================

def get_file_policies():
    """Retrieve all server-configured file transfer policies."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(
            "SELECT id, policy_type, value, is_allowed, description FROM file_policies ORDER BY is_allowed DESC, policy_type, value",
            conn
        )
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df

def add_file_policy(policy_type, value, is_allowed, description=""):
    """Add or update an allowed/restricted file policy rule."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO file_policies (policy_type, value, is_allowed, description)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(value) DO UPDATE SET
            policy_type = excluded.policy_type,
            is_allowed = excluded.is_allowed,
            description = excluded.description
    ''', (policy_type.upper().strip(), value.lower().strip(), int(is_allowed), description.strip()))
    conn.commit()
    conn.close()

def delete_file_policy(policy_id):
    """Delete a file policy rule by ID."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM file_policies WHERE id = ?", (int(policy_id),))
    conn.commit()
    conn.close()

def log_file_transfer(transfer_data):
    """Record a file transfer evaluation and action taken."""
    from datetime import datetime
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO file_transfers (
            timestamp, client_ip, client_port, file_name, file_path,
            file_size_bytes, classification, risk_score, action_taken, reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        transfer_data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        transfer_data.get('client_ip', 'Unknown'),
        int(transfer_data.get('client_port', 0)),
        transfer_data.get('file_name', ''),
        transfer_data.get('file_path', ''),
        int(transfer_data.get('file_size_bytes', 0)),
        transfer_data.get('classification', 'ACCESS_NOT_ALLOWED'),
        float(transfer_data.get('risk_score', 0.0)),
        transfer_data.get('action_taken', 'DEVICE_BLOCKED'),
        transfer_data.get('reason', '')
    ))
    conn.commit()
    conn.close()

def get_recent_file_transfers(limit=10, client_ip=None):
    """Retrieve recent file transfer activity logs."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        if client_ip and client_ip not in ["None", "Unknown", "All Devices"]:
            query = (
                "SELECT id, timestamp, client_ip, client_port, file_name, file_size_bytes, "
                "classification, risk_score, action_taken, reason "
                "FROM file_transfers WHERE client_ip = ? ORDER BY id DESC LIMIT ?"
            )
            df = pd.read_sql_query(query, conn, params=(client_ip, int(limit)))
        else:
            query = (
                "SELECT id, timestamp, client_ip, client_port, file_name, file_size_bytes, "
                "classification, risk_score, action_taken, reason "
                "FROM file_transfers ORDER BY id DESC LIMIT ?"
            )
            df = pd.read_sql_query(query, conn, params=(int(limit),))
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df
