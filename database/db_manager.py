import sqlite3
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "database" / "smartvnc.db"

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
    cursor.execute('''
        UPDATE blocked_devices SET status = 'UNBLOCKED' WHERE client_ip = ?
    ''', (client_ip,))
    conn.commit()
    conn.close()

def is_device_blocked(client_ip):
    if not client_ip or client_ip in ["None", "Unknown", "127.0.0.1", "localhost"]:
        return False
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT status FROM blocked_devices WHERE client_ip = ? AND status = 'BLOCKED'
    ''', (client_ip,))
    row = cursor.fetchone()
    conn.close()
    return row is not None

def get_blocked_devices():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(
            "SELECT timestamp, client_ip, client_port, reason, status FROM blocked_devices WHERE status = 'BLOCKED' ORDER BY id DESC",
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
        query = f"SELECT * FROM alerts WHERE client_ip = ? ORDER BY id DESC LIMIT {limit}"
        df = pd.read_sql_query(query, conn, params=(client_ip,))
    else:
        query = f"SELECT * FROM alerts ORDER BY id DESC LIMIT {limit}"
        df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def get_high_risk_alerts(client_ip=None):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    if client_ip and client_ip not in ["None", "Unknown", "All Devices"]:
        query = "SELECT * FROM alerts WHERE risk_level IN ('HIGH', 'CRITICAL') AND client_ip = ? ORDER BY id DESC"
        df = pd.read_sql_query(query, conn, params=(client_ip,))
    else:
        query = "SELECT * FROM alerts WHERE risk_level IN ('HIGH', 'CRITICAL') ORDER BY id DESC"
        df = pd.read_sql_query(query, conn)
    conn.close()
    return df
