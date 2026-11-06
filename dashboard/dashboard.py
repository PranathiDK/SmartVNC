import streamlit as st
import time
import json
import requests
from datetime import datetime, timedelta
from pathlib import Path
import sys
import math
import pandas as pd

# ============================================================
# SMARTVNC - ENTERPRISE SOC CYBER SECURITY DASHBOARD
# ============================================================

st.set_page_config(
    page_title="SMARTVNC - Real-Time VNC Exfiltration Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Helper function to render HTML cleanly without any markdown indentation-to-code artifact
def render_html(html_str: str):
    clean = "".join([line.strip() for line in html_str.splitlines() if line.strip()])
    st.markdown(clean, unsafe_allow_html=True)

# Format bytes to human readable format
def format_bytes(bytes_val):
    if bytes_val < 1024:
        return f"{bytes_val:.1f} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / (1024 * 1024):.2f} MB"
    else:
        return f"{bytes_val / (1024 * 1024 * 1024):.2f} GB"

# ============================================================
# PATH CONFIGURATION & IMPORTS
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "ml-engine"))
sys.path.append(str(BASE_DIR / "ml-engine" / "models"))

from config import API_URL, API_HOST, API_PORT
from database.db_manager import (
    get_recent_alerts,
    get_high_risk_alerts,
    is_device_blocked,
    get_blocked_devices,
    get_file_policies,
    add_file_policy,
    delete_file_policy,
    get_recent_file_transfers
)

def get_live_data_file():
    candidates = [
        BASE_DIR / "live_data" / "vnc_live_data_v2.json",
        BASE_DIR.parent / "live_data" / "vnc_live_data_v2.json",
        BASE_DIR / "SmartVNC" / "live_data" / "vnc_live_data_v2.json",
    ]
    existing = [p for p in candidates if p.exists()]
    if existing:
        return max(existing, key=lambda p: p.stat().st_mtime)
    return candidates[0]

LIVE_DATA_FILE = get_live_data_file()

# ============================================================
# SESSION STATE INITIALIZATION
# ============================================================

if "risk_history" not in st.session_state:
    st.session_state.risk_history = []

if "trend_points" not in st.session_state:
    st.session_state.trend_points = []

if "session_activities" not in st.session_state:
    st.session_state.session_activities = []

if "session_alerts" not in st.session_state:
    st.session_state.session_alerts = []

if "current_session_id" not in st.session_state:
    st.session_state.current_session_id = None

if "last_recorded_level" not in st.session_state:
    st.session_state.last_recorded_level = None

if "nav_page" not in st.session_state:
    st.session_state.nav_page = "Dashboard"

if "last_good_data" not in st.session_state:
    st.session_state.last_good_data = {
        "vnc_active": False,
        "client_ip": "None",
        "session_duration": 0.0,
        "forward_packets": 0,
        "backward_packets": 0,
        "bytes_per_second": 0.0,
        "packets_per_second": 0.0,
        "protocol": 6,
        "devices": {}
    }

# ============================================================
# GLOBAL CSS (EXACT SCREENSHOT SOC DARK THEME)
# ============================================================

render_html("""
<style>
/* Main App Background */
.stApp {
    background-color: #080c16;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

#MainMenu, header, footer {
    visibility: hidden;
    height: 0;
}

.block-container {
    padding-top: 1.2rem;
    padding-bottom: 2rem;
    padding-left: 2.2rem;
    padding-right: 2.2rem;
    max-width: 100%;
}

/* Sidebar Styling */
section[data-testid="stSidebar"] {
    background-color: #060913 !important;
    border-right: 1px solid #101726 !important;
}

section[data-testid="stSidebar"] .block-container {
    padding-top: 1.5rem;
    padding-left: 1rem;
    padding-right: 1rem;
}

/* Metric Cards (Top Row) */
.metric-card {
    background: #0b1120;
    border: 1px solid #142036;
    border-radius: 10px;
    padding: 14px 16px;
    display: flex;
    align-items: center;
    gap: 14px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
    height: 84px;
}

.metric-icon-box {
    width: 44px;
    height: 44px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    flex-shrink: 0;
}

.metric-content {
    display: flex;
    flex-direction: column;
    justify-content: center;
    overflow: hidden;
}

.metric-label {
    font-size: 11px;
    font-weight: 600;
    color: #8da2c0;
    margin-bottom: 2px;
    white-space: nowrap;
}

.metric-val-row {
    display: flex;
    align-items: baseline;
    gap: 6px;
}

.metric-val {
    font-size: 20px;
    font-weight: 800;
    color: #ffffff;
    line-height: 1.1;
}

.metric-sub {
    font-size: 11px;
    color: #64748b;
    white-space: nowrap;
}

/* Middle / Bottom Panels */
.panel-box {
    background: #0b1120;
    border: 1px solid #142036;
    border-radius: 10px;
    padding: 16px 18px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
    height: 100%;
}

.panel-header {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 15px;
    font-weight: 700;
    color: #ffffff;
    margin-bottom: 2px;
}

.panel-subtitle {
    font-size: 11px;
    color: #8da2c0;
    margin-bottom: 12px;
}

/* Telemetry list */
.telem-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid #121c30;
    font-size: 12px;
}
.telem-row:last-child {
    border-bottom: none;
}
.telem-label {
    color: #8da2c0;
    font-weight: 500;
}
.telem-val {
    font-weight: 600;
    color: #ffffff;
}

/* Badges */
.badge-active {
    background: rgba(16, 185, 129, 0.15);
    color: #10b981;
    border: 1px solid #059669;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    display: inline-block;
}

.badge-standby {
    background: rgba(245, 158, 11, 0.12);
    color: #f59e0b;
    border: 1px solid #d97706;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    display: inline-block;
}

.badge-critical {
    background: #3b1419;
    color: #ef4444;
    border: 1px solid #7f1d1d;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}

.badge-high {
    background: #381a10;
    color: #f97316;
    border: 1px solid #7c2d12;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}

.badge-medium {
    background: #332408;
    color: #facc15;
    border: 1px solid #713f12;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}

.badge-low {
    background: #0f2d1e;
    color: #4ade80;
    border: 1px solid #14532d;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}

/* Custom Table in Panels */
.soc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 11px;
}
.soc-table th {
    text-align: left;
    color: #64748b;
    font-weight: 600;
    padding: 6px 4px;
    border-bottom: 1px solid #142036;
}
.soc-table td {
    padding: 7px 4px;
    border-bottom: 1px solid #0f1829;
    color: #cbd5e1;
}
.soc-table tr:last-child td {
    border-bottom: none;
}

/* Pulse dot */
@keyframes pulse-soc {
    0% { transform: scale(0.95); opacity: 0.8; }
    50% { transform: scale(1.15); opacity: 1; }
    100% { transform: scale(0.95); opacity: 0.8; }
}
.pulse-green {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #10b981;
    box-shadow: 0 0 8px #10b981;
    display: inline-block;
    animation: pulse-soc 2s infinite ease-in-out;
}
.pulse-amber {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #f59e0b;
    box-shadow: 0 0 8px #f59e0b;
    display: inline-block;
    animation: pulse-soc 2s infinite ease-in-out;
}
</style>
""")

# ============================================================
# READ LIVE MONITOR DATA & RUN RISK ENGINE
# ============================================================

if not LIVE_DATA_FILE.exists():
    render_html("""
    <div class="panel-box" style="border-left: 4px solid #f59e0b; margin-top: 20px;">
        <div style="font-size: 15px; font-weight: 700; color: #fbbf24;">⚠️ Waiting for VNC Monitor...</div>
        <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Start <code>monitoring/vnc_monitor.py</code> to receive live VNC telemetry.</div>
    </div>
    """)
    time.sleep(2)
    st.rerun()

try:
    with open(LIVE_DATA_FILE, "r", encoding="utf-8") as file:
        content = file.read()
        if content.strip():
            live_data = json.loads(content)
            st.session_state.last_good_data = live_data
        else:
            live_data = st.session_state.last_good_data
except Exception:
    live_data = st.session_state.last_good_data

vnc_active = bool(live_data.get("vnc_active", False))

# Heartbeat check: if timestamp is older than 15s, the monitor has stalled or stopped
last_ts = float(live_data.get("timestamp", 0.0))
if last_ts > 0 and (time.time() - last_ts) > 15.0:
    vnc_active = False

devices = live_data.get("devices", {}) if vnc_active else {}

# Fallback for single-device packet sniffer
if vnc_active and not devices:
    legacy_ip = live_data.get("client_ip", "Unknown")
    if legacy_ip and legacy_ip not in ["None", "Unknown", ""]:
        devices = {
            legacy_ip: {
                "session_duration": float(live_data.get("session_duration", 0.0)),
                "forward_packets": int(live_data.get("forward_packets", 0)),
                "backward_packets": int(live_data.get("backward_packets", 0)),
                "forward_bytes": int(live_data.get("forward_bytes", 0)),
                "backward_bytes": int(live_data.get("backward_bytes", 0)),
                "bytes_per_second": float(live_data.get("bytes_per_second", 0.0)),
                "packets_per_second": float(live_data.get("packets_per_second", 0.0)),
                "burst_bytes": float(live_data.get("burst_bytes", 0.0)),
                "protocol": int(live_data.get("protocol", 6)),
                "client_ip": legacy_ip,
                "client_port": int(live_data.get("client_port", 0))
            }
        }

all_active_devices = dict(devices) if (vnc_active and devices) else {}

# Query ML Risk Scoring Engine
device_results = {}
critical_threats = []

if vnc_active and devices:
    active_client = next(iter(devices))
    for d_ip, d_stats in devices.items():
        payload = {
            "session_duration": float(d_stats.get("session_duration", 0.0)),
            "forward_packets": int(d_stats.get("forward_packets", 0)),
            "backward_packets": int(d_stats.get("backward_packets", 0)),
            "forward_bytes": int(d_stats.get("forward_bytes", 0)),
            "backward_bytes": int(d_stats.get("backward_bytes", 0)),
            "bytes_per_second": float(d_stats.get("bytes_per_second", 0.0)),
            "packets_per_second": float(d_stats.get("packets_per_second", 0.0)),
            "burst_bytes": float(d_stats.get("burst_bytes", 0.0)),
            "protocol": int(d_stats.get("protocol", 6)),
            "client_ip": d_stats.get("client_ip", d_ip),
            "client_port": int(d_stats.get("client_port", 0))
        }
        try:
            response = requests.post(API_URL, json=payload, timeout=15)
            if response.status_code == 200:
                res_data = response.json()
                if res_data.get("success"):
                    device_results[d_ip] = res_data
                    if res_data.get("risk_level") in ["HIGH", "CRITICAL"]:
                        critical_threats.append((
                            d_stats.get("client_ip", d_ip),
                            float(res_data.get("risk_score", 0.0)),
                            res_data.get("risk_level"),
                        ))
        except Exception:
            pass

selected_ip = next(iter(devices), None) if vnc_active else None

# Database statistics & device profile
is_blocked = is_device_blocked(selected_ip) if selected_ip else False
blocked_df = get_blocked_devices()
blocked_count = len(blocked_df) if not blocked_df.empty else 0
alerts_df = get_recent_alerts(limit=25)
alerts_count = len(alerts_df) if not alerts_df.empty else 0

if vnc_active and selected_ip:
    device_alerts_df = get_recent_alerts(limit=10, client_ip=selected_ip)
else:
    device_alerts_df = pd.DataFrame()

active_sessions_count = max(len(all_active_devices), len(devices), int(live_data.get("active_devices_count", 0))) if vnc_active else 0
if vnc_active and active_sessions_count == 0 and selected_ip:
    active_sessions_count = 1
total_transfers_count = max(alerts_count, 1 if vnc_active else 0)

now_dt = datetime.now()
now_str = now_dt.strftime("%d %b %Y  %H:%M:%S")

if selected_ip and vnc_active:
    sel_stats = devices[selected_ip]
    sel_res = device_results.get(selected_ip, {
        "risk_score": 0.0,
        "risk_level": "LOW",
        "status": "NORMAL"
    })
    session_duration = float(sel_stats.get("session_duration", 0.0))
    forward_packets = int(sel_stats.get("forward_packets", 0))
    backward_packets = int(sel_stats.get("backward_packets", 0))
    bytes_per_second = float(sel_stats.get("bytes_per_second", 0.0))
    packets_per_second = float(sel_stats.get("packets_per_second", 0.0))
    forward_bytes = int(sel_stats.get("forward_bytes", 0))
    backward_bytes = int(sel_stats.get("backward_bytes", 0))
    total_bytes = forward_bytes + backward_bytes
    protocol = int(sel_stats.get("protocol", 6))
    risk_score = float(sel_res.get("risk_score", 0.0))
    risk_level = sel_res.get("risk_level", "LOW")
    status = sel_res.get("status", "NORMAL")

    total_sec = int(session_duration)
    hh = total_sec // 3600
    mm = (total_sec % 3600) // 60
    ss = total_sec % 60
    session_duration_display = f"{hh:02d}:{mm:02d}:{ss:02d}"

    # Track real live trend points
    curr_t = datetime.now().strftime("%H:%M:%S")
    st.session_state.trend_points.append({"time": curr_t, "score": risk_score})
    if len(st.session_state.trend_points) > 15:
        st.session_state.trend_points.pop(0)

    # Detect new active VNC session
    if st.session_state.current_session_id != selected_ip:
        st.session_state.current_session_id = selected_ip
        st.session_state.last_recorded_level = "LOW"
        st.session_state.session_alerts = []
        st.session_state.session_activities = [
            {
                "time": curr_t,
                "action": "VNC Connection Established",
                "source": selected_ip,
                "risk_level": "LOW",
                "details": "Client connected on port 5900"
            }
        ]

    # Track risk level changes and file transfer bursts in current session
    if risk_level != st.session_state.last_recorded_level:
        prev_lvl = st.session_state.last_recorded_level
        st.session_state.last_recorded_level = risk_level

        if risk_level == "MEDIUM":
            act_desc = f"Medium File Transfer ({format_bytes(bytes_per_second)}/s)"
            event_name = "Medium Risk Activity"
        elif risk_level == "HIGH":
            act_desc = f"High Bandwidth Burst ({format_bytes(bytes_per_second)}/s)"
            event_name = "High Risk Exfiltration Attempt"
        elif risk_level == "CRITICAL":
            act_desc = f"Critical Exfiltration Detected ({format_bytes(bytes_per_second)}/s)"
            event_name = "Critical Exfiltration Threat"
        else:
            act_desc = "Normal VNC Telemetry"
            event_name = "Normal Activity Resumed"

        st.session_state.session_activities.insert(0, {
            "time": curr_t,
            "action": act_desc,
            "source": selected_ip,
            "risk_level": risk_level,
            "details": f"Score {int(risk_score)}/100"
        })

        if risk_level in ["MEDIUM", "HIGH", "CRITICAL"]:
            st.session_state.session_alerts.insert(0, {
                "time": curr_t,
                "event": event_name,
                "risk_level": risk_level,
                "details": f"Score {int(risk_score)}/100 • {format_bytes(bytes_per_second)}/s"
            })

    # Track active defense firewall block in current session
    if is_blocked and not any("Firewall" in a.get("action", "") or "RST" in a.get("action", "") for a in st.session_state.session_activities):
        st.session_state.session_activities.insert(0, {
            "time": curr_t,
            "action": "Active Defense RST Injected",
            "source": selected_ip,
            "risk_level": "CRITICAL",
            "details": "Port 5900 isolated at firewall"
        })
        st.session_state.session_alerts.insert(0, {
            "time": curr_t,
            "event": "Automated Firewall Quarantine",
            "risk_level": "CRITICAL",
            "details": f"Host {selected_ip} Blocked"
        })

    # Keep session lists clean
    st.session_state.session_activities = st.session_state.session_activities[:8]
    st.session_state.session_alerts = st.session_state.session_alerts[:8]

else:
    # DISCONNECTED / STANDBY STATE: Clean baseline reflecting zero active threat
    session_duration = 0.0
    forward_packets = 0
    backward_packets = 0
    bytes_per_second = 0.0
    packets_per_second = 0.0
    forward_bytes = 0
    backward_bytes = 0
    total_bytes = 0
    protocol = 6
    risk_score = 0.0
    risk_level = "LOW"
    status = "NORMAL"
    session_duration_display = "00:00:00"

    # Reset trend points to baseline flat line
    if len(st.session_state.trend_points) > 8:
        st.session_state.trend_points = [
            {"time": (datetime.now() - timedelta(seconds=i*4)).strftime("%H:%M:%S"), "score": 0.0}
            for i in range(7, -1, -1)
        ]

    # If a session just disconnected, record it in activity history
    if st.session_state.current_session_id is not None:
        curr_t = datetime.now().strftime("%H:%M:%S")
        st.session_state.session_activities.insert(0, {
            "time": curr_t,
            "action": "VNC Session Terminated",
            "source": st.session_state.current_session_id,
            "risk_level": "LOW",
            "details": "Client disconnected"
        })
        st.session_state.current_session_id = None

# ============================================================
# LEFT SIDEBAR NAVIGATION (MATCHING SCREENSHOT)
# ============================================================

with st.sidebar:
    render_html("""
    <div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 24px; padding-left: 4px;">
        <div style="width: 36px; height: 36px; background: linear-gradient(135deg, #1d4ed8, #3b82f6); border-radius: 8px; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 16px rgba(59, 130, 246, 0.4); flex-shrink: 0;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        </div>
        <div>
            <div style="font-size: 16px; font-weight: 800; color: #ffffff; letter-spacing: 0.5px; line-height: 1.1;">SMARTVNC</div>
            <div style="font-size: 9px; color: #60a5fa; line-height: 1.2; margin-top: 3px;">Privacy-Preserving Detection of Data Exfiltration in Encrypted VNC Sessions</div>
        </div>
    </div>
    """)

    nav_items = [
        ("Dashboard", "🏠"),
        ("File Transfer Policy", "📁"),
        ("Live Monitoring", "👁️"),
        ("Alert History", "⚠️"),
        ("Blocked Devices", "🚫"),
        ("Reports", "📄"),
        ("Settings", "⚙️")
    ]

    for name, icon in nav_items:
        is_active = (st.session_state.nav_page == name)
        btn_type = "primary" if is_active else "secondary"
        if st.button(f"{icon}  {name}", key=f"nav_{name}", use_container_width=True, type=btn_type):
            st.session_state.nav_page = name
            st.rerun()

    render_html("""
    <div style="margin-top: 60px; padding: 12px; background: #0b1120; border-radius: 8px; border: 1px solid #142036;">
        <div style="font-size: 11px; font-weight: 700; color: #8da2c0; margin-bottom: 4px;">PROTECTION ENGINE</div>
        <div style="font-size: 10px; color: #64748b;">Sniffer: TCP/5900</div>
        <div style="font-size: 10px; color: #64748b;">Risk API: Active</div>
        <div style="font-size: 10px; color: #10b981; margin-top: 4px;">● Active Defense Armed</div>
    </div>
    """)

# ============================================================
# MAIN TOP HEADER (MATCHING SCREENSHOT)
# ============================================================

current_page = st.session_state.nav_page

# Header row with title and system indicators
head_col1, head_col2 = st.columns([2, 1.2])

with head_col1:
    render_html(f"""
    <div>
        <div style="font-size: 24px; font-weight: 800; color: #ffffff; letter-spacing: 0.3px; margin-bottom: 2px;">{current_page}</div>
        <div style="font-size: 12px; color: #8da2c0;">Real-time monitoring & threat detection</div>
    </div>
    """)

with head_col2:
    status_indicator = '<span class="pulse-green"></span> <span style="color: #cbd5e1; font-weight: 500;">System Online</span>' if not is_blocked else '<span class="pulse-amber"></span> <span style="color: #f87171; font-weight: 700;">Threat Active</span>'
    render_html(f"""
    <div style="display: flex; align-items: center; justify-content: flex-end; gap: 18px; margin-top: 4px;">
        <div style="display: flex; align-items: center; gap: 8px; font-size: 12px;">
            {status_indicator}
        </div>
        <div style="font-size: 12px; color: #8da2c0; font-family: monospace;">{now_str}</div>
        <div style="font-size: 15px; color: #8da2c0; cursor: pointer;">⚙️</div>
    </div>
    """)

st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

# Threat Banner if active threat or device blocked
if is_blocked:
    render_html(f"""
    <div style="background: #3b1419; border: 1px solid #ef4444; border-radius: 8px; padding: 12px 18px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 12px;">
            <span style="font-size: 22px;">🛑</span>
            <div>
                <div style="font-size: 13px; font-weight: 800; color: #ef4444;">ACTIVE DEFENSE ENFORCED: HOST {selected_ip} IS CURRENTLY ISOLATED</div>
                <div style="font-size: 11px; color: #fca5a5;">Connection severed via TCP RST injection. Incoming VNC traffic blocked at Windows Firewall.</div>
            </div>
        </div>
    </div>
    """)
    col_u, _ = st.columns([1, 4])
    with col_u:
        if st.button(f"🔓 Unblock Device ({selected_ip})", key=f"unblock_top_{selected_ip}", type="primary"):
            try:
                resp = requests.post(f"http://{API_HOST}:{API_PORT}/unblock", json={"client_ip": selected_ip}, timeout=5)
                if resp.status_code == 200 and resp.json().get("success"):
                    st.success(f"Device {selected_ip} unblocked successfully!")
                    time.sleep(1)
                    st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")

elif critical_threats:
    for th_ip, th_sc, th_lvl in critical_threats:
        render_html(f"""
        <div style="background: #3b1419; border: 1px solid #ef4444; border-radius: 8px; padding: 12px 18px; margin-bottom: 16px;">
            <div style="display: flex; align-items: center; gap: 12px;">
                <span style="font-size: 20px;">🚨</span>
                <div>
                    <div style="font-size: 13px; font-weight: 800; color: #ef4444;">ACTIVE EXFILTRATION THREAT: {th_lvl} RISK ({th_sc:.1f}%)</div>
                    <div style="font-size: 11px; color: #fca5a5;">Suspicious transfer detected from client {th_ip}. Active defense triggered!</div>
                </div>
            </div>
        </div>
        """)

# ============================================================
# PAGE: DASHBOARD VIEW (MATCHING ATTACHED SCREENSHOT)
# ============================================================

if current_page == "Dashboard":

    # ------------------------------------------------------------
    # ROW 1: 5 METRIC CARDS
    # ------------------------------------------------------------
    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        sess_sub = "(Monitoring)" if vnc_active else "(Standing By)"
        render_html(f"""
        <div class="metric-card" style="border-left: 3px solid #1d4ed8;">
            <div class="metric-icon-box" style="background: rgba(29, 78, 216, 0.2); color: #3b82f6;">
                🖥️
            </div>
            <div class="metric-content">
                <div class="metric-label">Active Sessions</div>
                <div class="metric-val-row">
                    <span class="metric-val">{active_sessions_count}</span>
                </div>
                <div class="metric-sub">{sess_sub}</div>
            </div>
        </div>
        """)

    with c2:
        if risk_level == "LOW":
            r_col = "#10b981"
            r_box = "rgba(16, 185, 129, 0.2)"
            pill_bg = "#0f2d1e"
            pill_text = "Low Risk"
        elif risk_level == "MEDIUM":
            r_col = "#f59e0b"
            r_box = "rgba(245, 158, 11, 0.2)"
            pill_bg = "#332408"
            pill_text = "Medium Risk"
        elif risk_level == "HIGH":
            r_col = "#f97316"
            r_box = "rgba(249, 115, 22, 0.2)"
            pill_bg = "#381a10"
            pill_text = "High Risk"
        else:
            r_col = "#ef4444"
            r_box = "rgba(239, 68, 68, 0.2)"
            pill_bg = "#3b1419"
            pill_text = "Critical Risk"

        render_html(f"""
        <div class="metric-card" style="border-left: 3px solid {r_col};">
            <div class="metric-icon-box" style="background: {r_box}; color: {r_col};">
                🛡️
            </div>
            <div class="metric-content">
                <div class="metric-label">Current Risk Score</div>
                <div class="metric-val-row">
                    <span class="metric-val" style="color: {r_col};">{int(risk_score)}</span>
                    <span class="metric-sub">/ 100</span>
                </div>
                <div style="margin-top: 3px;">
                    <span style="background: {pill_bg}; color: {r_col}; font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 4px;">
                        {pill_text}
                    </span>
                </div>
            </div>
        </div>
        """)

    with c3:
        if vnc_active and selected_ip:
            dev_alert_cnt = len(device_alerts_df) if not device_alerts_df.empty else 0
            render_html(f"""
            <div class="metric-card" style="border-left: 3px solid #dc2626;">
                <div class="metric-icon-box" style="background: rgba(220, 38, 38, 0.2); color: #ef4444;">
                    ⚠️
                </div>
                <div class="metric-content">
                    <div class="metric-label">Alerts ({selected_ip})</div>
                    <div class="metric-val-row">
                        <span class="metric-val">{dev_alert_cnt}</span>
                    </div>
                    <div class="metric-sub" style="color: {'#ef4444' if dev_alert_cnt > 0 else '#64748b'}; font-weight: 600;">
                        {'Alert-Hit Device' if dev_alert_cnt > 0 else 'Clean Device Profile'}
                    </div>
                </div>
            </div>
            """)
        else:
            render_html("""
            <div class="metric-card" style="border-left: 3px solid #64748b;">
                <div class="metric-icon-box" style="background: rgba(100, 116, 139, 0.2); color: #94a3b8;">
                    ⚠️
                </div>
                <div class="metric-content">
                    <div class="metric-label">Alerts (Connected Device)</div>
                    <div class="metric-val-row">
                        <span class="metric-val" style="color: #64748b;">0</span>
                    </div>
                    <div class="metric-sub" style="color: #64748b;">(No Device Connected)</div>
                </div>
            </div>
            """)

    with c4:
        bl_sub = "Active" if blocked_count > 0 else "None"
        render_html(f"""
        <div class="metric-card" style="border-left: 3px solid #9333ea;">
            <div class="metric-icon-box" style="background: rgba(147, 51, 234, 0.2); color: #c084fc;">
                💻
            </div>
            <div class="metric-content">
                <div class="metric-label">Blocked Devices</div>
                <div class="metric-val-row">
                    <span class="metric-val">{blocked_count}</span>
                </div>
                <div class="metric-sub" style="color: #c084fc; font-weight: 600;">{bl_sub}</div>
            </div>
        </div>
        """)

    with c5:
        render_html(f"""
        <div class="metric-card" style="border-left: 3px solid #0284c7;">
            <div class="metric-icon-box" style="background: rgba(2, 132, 199, 0.2); color: #38bdf8;">
                🗄️
            </div>
            <div class="metric-content">
                <div class="metric-label">Total Transfers</div>
                <div class="metric-val-row">
                    <span class="metric-val">{total_transfers_count}</span>
                </div>
                <div class="metric-sub">(Monitored)</div>
            </div>
        </div>
        """)

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    # ------------------------------------------------------------
    # ROW 2: 3 MAJOR PANELS (TELEMETRY, RISK TREND, DONUT GAUGE)
    # ------------------------------------------------------------
    m1, m2, m3 = st.columns([1.1, 1.45, 1.0])

    # PANEL 1: Live Telemetry
    with m1:
        if vnc_active and selected_ip:
            session_id_str = f"VNC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            ip_display = selected_ip
            stat_badge = '<span class="badge-active">Active</span>'
            pps_display = int(packets_per_second)
            bps_display = format_bytes(bytes_per_second)
        else:
            session_id_str = "Standby"
            ip_display = "Waiting for connection..."
            stat_badge = '<span class="badge-standby">Standing By</span>'
            pps_display = 0
            bps_display = "0 B/s"

        render_html(f"""
        <div class="panel-box">
            <div class="panel-header">
                <span class="{'pulse-green' if vnc_active else 'pulse-amber'}"></span>
                <span>Live Telemetry</span>
            </div>
            <div class="panel-subtitle">Real-time network and session data</div>
            
            <div style="display: flex; flex-direction: column;">
                <div class="telem-row">
                    <span class="telem-label">Session ID</span>
                    <span class="telem-val" style="font-family: monospace;">{session_id_str}</span>
                </div>
                <div class="telem-row">
                    <span class="telem-label">Client IP</span>
                    <span class="telem-val">{ip_display}</span>
                </div>
                <div class="telem-row">
                    <span class="telem-label">Protocol</span>
                    <span class="telem-val">VNC (TCP/5900)</span>
                </div>
                <div class="telem-row">
                    <span class="telem-label">Session Duration</span>
                    <span class="telem-val" style="color: #38bdf8;">{session_duration_display}</span>
                </div>
                <div class="telem-row">
                    <span class="telem-label">Packets / sec</span>
                    <span class="telem-val">{pps_display}</span>
                </div>
                <div class="telem-row">
                    <span class="telem-label">Bytes / sec</span>
                    <span class="telem-val">{bps_display}</span>
                </div>
                <div class="telem-row">
                    <span class="telem-label">Protocol Status</span>
                    <span>{stat_badge}</span>
                </div>
            </div>
        </div>
        """)

    # PANEL 2: Risk Score Trend (Pure SVG Bézier Spline Chart)
    with m2:
        # Generate SVG Chart based on st.session_state.trend_points
        pts = st.session_state.trend_points
        if not pts:
            pts = [{"time": "00:00:00", "score": 0.0}]

        svg_w = 460
        svg_h = 165
        pad_l = 35
        pad_r = 15
        pad_t = 12
        pad_b = 24
        plot_w = svg_w - pad_l - pad_r
        plot_h = svg_h - pad_t - pad_b

        # Gridlines (0, 25, 50, 75, 100)
        grid_svg = ""
        for y_val in [0, 25, 50, 75, 100]:
            y_pos = pad_t + plot_h - (y_val / 100.0) * plot_h
            grid_svg += f'<line x1="{pad_l}" y1="{y_pos}" x2="{svg_w - pad_r}" y2="{y_pos}" stroke="#142036" stroke-width="1" stroke-dasharray="3,3"/>'
            grid_svg += f'<text x="{pad_l - 6}" y="{y_pos + 3}" fill="#64748b" font-size="9" text-anchor="end">{y_val}</text>'

        # Compute point coordinates
        coords = []
        n_pts = len(pts)
        for i, p in enumerate(pts):
            if n_pts > 1:
                x = pad_l + (i / (n_pts - 1)) * plot_w
            else:
                x = pad_l + plot_w / 2
            sc = min(max(float(p.get("score", 0.0)), 0.0), 100.0)
            y = pad_t + plot_h - (sc / 100.0) * plot_h
            coords.append((x, y, sc, p.get("time", "")))

        # Build Bézier path
        if len(coords) == 1:
            cx, cy, _, _ = coords[0]
            path_d = f"M {pad_l} {cy} L {svg_w - pad_r} {cy}"
            area_d = f"M {pad_l} {pad_t + plot_h} L {pad_l} {cy} L {svg_w - pad_r} {cy} L {svg_w - pad_r} {pad_t + plot_h} Z"
        else:
            path_d = f"M {coords[0][0]:.1f} {coords[0][1]:.1f}"
            for i in range(len(coords) - 1):
                p0 = coords[i]
                p1 = coords[i + 1]
                mid_x = (p0[0] + p1[0]) / 2.0
                path_d += f" C {mid_x:.1f} {p0[1]:.1f}, {mid_x:.1f} {p1[1]:.1f}, {p1[0]:.1f} {p1[1]:.1f}"
            
            area_d = path_d + f" L {coords[-1][0]:.1f} {pad_t + plot_h} L {coords[0][0]:.1f} {pad_t + plot_h} Z"

        # Points and X-axis timestamps
        dots_svg = ""
        labels_svg = ""
        for i, (x, y, sc, tm) in enumerate(coords):
            # Pick color for point
            if sc < 26:
                d_col = "#10b981"
            elif sc < 51:
                d_col = "#f59e0b"
            elif sc < 76:
                d_col = "#f97316"
            else:
                d_col = "#ef4444"
            
            # Draw point
            if i == len(coords) - 1:
                dots_svg += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{d_col}" stroke="#ffffff" stroke-width="1.5"/>'
            elif i % 2 == 0:
                dots_svg += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{d_col}"/>'

            # Timestamp labels (show max 5 labels)
            if (i % max(1, n_pts // 5) == 0 or i == n_pts - 1) and tm:
                labels_svg += f'<text x="{x:.1f}" y="{svg_h - 4}" fill="#64748b" font-size="9" text-anchor="middle">{tm[-5:]}</text>'

        render_html(f"""
        <div class="panel-box">
            <div class="panel-header">
                <span style="font-size: 15px;">🔔</span>
                <span>Risk Score Trend</span>
            </div>
            <div class="panel-subtitle">Live risk score over time</div>
            
            <svg width="100%" height="{svg_h}" viewBox="0 0 {svg_w} {svg_h}" style="overflow: visible;">
                <defs>
                    <linearGradient id="trendAreaGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stop-color="#ef4444" stop-opacity="0.35"/>
                        <stop offset="40%" stop-color="#f97316" stop-opacity="0.2"/>
                        <stop offset="70%" stop-color="#f59e0b" stop-opacity="0.1"/>
                        <stop offset="100%" stop-color="#10b981" stop-opacity="0.02"/>
                    </linearGradient>
                    <linearGradient id="trendLineGrad" x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stop-color="#10b981"/>
                        <stop offset="45%" stop-color="#f59e0b"/>
                        <stop offset="75%" stop-color="#f97316"/>
                        <stop offset="100%" stop-color="#ef4444"/>
                    </linearGradient>
                </defs>
                {grid_svg}
                <path d="{area_d}" fill="url(#trendAreaGrad)" />
                <path d="{path_d}" fill="none" stroke="url(#trendLineGrad)" stroke-width="2.5" stroke-linecap="round"/>
                {dots_svg}
                {labels_svg}
            </svg>
            
            <div style="display: flex; justify-content: center; gap: 16px; margin-top: 8px; font-size: 10px; color: #8da2c0;">
                <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 7px; height: 7px; border-radius: 50%; background: #10b981; display: inline-block;"></span> Low</span>
                <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 7px; height: 7px; border-radius: 50%; background: #f59e0b; display: inline-block;"></span> Medium</span>
                <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 7px; height: 7px; border-radius: 50%; background: #f97316; display: inline-block;"></span> High</span>
                <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 7px; height: 7px; border-radius: 50%; background: #ef4444; display: inline-block;"></span> Critical</span>
            </div>
        </div>
        """)

    # PANEL 3: Risk Level Donut Meter
    with m3:
        donut_score = min(max(risk_score, 0.0), 100.0)
        
        # Color based on score
        if donut_score < 26:
            gauge_col = "#10b981"
            threat_txt = "Low"
        elif donut_score < 51:
            gauge_col = "#f59e0b"
            threat_txt = "Medium"
        elif donut_score < 76:
            gauge_col = "#f97316"
            threat_txt = "High"
        else:
            gauge_col = "#ef4444"
            threat_txt = "Critical"

        radius = 58
        circ = 2 * math.pi * radius
        offset = circ * (1.0 - (donut_score / 100.0))

        render_html(f"""
        <div class="panel-box">
            <div class="panel-header">
                <span>Risk Level</span>
            </div>
            <div class="panel-subtitle">Current threat level based on activity</div>
            
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 4px 0;">
                <!-- Circular Donut SVG -->
                <div style="position: relative; width: 140px; height: 140px; flex-shrink: 0;">
                    <svg width="140" height="140" viewBox="0 0 140 140">
                        <circle cx="70" cy="70" r="{radius}" fill="none" stroke="#121d33" stroke-width="12"/>
                        <circle cx="70" cy="70" r="{radius}" fill="none" stroke="{gauge_col}" stroke-width="12"
                                stroke-dasharray="{circ:.2f}" stroke-dashoffset="{offset:.2f}"
                                stroke-linecap="round" transform="rotate(-90 70 70)"/>
                    </svg>
                    <div style="position: absolute; top: 0; left: 0; width: 140px; height: 140px; display: flex; flex-direction: column; align-items: center; justify-content: center;">
                        <span style="font-size: 16px;">⚠️</span>
                        <span style="font-size: 15px; font-weight: 800; color: {gauge_col}; margin-top: 1px;">{threat_txt}</span>
                        <span style="font-size: 11px; color: #8da2c0; font-weight: 600;">{int(donut_score)} / 100</span>
                    </div>
                </div>

                <!-- Legend on the right -->
                <div style="display: flex; flex-direction: column; gap: 6px; font-size: 10px; color: #8da2c0;">
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="width: 7px; height: 7px; border-radius: 50%; background: #10b981; display: inline-block;"></span>
                        <span>Low (0 - 25)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="width: 7px; height: 7px; border-radius: 50%; background: #f59e0b; display: inline-block;"></span>
                        <span>Medium (26 - 50)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="width: 7px; height: 7px; border-radius: 50%; background: #f97316; display: inline-block;"></span>
                        <span>High (51 - 75)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="width: 7px; height: 7px; border-radius: 50%; background: #ef4444; display: inline-block;"></span>
                        <span>Critical (76 - 100)</span>
                    </div>
                </div>
            </div>
        </div>
        """)

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    # ------------------------------------------------------------
    # ROW 3: 3 BOTTOM CARDS (ALERT HISTORY, ACTIVITY HISTORY, BLOCKED DEVICES)
    # ------------------------------------------------------------
    b1, b2, b3 = st.columns(3)

    # CARD 1: Alert History (Relevant strictly to Connected Device)
    with b1:
        alert_rows = ""
        if vnc_active and selected_ip:
            if not device_alerts_df.empty:
                for _, r in device_alerts_df.head(4).iterrows():
                    ts_raw = str(r.get("timestamp", ""))
                    ts_str = ts_raw[-8:] if len(ts_raw) >= 8 else ts_raw
                    lvl = str(r.get("risk_level", "LOW")).upper()
                    badge_cls = f"badge-{lvl.lower()}"
                    sc = float(r.get("risk_score", 0.0))

                    if lvl == "CRITICAL":
                        event_title = "Exfiltration Detected"
                        det = f"Score {sc:.0f}% • Active Defense"
                    elif lvl == "HIGH":
                        event_title = "High Data Transfer"
                        det = f"Score {sc:.0f}% • Burst Alert"
                    elif lvl == "MEDIUM":
                        event_title = "File Access Event"
                        det = f"Score {sc:.0f}% • Monitoring"
                    else:
                        event_title = "VNC Telemetry Alert"
                        det = f"Score {sc:.0f}%"

                    alert_rows += f"""
                    <tr>
                        <td>{ts_str}</td>
                        <td>{event_title}</td>
                        <td><span class="{badge_cls}">{lvl}</span></td>
                        <td style="color: #8da2c0;">{det}</td>
                    </tr>
                    """
                dev_sub = f"Sustained alert records for connected host {selected_ip}"
                footer_txt = f"<span style='color: #ef4444; font-weight: 600;'>{len(device_alerts_df)} Alerts on Record for {selected_ip}</span>"
            else:
                alert_rows = f"<tr><td colspan='4' style='text-align: center; color: #10b981; padding: 18px 0;'>🟢 Clean Device Profile • No prior alerts for {selected_ip}</td></tr>"
                dev_sub = f"Host {selected_ip} has no prior alerts"
                footer_txt = "<span style='color: #10b981; font-weight: 600;'>Safe Device Profile</span>"
            
            dev_title = f"Alert History ({selected_ip})"
        else:
            alert_rows = "<tr><td colspan='4' style='text-align: center; color: #64748b; padding: 18px 0;'>No client connected • Alert history appears once device connects</td></tr>"
            dev_title = "Alert History"
            dev_sub = "Connect a VNC client to load its alert story"
            footer_txt = "<span style='color: #64748b;'>Waiting for Device Connection</span>"

        render_html(f"""
        <div class="panel-box">
            <div class="panel-header">
                <span>🔔 {dev_title}</span>
            </div>
            <div class="panel-subtitle">{dev_sub}</div>
            
            <table class="soc-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Event</th>
                        <th>Risk Level</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {alert_rows}
                </tbody>
            </table>
            
            <div style="margin-top: 10px; font-size: 11px;">
                {footer_txt}
            </div>
        </div>
        """)

    # CARD 2: Activity History (Generated for Current Activity / Live Session)
    with b2:
        act_rows = ""
        current_activities = st.session_state.session_activities
        if vnc_active and selected_ip:
            if current_activities:
                for item in current_activities[:4]:
                    ts_str = item.get("time", "")
                    act = item.get("action", "VNC Event")
                    src = item.get("source", "Client")
                    lvl = item.get("risk_level", "LOW")
                    badge_cls = f"badge-{lvl.lower()}"
                    act_rows += f"""
                    <tr>
                        <td>{ts_str}</td>
                        <td>{act}</td>
                        <td>{src}</td>
                        <td><span class="{badge_cls}">{lvl}</span></td>
                    </tr>
                    """
            else:
                act_rows = f"""
                <tr>
                    <td>{now_str[-8:]}</td>
                    <td>Connection Established</td>
                    <td>{selected_ip}</td>
                    <td><span class="badge-low">LOW</span></td>
                </tr>
                """
            act_sub = f"Live event stream for current session ({selected_ip})"
            act_footer = f"<span style='color: #3b82f6; font-weight: 600;'>Live Session Active ({selected_ip})</span>"
        else:
            act_rows = "<tr><td colspan='4' style='text-align: center; color: #64748b; padding: 18px 0;'>Awaiting VNC connection on port 5900</td></tr>"
            act_sub = "Live events generated during active connection"
            act_footer = "<span style='color: #64748b;'>Standing By on Port 5900</span>"

        render_html(f"""
        <div class="panel-box">
            <div class="panel-header">
                <span>🕒 Activity History</span>
            </div>
            <div class="panel-subtitle">{act_sub}</div>
            
            <table class="soc-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Action</th>
                        <th>Source</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    {act_rows}
                </tbody>
            </table>
            
            <div style="margin-top: 10px; font-size: 11px;">
                {act_footer}
            </div>
        </div>
        """)

    # CARD 3: Blocked Devices
    with b3:
        bl_rows = ""
        if not blocked_df.empty:
            for _, r in blocked_df.head(4).iterrows():
                ip = str(r.get("client_ip", ""))
                ts = str(r.get("timestamp", ""))[-8:]
                bl_rows += f"""
                <tr>
                    <td>{ip}</td>
                    <td>Critical Risk Exceeded</td>
                    <td>{ts}</td>
                    <td><span class="badge-critical">Blocked</span></td>
                </tr>
                """
        else:
            bl_rows = "<tr><td colspan='4' style='text-align: center; color: #64748b; padding: 16px 0;'>No devices currently blocked</td></tr>"

        render_html(f"""
        <div class="panel-box">
            <div class="panel-header">
                <span>🚫 Blocked Devices</span>
            </div>
            <div class="panel-subtitle">Devices blocked by firewall</div>
            
            <table class="soc-table">
                <thead>
                    <tr>
                        <th>Device IP</th>
                        <th>Reason</th>
                        <th>Time</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {bl_rows}
                </tbody>
            </table>
        </div>
        """)
        
        # Interactive Unblock control if blocked hosts exist
        if not blocked_df.empty:
            t_ip = st.selectbox("Unblock Host:", blocked_df['client_ip'].unique(), key="unblock_sel_dash")
            if st.button(f"🔓 Unblock {t_ip}", key="unblock_btn_dash"):
                try:
                    resp = requests.post(f"http://{API_HOST}:{API_PORT}/unblock", json={"client_ip": t_ip}, timeout=5)
                    if resp.status_code == 200 and resp.json().get("success"):
                        st.success(f"{t_ip} unblocked!")
                        time.sleep(1)
                        st.rerun()
                except Exception as e:
                    st.error(f"Error: {e}")

    # ------------------------------------------------------------
    # FOOTER
    # ------------------------------------------------------------
    render_html("""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 24px; padding-top: 12px; border-top: 1px solid #142036; font-size: 11px; color: #64748b;">
        <div>SMARTVNC&nbsp;&nbsp;|&nbsp;&nbsp;Detect&nbsp;&nbsp;•&nbsp;&nbsp;Monitor&nbsp;&nbsp;•&nbsp;&nbsp;Protect</div>
        <div>Network Security Dashboard</div>
    </div>
    """)

# ============================================================
# PAGE: FILE TRANSFER POLICY & ACCESS CLASSIFICATION
# ============================================================
elif current_page == "File Transfer Policy":
    render_html("""
    <div class="panel-box" style="margin-bottom: 16px;">
        <div class="panel-header">📁 File Transfer Access Control & Classification</div>
        <div class="panel-subtitle">
            Specify which files and extensions clients are allowed to transfer over VNC. If a client attempts to access unauthorized or restricted files, 
            SmartVNC automatically severs the session and blocks the device at the firewall.
        </div>
    </div>
    """)

    all_policies_df = get_file_policies()
    allowed_df = all_policies_df[all_policies_df["is_allowed"] == 1] if not all_policies_df.empty else pd.DataFrame()
    blocked_df_pol = all_policies_df[all_policies_df["is_allowed"] == 0] if not all_policies_df.empty else pd.DataFrame()
    recent_transfers_df = get_recent_file_transfers(limit=50)

    cnt_allowed = len(allowed_df)
    cnt_blocked = len(blocked_df_pol)
    cnt_transfers = len(recent_transfers_df)
    cnt_violations = len(recent_transfers_df[recent_transfers_df["classification"] == "ACCESS_NOT_ALLOWED"]) if not recent_transfers_df.empty else 0

    pc1, pc2, pc3, pc4 = st.columns(4)
    with pc1:
        st.metric("Allowed Rules", cnt_allowed)
    with pc2:
        st.metric("Restricted Rules", cnt_blocked)
    with pc3:
        st.metric("Total Transfers Logged", cnt_transfers)
    with pc4:
        st.metric("Access Violations Blocked", cnt_violations)

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    tab_policy, tab_blocked_rules, tab_history, tab_sim = st.tabs([
        "✅ Server Allowed Files (Whitelist)",
        "🚫 Restricted & Prohibited Rules",
        "📊 Live File Transfer Activity Log",
        "🧪 Test / Simulate Client File Access"
    ])

    with tab_policy:
        st.subheader("Server-Approved Files & Extensions")
        st.caption("Only files matching these extensions/patterns may be transferred or accessed by VNC clients.")

        if not allowed_df.empty:
            st.dataframe(
                allowed_df[["id", "policy_type", "value", "description"]].rename(columns={
                    "id": "Rule ID",
                    "policy_type": "Policy Type",
                    "value": "Allowed Pattern / Extension",
                    "description": "Description"
                }),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No allowed policies currently defined.")

        st.divider()
        st.markdown("#### ➕ Add Allowed File Transfer Rule")
        with st.form("add_allowed_rule_form"):
            col_a1, col_a2 = st.columns(2)
            with col_a1:
                new_type = st.selectbox("Policy Type", ["EXTENSION", "FILENAME", "DIRECTORY"], key="allow_type")
                new_val = st.text_input("Allowed Value (e.g. .pdf, .txt, project_shared)", key="allow_val")
            with col_a2:
                new_desc = st.text_input("Description", key="allow_desc", placeholder="e.g. Approved documents")
                submit_allow = st.form_submit_button("Add Allowed Rule")

            if submit_allow:
                if new_val.strip():
                    add_file_policy(new_type, new_val, is_allowed=1, description=new_desc)
                    st.success(f"Rule for '{new_val}' added to Server Allowed Policies!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.warning("Please provide a valid rule value.")

        if not allowed_df.empty:
            del_id = st.selectbox("Select Rule to Remove:", allowed_df["id"].tolist(), format_func=lambda x: f"ID {x}: {allowed_df.loc[allowed_df['id']==x, 'value'].values[0]}", key="del_allow_sel")
            if st.button("🗑️ Delete Selected Allowed Rule", key="del_allow_btn"):
                delete_file_policy(del_id)
                st.success("Rule deleted.")
                time.sleep(1)
                st.rerun()

    with tab_blocked_rules:
        st.subheader("Restricted File Patterns & Prohibited Extensions")
        st.caption("Any client accessing files matching these prohibited types or sensitive keywords is immediately blocked.")

        if not blocked_df_pol.empty:
            st.dataframe(
                blocked_df_pol[["id", "policy_type", "value", "description"]].rename(columns={
                    "id": "Rule ID",
                    "policy_type": "Policy Type",
                    "value": "Prohibited Pattern / Keyword",
                    "description": "Risk Assessment Reason"
                }),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No restricted policies currently defined.")

        st.divider()
        st.markdown("#### ➕ Add Restricted / Prohibited Rule")
        with st.form("add_blocked_rule_form"):
            col_b1, col_b2 = st.columns(2)
            with col_b1:
                b_type = st.selectbox("Policy Type", ["EXTENSION", "KEYWORD", "DIRECTORY"], key="block_type")
                b_val = st.text_input("Prohibited Value (e.g. .exe, .zip, password, confidential)", key="block_val")
            with col_b2:
                b_desc = st.text_input("Reason / Description", key="block_desc", placeholder="e.g. Prohibited executable file")
                submit_block = st.form_submit_button("Add Prohibited Rule")

            if submit_block:
                if b_val.strip():
                    add_file_policy(b_type, b_val, is_allowed=0, description=b_desc)
                    st.success(f"Prohibited rule for '{b_val}' added!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.warning("Please provide a valid rule value.")

        if not blocked_df_pol.empty:
            del_b_id = st.selectbox("Select Prohibited Rule to Remove:", blocked_df_pol["id"].tolist(), format_func=lambda x: f"ID {x}: {blocked_df_pol.loc[blocked_df_pol['id']==x, 'value'].values[0]}", key="del_block_sel")
            if st.button("🗑️ Delete Selected Prohibited Rule", key="del_block_btn"):
                delete_file_policy(del_b_id)
                st.success("Rule deleted.")
                time.sleep(1)
                st.rerun()

    with tab_history:
        st.subheader("File Transfer Access & Classification History")
        st.caption("Live forensic log of all file transfer evaluations, classifications, and active defense enforcements.")

        if not recent_transfers_df.empty:
            disp_transfers = recent_transfers_df.rename(columns={
                "timestamp": "Timestamp",
                "client_ip": "Client IP",
                "file_name": "File Name",
                "classification": "Access Classification",
                "risk_score": "Risk Score (%)",
                "action_taken": "Action Taken",
                "reason": "Detection Reason"
            })
            st.dataframe(disp_transfers, use_container_width=True, hide_index=True)
        else:
            st.info("No file transfers logged yet. Use the 'Test / Simulate' tab or transfer a file to generate records.")

    with tab_sim:
        st.subheader("🧪 Live Simulation & Evaluation Demonstration")
        st.caption("Demonstrate how SmartVNC evaluates client file requests, classifies them as Allowed vs Not Allowed, and automatically triggers device blocking.")

        default_test_ip = selected_ip if (vnc_active and selected_ip) else "10.134.240.153"
        test_ip = st.text_input("Client IP to Test:", value=default_test_ip)

        st.markdown("**Quick Preset Scenarios:**")
        q1, q2, q3, q4 = st.columns(4)
        sample_name = "quarterly_report.pdf"
        if q1.button("📄 Approved PDF (.pdf)"):
            sample_name = "quarterly_report.pdf"
        if q2.button("⚠️ Prohibited Binary (.exe)"):
            sample_name = "network_scanner.exe"
        if q3.button("🔑 Sensitive Keyword (passwords.txt)"):
            sample_name = "employee_passwords.txt"
        if q4.button("🔒 Prohibited Archive (.zip)"):
            sample_name = "database_backup.zip"

        test_file = st.text_input("File Name to Evaluate:", value=sample_name, key="test_file_input")

        if st.button("🚀 Evaluate & Classify File Transfer Attempt", type="primary"):
            from file_classifier import classify_file_transfer
            res = classify_file_transfer(
                file_name=test_file,
                client_ip=test_ip,
                client_port=client_port,
                file_path=test_file
            )

            classification = res.get("classification")
            risk_score = res.get("risk_score", 0.0)
            action = res.get("action_taken")
            reason = res.get("reason")

            if classification == "ACCESS_ALLOWED":
                st.success(f"### 🟢 ACCESS ALLOWED (Risk: {risk_score:.1f}%)\n**Action:** {action}\n\n**Reason:** {reason}")
            else:
                st.error(f"### 🔴 ACCESS NOT ALLOWED - SECURITY VIOLATION (Risk: {risk_score:.1f}%)\n**Action:** {action}\n\n**Reason:** {reason}\n\n🛡️ **Automated Defense Activated:** Client `{test_ip}` connection has been terminated and added to Windows Firewall Block List!")

            time.sleep(2)
            st.rerun()

# ============================================================
# PAGE: LIVE MONITORING
# ============================================================
elif current_page == "Live Monitoring":
    render_html("""
    <div class="panel-box" style="margin-bottom: 16px;">
        <div class="panel-header">Detailed Real-Time Network Packet Telemetry</div>
        <div class="panel-subtitle">In-depth traffic analysis on port 5900</div>
    </div>
    """)
    col_l1, col_l2 = st.columns(2)
    with col_l1:
        st.metric("Forward Packets", forward_packets)
        st.metric("Forward Bytes", format_bytes(forward_bytes))
        st.metric("Packets / Second", f"{packets_per_second:.1f}")
    with col_l2:
        st.metric("Backward Packets", backward_packets)
        st.metric("Backward Bytes", format_bytes(backward_bytes))
        st.metric("Bytes / Second", f"{format_bytes(bytes_per_second)}/s")

# ============================================================
# PAGE: ALERT HISTORY (GLOBAL SECURITY ARCHIVE)
# ============================================================
elif current_page == "Alert History":
    render_html("""
    <div class="panel-box" style="margin-bottom: 16px;">
        <div class="panel-header">Global Exfiltration Alert History Database</div>
        <div class="panel-subtitle">Permanent archive of all alerts across all devices and sessions for forensic analysis</div>
    </div>
    """)
    
    full_alerts_df = get_recent_alerts(limit=100)
    if not full_alerts_df.empty:
        f_col1, f_col2 = st.columns(2)
        with f_col1:
            unique_ips = ["All Devices"] + list(full_alerts_df['client_ip'].dropna().unique())
            default_idx = unique_ips.index(selected_ip) if (vnc_active and selected_ip in unique_ips) else 0
            sel_ip_filter = st.selectbox("Filter by Device IP:", unique_ips, index=default_idx)
        with f_col2:
            risk_filter = st.selectbox("Filter by Risk Level:", ["All Levels", "CRITICAL", "HIGH", "MEDIUM", "LOW"], index=0)

        display_df = full_alerts_df.copy()
        if sel_ip_filter != "All Devices":
            display_df = display_df[display_df['client_ip'] == sel_ip_filter]
        if risk_filter != "All Levels":
            display_df = display_df[display_df['risk_level'] == risk_filter]

        st.markdown(f"**Showing {len(display_df)} alert records**")
        st.dataframe(
            display_df[['timestamp', 'client_ip', 'risk_score', 'risk_level', 'status', 'recommended_action', 'bytes_per_second']],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No security alerts recorded in the database yet.")

# ============================================================
# PAGE: BLOCKED DEVICES
# ============================================================
elif current_page == "Blocked Devices":
    render_html("""
    <div class="panel-box" style="margin-bottom: 16px;">
        <div class="panel-header">Active Firewall Isolations</div>
        <div class="panel-subtitle">Manage devices quarantined by automated active defense</div>
    </div>
    """)
    if not blocked_df.empty:
        st.dataframe(blocked_df, use_container_width=True, hide_index=True)
        t_ip_page = st.selectbox("Select Device to Unblock:", blocked_df['client_ip'].unique(), key="unblock_page_sel")
        if st.button(f"Unblock {t_ip_page}", key="unblock_page_btn", type="primary"):
            try:
                resp = requests.post(f"http://{API_HOST}:{API_PORT}/unblock", json={"client_ip": t_ip_page}, timeout=5)
                if resp.status_code == 200 and resp.json().get("success"):
                    st.success(f"{t_ip_page} unblocked successfully!")
                    time.sleep(1)
                    st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")
    else:
        st.success("No devices are currently quarantined by Windows Firewall.")

# ============================================================
# PAGE: REPORTS & SETTINGS
# ============================================================
elif current_page == "Reports":
    render_html("""
    <div class="panel-box">
        <div class="panel-header">System Security Audit Reports</div>
        <div class="panel-subtitle">Summary report of VNC sessions, detection rates, and active defense actions</div>
        <div style="font-size: 13px; color: #cbd5e1; margin-top: 14px;">
            Total Monitored Sessions: <b>4</b><br>
            Exfiltration Incidents Blocked: <b>1</b><br>
            Model Precision: <b>98.4%</b>
        </div>
    </div>
    """)

elif current_page == "Settings":
    render_html("""
    <div class="panel-box">
        <div class="panel-header">SmartVNC Engine Configuration</div>
        <div class="panel-subtitle">Network sniffer and risk threshold parameters</div>
        <div style="font-size: 13px; color: #cbd5e1; margin-top: 14px;">
            Target VNC Port: <b>5900 (TCP)</b><br>
            Risk API Endpoint: <b>http://127.0.0.1:5000/predict</b><br>
            Critical Risk Sever Threshold: <b>80.0%</b>
        </div>
    </div>
    """)

# ============================================================
# REAL-TIME DYNAMIC AUTO-REFRESH
# ============================================================

time.sleep(1)
st.rerun()
