import streamlit as st
import time
import json
import requests
from datetime import datetime
from pathlib import Path
import sys
import pandas as pd


# ============================================================
# SMARTVNC - LIVE SECURITY DASHBOARD
# ============================================================


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(

    page_title="SMARTVNC Security Dashboard",

    page_icon="🛡️",

    layout="centered",

    initial_sidebar_state="collapsed"
)


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[1]

# Allow importing config.py and db_manager
sys.path.append(str(BASE_DIR))
from config import API_URL, API_HOST, API_PORT
from database.db_manager import (
    get_recent_alerts,
    get_high_risk_alerts,
    is_device_blocked,
    get_blocked_devices
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

ALERTS_FILE = (
    BASE_DIR
    / "datasets"
    / "risk"
    / "smartvnc_alerts.csv"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .stApp {
        background-color: #080b10;
    }

    .main {
        padding-top: 25px;
        padding-bottom: 25px;
    }

    #MainMenu {
        visibility: hidden;
    }

    header {
        visibility: hidden;
    }

    footer {
        visibility: hidden;
    }

    .smart-title {
        font-size: 30px;
        font-weight: 700;
        color: #ffffff;
        margin-bottom: 3px;
    }

    .smart-subtitle {
        font-size: 13px;
        color: #8b949e;
        margin-bottom: 20px;
    }

    .section-label {
        font-size: 12px;
        font-weight: 700;
        color: #8b949e;
        letter-spacing: 1px;
        margin-bottom: 8px;
        text-transform: uppercase;
    }

    .active-status {
        background-color: #0d2b1d;
        border: 1px solid #238636;
        border-radius: 6px;
        padding: 10px 14px;
        color: #3fb950;
        font-size: 15px;
        font-weight: 700;
    }

    .inactive-status {
        background-color: #2b1616;
        border: 1px solid #f85149;
        border-radius: 6px;
        padding: 10px 14px;
        color: #ff7b72;
        font-size: 15px;
        font-weight: 700;
    }

    .duration {
        color: #c9d1d9;
        font-size: 13px;
        margin-top: 8px;
    }

    .risk-score {
        font-size: 46px;
        font-weight: 750;
        color: #ff6b6b;
        line-height: 1.1;
    }

    .risk-low {
        font-size: 23px;
        font-weight: 700;
        color: #3fb950;
    }

    .risk-medium {
        font-size: 23px;
        font-weight: 700;
        color: #d29922;
    }

    .risk-high {
        font-size: 23px;
        font-weight: 700;
        color: #ff7b72;
    }

    .risk-critical {
        font-size: 23px;
        font-weight: 700;
        color: #ff4d4d;
    }

    .threat {
        font-size: 19px;
        font-weight: 700;
        color: #ff7b72;
    }

    .normal {
        font-size: 19px;
        font-weight: 700;
        color: #3fb950;
    }

    .action-label {
        font-size: 12px;
        font-weight: 700;
        color: #8b949e;
        letter-spacing: 0.7px;
        margin-bottom: 4px;
    }

    .action-value {
        font-size: 19px;
        font-weight: 700;
        color: #ff7b72;
    }

    .action-safe {
        font-size: 19px;
        font-weight: 700;
        color: #3fb950;
    }

    .last-updated {
        text-align: right;
        color: #6e7681;
        font-size: 11px;
        margin-top: 20px;
    }

    .footer-text {
        text-align: center;
        color: #484f58;
        font-size: 10px;
        margin-top: 25px;
    }

    hr {
        border: none;
        border-top: 1px solid #30363d;
        margin: 20px 0;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# READ LIVE DATA
# ============================================================

LIVE_DATA_FILE = get_live_data_file()

if not LIVE_DATA_FILE.exists():

    st.warning(
        "Waiting for VNC monitor..."
    )

    st.info(
        "Start monitoring/vnc_monitor.py "
        "to begin receiving live VNC data."
    )

    time.sleep(2)
    st.rerun()


if "last_good_data" not in st.session_state:
    st.session_state.last_good_data = {}

if "risk_history" not in st.session_state:
    st.session_state.risk_history = []

try:
    with open(
        LIVE_DATA_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        content = file.read()
        if content.strip():
            live_data = json.loads(content)
            st.session_state.last_good_data = live_data
        else:
            live_data = st.session_state.last_good_data

except Exception as e:
    # If the JSON is temporarily corrupted by a simultaneous write, do not crash.
    # Fallback to the last known good data to prevent flickering.
    live_data = st.session_state.last_good_data


# ============================================================
# EXTRACT NETWORK FEATURES & MULTI-DEVICE SUPPORT
# ============================================================

vnc_active = bool(
    live_data.get(
        "vnc_active",
        False
    )
)

# Liveness Heartbeat Check:
# If monitor hasn't updated the live data in over 6 seconds, the session was closed or disconnected
last_ts = float(live_data.get("timestamp", 0.0))
if last_ts > 0 and (time.time() - last_ts) > 6.0:
    vnc_active = False

devices = live_data.get("devices", {}) if vnc_active else {}

# Fallback: if vnc_active is True but devices dict is empty (e.g. legacy packet sniffer)
if vnc_active and not devices:
    legacy_ip = live_data.get("client_ip", "Unknown")
    devices = {
        legacy_ip: {
            "session_duration": float(live_data.get("session_duration", 0.0)),
            "forward_packets": int(live_data.get("forward_packets", 0)),
            "backward_packets": int(live_data.get("backward_packets", 0)),
            "bytes_per_second": float(live_data.get("bytes_per_second", 0.0)),
            "packets_per_second": float(live_data.get("packets_per_second", 0.0)),
            "protocol": int(live_data.get("protocol", 6))
        }
    }

# Predict risk for every currently connected device
device_results = {}
critical_threats = []

if vnc_active and devices:
    for d_ip, d_stats in devices.items():
        payload = {
            "session_duration": float(d_stats.get("session_duration", 0.0)),
            "forward_packets": int(d_stats.get("forward_packets", 0)),
            "backward_packets": int(d_stats.get("backward_packets", 0)),
            "bytes_per_second": float(d_stats.get("bytes_per_second", 0.0)),
            "packets_per_second": float(d_stats.get("packets_per_second", 0.0)),
            "protocol": int(d_stats.get("protocol", 6)),
            "client_ip": d_ip,
            "client_port": int(d_stats.get("client_port", 0))
        }
        try:
            response = requests.post(API_URL, json=payload, timeout=3)
            if response.status_code == 200:
                res_data = response.json()
                if res_data.get("success"):
                    device_results[d_ip] = res_data
                    if res_data.get("risk_level") in ["HIGH", "CRITICAL"]:
                        critical_threats.append((d_ip, float(res_data.get("risk_score", 0.0)), res_data.get("risk_level")))
        except requests.exceptions.ConnectionError:
            st.error("Cannot connect to SMARTVNC API. Please ensure risk_api.py is running.")
            st.stop()
        except Exception:
            pass

# ============================================================
# DASHBOARD TITLE
# ============================================================

st.markdown(
    """
    <div class="smart-title">
        🛡️ SMARTVNC SECURITY DASHBOARD
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="smart-subtitle">
        Secure VNC Based Prevention of Exfiltration Attacks
    </div>
    """,
    unsafe_allow_html=True
)

st.divider()

# ============================================================
# MULTI-DEVICE SELECTION & DEVICE STATS
# ============================================================

if vnc_active and devices:
    device_list = list(devices.keys())
    if len(device_list) > 1:
        st.info(f"🌐 **Multi-Device Environment:** {len(device_list)} active VNC clients connected simultaneously.")
        selected_ip = st.selectbox("🎯 Select Client Device to Inspect in Detail:", device_list)
    else:
        selected_ip = device_list[0]
else:
    selected_ip = None

# Extract statistics for the selected device (or defaults if inactive)
if selected_ip and selected_ip in devices:
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
    protocol = int(sel_stats.get("protocol", 6))
    client_ip = selected_ip

    risk_score = float(sel_res.get("risk_score", 0.0))
    risk_level = sel_res.get("risk_level", "LOW")
    status = sel_res.get("status", "NORMAL")
else:
    session_duration = 0.0
    forward_packets = 0
    backward_packets = 0
    bytes_per_second = 0.0
    packets_per_second = 0.0
    protocol = 6
    client_ip = "None"
    risk_score = 0.0
    risk_level = "LOW"
    status = "NORMAL"

total_seconds = int(session_duration)
hours = total_seconds // 3600
minutes = (total_seconds % 3600) // 60
seconds = total_seconds % 60
session_duration_display = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

# Append to history for the live graph (limit to 60 data points / 60 seconds)
st.session_state.risk_history.append(risk_score)
if len(st.session_state.risk_history) > 60:
    st.session_state.risk_history.pop(0)

# RECOMMENDED ACTION
if status == "NORMAL":
    recommended_action = "MONITOR"
else:
    if risk_level == "MEDIUM":
        recommended_action = "MONITOR"
    elif risk_level == "HIGH":
        recommended_action = "ALERT_AND_LOG"
    else:
        recommended_action = "TERMINATE_AND_BLOCK"

last_updated = live_data.get(
    "last_updated",
    datetime.now().strftime("%H:%M:%S")
)

# ============================================================
# VNC SESSION STATUS
# ============================================================

st.markdown(
    '<div class="section-label">'
    'VNC SESSION'
    '</div>',
    unsafe_allow_html=True
)

if critical_threats:
    for th_ip, th_sc, th_lvl in critical_threats:
        st.error(f"🚨 **ACTIVE EXFILTRATION THREAT: {th_lvl} RISK on Client {th_ip} ({th_sc:.2f}%)** — Active Defense Triggered!")

if not (vnc_active and selected_ip):
    st.session_state.risk_history = []
    st.markdown(
        '<div class="inactive-status">'
        '🔴 INACTIVE (Waiting for connection...)'
        '</div>',
        unsafe_allow_html=True
    )
    st.info(
        "📡 **System Standing By:** No VNC client is connected. Waiting for inbound connection on port 5900...\n\n"
        "Live network bandwidth, real-time exfiltration risk score, and isolated activity history will appear automatically once a client device connects."
    )

    try:
        blocked_df = get_blocked_devices()
        if not blocked_df.empty:
            st.divider()
            st.markdown(
                '<div class="section-label">'
                'FIREWALL BLOCKED DEVICES'
                '</div>',
                unsafe_allow_html=True
            )
            st.dataframe(
                blocked_df[['timestamp', 'client_ip', 'client_port', 'reason', 'status']],
                use_container_width=True,
                hide_index=True
            )
    except Exception:
        pass

    st.markdown(
        f"""
        <div class="last-updated">
            Last Updated&nbsp;&nbsp; {last_updated}
        </div>
        """,
        unsafe_allow_html=True
    )
    st.markdown(
        """
        <div class="footer-text">
            SMARTVNC • Real-Time VNC Security Monitoring
        </div>
        """,
        unsafe_allow_html=True
    )
    time.sleep(1)
    st.rerun()

# --- ACTIVE CLIENT SESSION VIEW ---
if len(devices) > 1:
    st.markdown(
        f'<div class="active-status">'
        f'🟢 ACTIVE — {len(devices)} Devices Connected (Inspecting: {selected_ip})'
        f'</div>',
        unsafe_allow_html=True
    )
else:
    st.markdown(
        f'<div class="active-status">'
        f'🟢 ACTIVE (Client: {selected_ip})'
        f'</div>',
        unsafe_allow_html=True
    )

st.markdown(
    f'<div class="session-duration">'
    f'⏱️ Session Duration: {session_duration_display}'
    f'</div>',
    unsafe_allow_html=True
)

if len(devices) > 1:
    summary_rows = []
    for d_ip, d_stats in devices.items():
        res = device_results.get(d_ip, {})
        summary_rows.append({
            "Device IP": d_ip,
            "Risk Score": f"{float(res.get('risk_score', 0.0)):.2f}%",
            "Risk Level": res.get("risk_level", "LOW"),
            "Threat Status": res.get("status", "NORMAL"),
            "Speed": f"{float(d_stats.get('bytes_per_second', 0.0)):,.1f} B/s",
            "Duration": f"{int(d_stats.get('session_duration', 0.0))}s"
        })
    st.caption("Concurrent Devices Overview:")
    st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)

st.divider()

# ============================================================
# ACTIVE DEFENSE CONTROL PANEL
# ============================================================
is_blocked = is_device_blocked(selected_ip) if selected_ip else False

if is_blocked:
    st.error(f"🛑 **DEVICE BLOCKED:** Client {selected_ip} has been TERMINATED and is BLOCKED in Windows Firewall.")
    if st.button(f"🔓 Unblock Device ({selected_ip})", key=f"unblock_btn_{selected_ip}"):
        try:
            resp = requests.post(f"http://{API_HOST}:{API_PORT}/unblock", json={"client_ip": selected_ip}, timeout=5)
            if resp.status_code == 200 and resp.json().get("success"):
                st.success(f"Device {selected_ip} has been unblocked from Windows Firewall!")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Failed to unblock device via API.")
        except Exception as e:
            st.error(f"Cannot reach Risk API to unblock: {e}")

elif risk_level == "CRITICAL" and selected_ip:
    st.error(f"🚨 **ACTIVE DEFENSE ENFORCED:** CRITICAL exfiltration risk ({risk_score:.2f}%) detected! Active VNC connection severed and {selected_ip} blocked in Windows Firewall.")
    if st.button(f"🔓 Unblock Device ({selected_ip})", key=f"unblock_crit_{selected_ip}"):
        try:
            resp = requests.post(f"http://{API_HOST}:{API_PORT}/unblock", json={"client_ip": selected_ip}, timeout=5)
            if resp.status_code == 200 and resp.json().get("success"):
                st.success(f"Device {selected_ip} unblocked!")
                time.sleep(1)
                st.rerun()
        except Exception as e:
            st.error(f"Error unblocking: {e}")

elif vnc_active and selected_ip:
    col_block, col_dummy = st.columns([1, 1])
    with col_block:
        if st.button(f"🚨 Terminate & Block Device ({selected_ip})", key=f"manual_block_{selected_ip}", help="Immediately sever VNC connection and block at Windows Firewall"):
            try:
                resp = requests.post(
                    f"http://{API_HOST}:{API_PORT}/block",
                    json={"client_ip": selected_ip, "client_port": int(sel_stats.get("client_port", 0)), "reason": "Manual Operator Action"},
                    timeout=5
                )
                if resp.status_code == 200 and resp.json().get("success"):
                    st.warning(f"Active connection severed! Device {selected_ip} blocked in Windows Firewall.")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Failed to execute block.")
            except Exception as e:
                st.error(f"Error contacting Risk API: {e}")

st.divider()


# ============================================================
# RISK SCORE
# ============================================================

st.markdown(
    '<div class="section-label">'
    'RISK SCORE'
    '</div>',
    unsafe_allow_html=True
)


st.markdown(
    f"""
    <div class="risk-score">
        {risk_score:.2f}%
    </div>
    """,
    unsafe_allow_html=True
)


st.divider()


# ============================================================
# RISK LEVEL
# ============================================================

st.markdown(
    '<div class="section-label">'
    'RISK LEVEL'
    '</div>',
    unsafe_allow_html=True
)


if risk_level == "LOW":

    st.markdown(
        '<div class="risk-low">LOW</div>',
        unsafe_allow_html=True
    )

elif risk_level == "MEDIUM":

    st.markdown(
        '<div class="risk-medium">MEDIUM</div>',
        unsafe_allow_html=True
    )

elif risk_level == "HIGH":

    st.markdown(
        '<div class="risk-high">HIGH</div>',
        unsafe_allow_html=True
    )

else:

    st.markdown(
        '<div class="risk-critical">'
        'CRITICAL'
        '</div>',
        unsafe_allow_html=True
    )


st.divider()


# ============================================================
# STATUS
# ============================================================

st.markdown(
    '<div class="section-label">'
    'STATUS'
    '</div>',
    unsafe_allow_html=True
)


if status == "THREAT":

    st.markdown(
        '<div class="threat">'
        '🔴 THREAT'
        '</div>',
        unsafe_allow_html=True
    )

else:

    st.markdown(
        '<div class="normal">'
        '🟢 NORMAL'
        '</div>',
        unsafe_allow_html=True
    )


st.divider()


# ============================================================
# RECOMMENDED ACTION
# ============================================================

st.markdown(
    '<div class="action-label">'
    'RECOMMENDED ACTION'
    '</div>',
    unsafe_allow_html=True
)


if recommended_action == "MONITOR":

    st.markdown(
        '<div class="action-safe">'
        'MONITOR'
        '</div>',
        unsafe_allow_html=True
    )

else:

    st.markdown(
        f"""
        <div class="action-value">
            {recommended_action}
        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# LIVE NETWORK INFORMATION
# ============================================================

with st.expander(
    "Live Network Details"
):

    col1, col2 = st.columns(2)

    with col1:

        st.metric(
            "Forward Packets",
            forward_packets
        )

        st.metric(
            "Bytes / Second",
            f"{bytes_per_second:,.2f}"
        )

        st.metric(
            "Protocol",
            protocol
        )

    with col2:

        st.metric(
            "Backward Packets",
            backward_packets
        )

        st.metric(
            "Packets / Second",
            f"{packets_per_second:,.2f}"
        )

        st.metric(
            "Session Duration",
            session_duration_display
        )

# ============================================================
# LIVE RISK TREND GRAPH
# ============================================================
st.divider()
st.markdown(
    '<div class="section-label">'
    'LIVE RISK TREND (Last 60s)'
    '</div>',
    unsafe_allow_html=True
)
history_df = pd.DataFrame(
    st.session_state.risk_history, 
    columns=["Risk Score (%)"]
)
history_df.index.name = "Time (Last 60s)"

st.line_chart(
    history_df, 
    use_container_width=True, 
    height=150,
    x_label="Time (Last 60s)",
    y_label="Risk Score (%)"
)


# ============================================================
# RECENT ALERTS (Active Device Only)
# ============================================================
st.divider()
st.markdown(
    '<div class="section-label">'
    f'RECENT ALERTS ({selected_ip})'
    '</div>',
    unsafe_allow_html=True
)

try:
    recent_alerts = get_recent_alerts(limit=5, client_ip=selected_ip)
    
    if not recent_alerts.empty:
        # Format the risk score as a percentage, handling bytes if API wasn't restarted
        import struct
        def format_risk_score(x):
            if isinstance(x, bytes):
                try:
                    x = struct.unpack('f', x)[0]
                except Exception:
                    x = 0.0
            elif pd.isna(x):
                x = 0.0
            return f"{float(x):.2f}%"
            
        recent_alerts['risk_score'] = recent_alerts['risk_score'].apply(format_risk_score)
        
        display_cols = ['timestamp', 'client_ip']
        if 'client_port' in recent_alerts.columns:
            display_cols.append('client_port')
        display_cols.extend(['risk_score', 'risk_level', 'status', 'recommended_action'])
        
        st.dataframe(
            recent_alerts[display_cols],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info(f"No alerts recorded yet for device {selected_ip}.")
except Exception as e:
    st.warning(f"Unable to read alerts log: {e}")


# ============================================================
# HIGH RISK HISTORY (Active Device Only)
# ============================================================
st.divider()
st.markdown(
    '<div class="section-label">'
    f'HIGH RISK HISTORY ({selected_ip})'
    '</div>',
    unsafe_allow_html=True
)

try:
    high_risk_alerts = get_high_risk_alerts(client_ip=selected_ip)
    
    if not high_risk_alerts.empty:
        high_risk_alerts['risk_score'] = high_risk_alerts['risk_score'].apply(format_risk_score)
        
        hr_display_cols = ['timestamp', 'client_ip']
        if 'client_port' in high_risk_alerts.columns:
            hr_display_cols.append('client_port')
        hr_display_cols.extend(['risk_score', 'risk_level', 'status', 'recommended_action', 'bytes_per_second'])
        
        st.dataframe(
            high_risk_alerts[hr_display_cols],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.success(f"No high risk alerts recorded for device {selected_ip}. Device is safe!")
except Exception as e:
    st.warning(f"Unable to read high risk alerts log: {e}")


# ============================================================
# ACTIVE FIREWALL BLOCKS
# ============================================================
try:
    blocked_df = get_blocked_devices()
    if not blocked_df.empty:
        st.divider()
        st.markdown(
            '<div class="section-label">'
            'FIREWALL BLOCKED DEVICES'
            '</div>',
            unsafe_allow_html=True
        )
        st.dataframe(
            blocked_df[['timestamp', 'client_ip', 'client_port', 'reason', 'status']],
            use_container_width=True,
            hide_index=True
        )
except Exception:
    pass


# ============================================================
# LAST UPDATED
# ============================================================

st.markdown(
    f"""
    <div class="last-updated">
        Last Updated&nbsp;&nbsp; {last_updated}
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer-text">
        SMARTVNC • Real-Time VNC Security Monitoring
    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# AUTO REFRESH
# ============================================================

time.sleep(1)

st.rerun()