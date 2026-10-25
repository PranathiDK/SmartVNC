# SmartVNC Demonstration Files Guide

This directory contains benchmark test files calibrated for testing and demonstrating SmartVNC's dual-pipeline ML risk scoring and Active Defense prevention system.

---

## 📂 File Inventory

| File Name | File Size | Target Risk Level | Target Risk Score | Action Taken |
| :--- | :---: | :---: | :---: | :---: |
| **`1_LOW_RISK_meeting_notes.txt`** | ~3.5 KB | **LOW** | 0.0% – 19.0% | MONITOR (Normal) |
| **`2_MEDIUM_RISK_quarterly_analytics.html`** | ~5.9 KB | **MEDIUM** | 25.0% – 45.0% | MONITOR (Elevated Activity) |
| **`3_HIGH_RISK_customer_records_6MB.csv`** | ~7.3 MB | **HIGH** | 55.0% – 72.0% | ALERT_AND_LOG (Warning) |
| **`4_CRITICAL_RISK_database_backup_16MB.zip`** | ~16.8 MB | **CRITICAL** | 80.0% – 96.0% | TERMINATE_AND_BLOCK (Active Defense) |

---

## 🎯 How to Use During Your Demonstration

### Step 1: Demonstrate Idle Stability (Doing Nothing)
1. Launch SmartVNC via `run_smartvnc.bat`.
2. Connect your VNC viewer (TightVNC Viewer).
3. Leave the mouse and keyboard untouched for 5–10 seconds.
4. **Show the Dashboard:**
   - Risk Score stays steady at **0.00%**.
   - Risk Level stays on **LOW**.
   - Proves the fix for false alarms: idle desktop refreshes do not fluctuate into MEDIUM.

---

### Step 2: Demonstrate Normal Operation (LOW Risk)
1. Open **`1_LOW_RISK_meeting_notes.txt`** in Notepad inside the VNC viewer.
2. Type a sentence or read through the checklist.
3. **Show the Dashboard:**
   - Bandwidth measures ~20 KB/s – 40 KB/s.
   - Risk Score remains **0.0% – 19.0%**, safely within **LOW**.
   - Proves legitimate work is accurately allowed without disruption.

---

### Step 3: Demonstrate Elevated Activity (MEDIUM Risk)
1. Double-click **`2_MEDIUM_RISK_quarterly_analytics.html`** to open it in a browser inside VNC.
2. Scroll smoothly through the data table rows.
3. **Show the Dashboard:**
   - Bandwidth reaches ~160 KB/s – 230 KB/s.
   - Risk Score stays within **25.0% – 45.0% (MEDIUM)** while viewing the file.
   - Threat status remains **NORMAL** and recommended action is **MONITOR**.
   - As soon as you stop scrolling, the score decays smoothly back to **0.00% LOW**.

---

### Step 4: Demonstrate Data Transfer Warning (HIGH Risk)
1. Open the TightVNC built-in File Transfer dialog (or initiate download of **`3_HIGH_RISK_customer_records_6MB.csv`**).
2. Transfer the file from the remote machine to your client.
3. **Show the Dashboard:**
   - Bandwidth hits ~260 KB/s – 330 KB/s.
   - The monitor confirms a transfer after **three consecutive samples above 250 KB/s**. A confirmed burst of **6 MB to less than 14 MB** raises the score to **55.0% – 72.0% (HIGH)**.
   - Status changes to **THREAT (ALERT_AND_LOG)**.
   - Warning banner appears on the dashboard with a manual **Terminate & Block** button for operator intervention.

---

### Step 5: Demonstrate Active Defense Blocking (CRITICAL Risk)
1. Transfer **`4_CRITICAL_RISK_database_backup_16MB.zip`** across the VNC connection.
2. Because this is a high-volume compressed file (> 14 MB), SmartVNC detects unauthorized bulk exfiltration after transfer confirmation. Brief pauses of less than three samples do not immediately clear the confirmed burst.
3. **Observe the Active Defense in Real Time:**
   - A sustained transfer burst of **14 MB or more** raises the score to **80.0% – 96.0% (CRITICAL)**.
   - Status switches to **TERMINATE_AND_BLOCK**.
   - SmartVNC immediately triggers bidirectional **Scapy TCP RST injection** and creates a Windows Firewall rule.
   - The VNC viewer immediately disconnects with a connection severed alert.
   - The dashboard updates to display: **"🛑 ACTIVE DEFENSE ENFORCED: Client connection has been TERMINATED and is actively BLOCKED."**
   - The blocked IP appears in the Firewall Blocked Devices table.
   - Clicking **"🔓 Unblock Device"** on the dashboard restores access.
