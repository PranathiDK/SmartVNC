import time
import os
import sys
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "ml-engine"))
sys.path.append(str(BASE_DIR / "ml-engine" / "models"))

from file_classifier import classify_file_transfer
from live_data import read_live_data

# ============================================================
# SMARTVNC - FILE TRANSFER DIRECTORY WATCHER
# ============================================================
# Monitors designated transfer directory for incoming or staged files.
# Evaluates each file against the Server Access Policy.
# If an unauthorized file is found, the active VNC device is blocked.
# ============================================================

DEFAULT_WATCH_DIR = BASE_DIR / "vnc_transfers"
DEFAULT_WATCH_DIR.mkdir(parents=True, exist_ok=True)

class FileTransferMonitor:
    def __init__(self, watch_dir=DEFAULT_WATCH_DIR, poll_interval=1.0):
        self.watch_dir = Path(watch_dir)
        self.poll_interval = poll_interval
        self.seen_files = set()
        self._init_seen_files()

    def _init_seen_files(self):
        if self.watch_dir.exists():
            for p in self.watch_dir.iterdir():
                if p.is_file():
                    self.seen_files.add(p.name)

    def scan_once(self):
        """Scans the directory for newly transferred or accessed files."""
        if not self.watch_dir.exists():
            return []

        # Find active client IP from live session data
        live_info = read_live_data() or {}
        vnc_active = live_info.get("vnc_active", False)
        active_ip = live_info.get("client_ip", "Unknown")
        client_port = live_info.get("client_port", 0)

        results = []
        current_files = set()

        for p in self.watch_dir.iterdir():
            if not p.is_file():
                continue
            current_files.add(p.name)

            if p.name not in self.seen_files:
                self.seen_files.add(p.name)
                try:
                    file_size = p.stat().st_size
                except Exception:
                    file_size = 0

                print(f"\n[📁] File Transfer Detected in Watch Folder: '{p.name}' ({file_size} bytes)")
                print(f"     Associated Client IP: {active_ip}")

                # Classify against server policy
                res = classify_file_transfer(
                    file_name=p.name,
                    client_ip=active_ip,
                    client_port=client_port,
                    file_path=str(p),
                    file_size_bytes=file_size
                )
                results.append(res)

                # If violation, quarantine/delete the unauthorized file
                if res.get("classification") == "ACCESS_NOT_ALLOWED":
                    quarantine_name = p.with_suffix(p.suffix + ".BLOCKED_QUARANTINE")
                    try:
                        p.rename(quarantine_name)
                        print(f"[🛡️] Quarantined unauthorized file to: {quarantine_name.name}")
                    except Exception as e:
                        print(f"[!] Could not quarantine file: {e}")

        # Remove deleted files from seen set
        self.seen_files = self.seen_files.intersection(current_files)
        return results

    def run_loop(self):
        print("=" * 70)
        print("SMARTVNC - FILE TRANSFER POLICY MONITOR")
        print("=" * 70)
        print(f"Monitoring folder: {self.watch_dir.resolve()}")
        print("Enforcing: ALLOWED vs NOT ALLOWED Server Access Policies")
        print("Press CTRL+C to stop.\n")

        while True:
            try:
                self.scan_once()
                time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Error in file transfer monitor loop: {e}")
                time.sleep(self.poll_interval)

if __name__ == "__main__":
    monitor = FileTransferMonitor()
    monitor.run_loop()
