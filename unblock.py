import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "ml-engine"))
sys.path.append(str(BASE_DIR / "ml-engine" / "models"))

from database.db_manager import get_blocked_devices
from vnc_prevention import enforce_unblock
from risk_alert_engine import clear_blocked_cache

def unblock_all(specific_ip=None):
    if specific_ip:
        print(f"[*] Unblocking device: {specific_ip}")
        clear_blocked_cache(specific_ip)
        success, message = enforce_unblock(specific_ip)
        print(f"[+] {message}" if success else f"[!] {message}")
        return

    df = get_blocked_devices()
    if df.empty:
        print("[i] No currently blocked devices found in database.")
        # Also clean any leftover firewall rules
        enforce_unblock("127.0.0.1")
        return

    for _, row in df.iterrows():
        ip = row["client_ip"]
        print(f"[*] Unblocking device: {ip} (Reason was: {row.get('reason', 'N/A')})")
        clear_blocked_cache(ip)
        success, message = enforce_unblock(ip)
        print(f"[+] {message}" if success else f"[!] {message}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    unblock_all(target)
