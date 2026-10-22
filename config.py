import os

# Network configuration
HOST_IP = os.getenv("SMARTVNC_HOST_IP", "10.228.16.167")
CLIENT_IP = os.getenv("SMARTVNC_CLIENT_IP", "10.228.16.111")
VNC_PORT = int(os.getenv("SMARTVNC_PORT", 5900))

# API configuration
API_HOST = os.getenv("SMARTVNC_API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("SMARTVNC_API_PORT", 5000))
API_URL = f"http://{API_HOST}:{API_PORT}/predict"
