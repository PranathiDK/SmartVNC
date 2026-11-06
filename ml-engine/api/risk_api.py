from flask import Flask, request, jsonify
import sys
from pathlib import Path

# ============================================================
# SMARTVNC - RISK PREDICTION API
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

MODELS_DIR = BASE_DIR / "ml-engine" / "models"

# Allow importing risk_alert_engine.py
sys.path.append(str(MODELS_DIR))
sys.path.append(str(BASE_DIR))

from risk_alert_engine import process_session
from config import API_HOST, API_PORT


# ============================================================
# CREATE FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "ONLINE",
        "service": "SMARTVNC Risk API"
    })


# ============================================================
# RISK PREDICTION
# ============================================================

@app.route("/predict", methods=["POST"])
def predict():

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "error": "No JSON data received"
            }), 400

        # ----------------------------------------------------
        # Required features
        # ----------------------------------------------------

        required_fields = [
            "session_duration",
            "forward_packets",
            "backward_packets",
            "bytes_per_second",
            "packets_per_second",
            "protocol"
        ]

        # ----------------------------------------------------
        # Check missing fields
        # ----------------------------------------------------

        missing_fields = [
            field
            for field in required_fields
            if field not in data
        ]

        if missing_fields:

            return jsonify({
                "error": "Missing required fields",
                "missing_fields": missing_fields
            }), 400

        # ----------------------------------------------------
        # Convert values to numbers
        # ----------------------------------------------------

        session_duration = float(
            data["session_duration"]
        )

        forward_packets = float(
            data["forward_packets"]
        )

        backward_packets = float(
            data["backward_packets"]
        )

        bytes_per_second = float(
            data["bytes_per_second"]
        )

        packets_per_second = float(
            data["packets_per_second"]
        )

        protocol = float(
            data["protocol"]
        )
        
        client_ip = data.get("client_ip", "Unknown")
        client_port = int(data.get("client_port", 0))
        forward_bytes = float(data.get("forward_bytes", 0.0))
        backward_bytes = float(data.get("backward_bytes", 0.0))
        burst_bytes = float(data.get("burst_bytes", 0.0))

        # ----------------------------------------------------
        # Run SMARTVNC risk engine
        # ----------------------------------------------------

        result = process_session(

            session_duration=session_duration,

            forward_packets=forward_packets,

            backward_packets=backward_packets,

            bytes_per_second=bytes_per_second,

            packets_per_second=packets_per_second,

            protocol=protocol,
            
            client_ip=client_ip,

            client_port=client_port,

            forward_bytes=forward_bytes,

            backward_bytes=backward_bytes,

            burst_bytes=burst_bytes
        )

        # ----------------------------------------------------
        # Return result
        # ----------------------------------------------------

        return jsonify({

    "success": True,

    "input": {
        "session_duration": float(session_duration),
        "forward_packets": float(forward_packets),
        "backward_packets": float(backward_packets),
        "bytes_per_second": float(bytes_per_second),
        "packets_per_second": float(packets_per_second),
        "protocol": float(protocol)
    },

    "prediction": int(result["prediction"]),

    "status": str(result["status"]),

    "normal_probability": float(
        result["normal_probability"]
    ),

    "threat_probability": float(
        result["threat_probability"]
    ),

    "risk_score": float(
        result["risk_score"]
    ),

    "risk_level": str(
        result["risk_level"]
    ),

    "recommended_action": str(
        result["recommended_action"]
    )
})

    except ValueError as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 400

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# ============================================================
# ACTIVE DEFENSE CONTROL ENDPOINTS
# ============================================================

@app.route("/block", methods=["POST"])
def block_device():
    try:
        data = request.get_json() or {}
        client_ip = data.get("client_ip")
        reason = data.get("reason", "Manual Operator Defense Action")
        if not client_ip:
            return jsonify({"success": False, "error": "Missing client_ip"}), 400
            
        from vnc_prevention import enforce_block
        success, msg = enforce_block(client_ip, reason=reason)
        return jsonify({"success": success, "message": msg})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/unblock", methods=["POST"])
def unblock_device():
    try:
        data = request.get_json() or {}
        client_ip = data.get("client_ip")
        if not client_ip:
            return jsonify({"success": False, "error": "Missing client_ip"}), 400
            
        from vnc_prevention import enforce_unblock
        from risk_alert_engine import clear_blocked_cache
        clear_blocked_cache(client_ip)
        success, msg = enforce_unblock(client_ip)
        return jsonify({"success": success, "message": msg})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/blocked", methods=["GET"])
def list_blocked():
    try:
        from database.db_manager import get_blocked_devices
        df = get_blocked_devices()
        return jsonify({"success": True, "blocked": df.to_dict(orient="records")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# FILE TRANSFER ACCESS CONTROL & CLASSIFICATION ENDPOINTS
# ============================================================

@app.route("/file-transfer/classify", methods=["POST"])
def classify_file():
    try:
        data = request.get_json() or {}
        file_name = data.get("file_name", "")
        client_ip = data.get("client_ip", "Unknown")
        client_port = int(data.get("client_port", 0))
        file_path = data.get("file_path", file_name)
        file_size_bytes = int(data.get("file_size_bytes", 0))

        if not file_name:
            return jsonify({"success": False, "error": "file_name is required"}), 400

        from file_classifier import classify_file_transfer
        result = classify_file_transfer(
            file_name=file_name,
            client_ip=client_ip,
            client_port=client_port,
            file_path=file_path,
            file_size_bytes=file_size_bytes
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/file-transfer/policies", methods=["GET"])
def list_file_policies():
    try:
        from database.db_manager import get_file_policies
        df = get_file_policies()
        return jsonify({"success": True, "policies": df.to_dict(orient="records")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/file-transfer/policy", methods=["POST"])
def save_file_policy():
    try:
        data = request.get_json() or {}
        policy_type = data.get("policy_type", "EXTENSION")
        value = data.get("value", "").strip()
        is_allowed = int(data.get("is_allowed", 1))
        description = data.get("description", "")

        if not value:
            return jsonify({"success": False, "error": "Policy value is required"}), 400

        from database.db_manager import add_file_policy
        add_file_policy(policy_type, value, is_allowed, description)
        return jsonify({"success": True, "message": f"Policy for '{value}' updated."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/file-transfer/policy/<int:policy_id>", methods=["DELETE"])
def remove_file_policy(policy_id):
    try:
        from database.db_manager import delete_file_policy
        delete_file_policy(policy_id)
        return jsonify({"success": True, "message": f"Policy {policy_id} deleted."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/file-transfer/history", methods=["GET"])
def file_transfer_history():
    try:
        client_ip = request.args.get("client_ip")
        limit = int(request.args.get("limit", 20))
        from database.db_manager import get_recent_file_transfers
        df = get_recent_file_transfers(limit=limit, client_ip=client_ip)
        return jsonify({"success": True, "transfers": df.to_dict(orient="records")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("SMARTVNC - RISK PREDICTION API")
    print("=" * 70)

    print("\nStarting SMARTVNC Risk API...")

    print("\nEndpoints:")

    print("GET  /health")
    print("POST /predict")
    print("POST /block")
    print("POST /unblock")
    print("GET  /blocked")
    print("POST /file-transfer/classify")
    print("GET  /file-transfer/policies")
    print("POST /file-transfer/policy")
    print("GET  /file-transfer/history")

    print(f"http://{API_HOST}:{API_PORT}")

    print("\n" + "=" * 70)

    app.run(
        host=API_HOST,
        port=API_PORT,
        debug=False
    )