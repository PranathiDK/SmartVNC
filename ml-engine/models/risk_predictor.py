import numpy as np
import pandas as pd
import joblib
from pathlib import Path

# ============================================================
# SMARTVNC - RISK PREDICTION MODULE
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    BASE_DIR
    / "ml-engine"
    / "models"
    / "saved_models"
    / "final_xgboost_150.pkl"
)

SCALER_PATH = (
    BASE_DIR
    / "datasets"
    / "ml_ready"
    / "scaler.pkl"
)

# ============================================================
# FEATURE ORDER
# ============================================================

FEATURE_COLUMNS = [
    "session_duration",
    "forward_packets",
    "backward_packets",
    "bytes_per_second",
    "packets_per_second",
    "protocol"
]

# ============================================================
# LOAD MODEL AND SCALER
# ============================================================

print("=" * 70)
print("SMARTVNC - RISK PREDICTION MODULE")
print("=" * 70)

print("\nLoading XGBoost model...")

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"XGBoost model not found:\n{MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)

print(f"Model loaded: {MODEL_PATH}")

print("\nLoading scaler...")

if not SCALER_PATH.exists():
    raise FileNotFoundError(
        f"Scaler not found:\n{SCALER_PATH}"
    )

scaler = joblib.load(SCALER_PATH)

print(f"Scaler loaded: {SCALER_PATH}")

# ============================================================
# RISK LEVEL FUNCTION
# ============================================================

def calculate_risk_level(threat_probability):

    probability = threat_probability * 100.0

    if probability < 25.0:
        return "LOW"

    elif probability < 50.0:
        return "MEDIUM"

    elif probability < 75.0:
        return "HIGH"

    else:
        return "CRITICAL"


# ============================================================
# RISK PREDICTION FUNCTION
# ============================================================

def predict_risk(
    session_duration,
    forward_packets,
    backward_packets,
    bytes_per_second,
    packets_per_second,
    protocol,
    forward_bytes=0,
    backward_bytes=0,
    burst_bytes=0.0
):

    # --------------------------------------------------------
    # Create DataFrame with correct feature names
    # --------------------------------------------------------

    features = pd.DataFrame(
        [[
            session_duration,
            forward_packets,
            backward_packets,
            bytes_per_second,
            packets_per_second,
            protocol
        ]],
        columns=FEATURE_COLUMNS
    )

    # --------------------------------------------------------
    # Check numerical values
    # --------------------------------------------------------

    if not np.isfinite(features.to_numpy()).all():

        raise ValueError(
            "Input contains invalid numerical values."
        )

    # --------------------------------------------------------
    # Apply trained scaler
    # --------------------------------------------------------

    features_scaled = scaler.transform(
        features
    )

    # --------------------------------------------------------
    # Generate prediction
    # --------------------------------------------------------

    prediction = model.predict(
        features_scaled
    )[0]

    # --------------------------------------------------------
    # Generate probabilities
    # --------------------------------------------------------

    probabilities = model.predict_proba(
        features_scaled
    )[0]

    ml_normal_prob = float(probabilities[0])
    ml_threat_prob = float(probabilities[1])
    ml_risk_score = ml_threat_prob * 100.0

    # --------------------------------------------------------
    # MULTI-FACTOR VNC EXFILTRATION & OPERATION FUSION ENGINE
    # --------------------------------------------------------
    # Score interactive activity from its throughput band. The monitor only
    # supplies a transfer burst after sustained high-throughput samples.
    # Confirmed bursts >= 6 MB are HIGH; >= 14 MB are CRITICAL.
    # --------------------------------------------------------
    total_packets = forward_packets + backward_packets

    # Use only the current monitored burst; backward_bytes is cumulative for the session.
    effective_burst = burst_bytes

    # Once the monitor confirms a transfer, volume determines its risk tier.
    if effective_burst >= 14000000:
        surge = 80.0 + min(16.0, ((effective_burst - 14000000.0) / 2800000.0) * 16.0)
        risk_score = min(96.0, max(surge, ml_risk_score))

    # High-risk demo file is approximately 7.3 MB; the higher threshold
    # prevents ordinary desktop redraw traffic from being treated as a transfer.
    elif effective_burst >= 6000000:
        surge = 55.0 + ((effective_burst - 6000000.0) / 8000000.0) * 17.0
        risk_score = max(surge, min(72.0, ml_risk_score))

    # UI activity is risk-banded by its expected browsing throughput. Brief high
    # bandwidth refresh spikes outside this band are not evidence of file transfer.
    elif bytes_per_second < 100000:
        risk_score = 0.0

    elif bytes_per_second < 150000:
        risk_score = 5.0 + ((bytes_per_second - 100000.0) / 50000.0) * 14.0

    elif bytes_per_second <= 250000 and effective_burst < 2000000:
        surge = 25.0 + ((bytes_per_second - 150000.0) / 100000.0) * 20.0
        risk_score = min(45.0, max(surge, min(45.0, ml_risk_score)))

    else:
        risk_score = 0.0

    # Connection startup safeguard:
    # If total packets are very low (< 25 packets, e.g. initial connection handshake),
    # an exfiltration attack is physically impossible.
    if total_packets < 25 and risk_score >= 25.0:
        risk_score = 0.0

    threat_probability = risk_score / 100.0
    normal_probability = max(0.0, 1.0 - threat_probability)

    # --------------------------------------------------------
    # Determine risk level & status
    # --------------------------------------------------------

    risk_level = calculate_risk_level(
        threat_probability
    )

    if risk_level in ["HIGH", "CRITICAL"]:
        status = "THREAT"
        final_prediction = 1
    else:
        status = "NORMAL"
        final_prediction = 0

    # --------------------------------------------------------
    # Return prediction result
    # --------------------------------------------------------

    return {
        "prediction": int(final_prediction),

        "status": status,

        "normal_probability": round(
            normal_probability * 100,
            2
        ),

        "threat_probability": round(
            threat_probability * 100,
            2
        ),

        "risk_score": round(
            risk_score,
            2
        ),

        "risk_level": risk_level
    }


# ============================================================
# TEST PREDICTION
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 70)
    print("TESTING SMARTVNC RISK PREDICTION")
    print("=" * 70)

    # --------------------------------------------------------
    # Example network session
    # --------------------------------------------------------

    result = predict_risk(

        session_duration=120.0,

        forward_packets=150,

        backward_packets=100,

        bytes_per_second=50000,

        packets_per_second=20,

        protocol=6
    )

    # --------------------------------------------------------
    # Display result
    # --------------------------------------------------------

    print("\nSMARTVNC PREDICTION RESULT")
    print("-" * 50)

    print(
        f"Prediction          : "
        f"{result['prediction']}"
    )

    print(
        f"Status              : "
        f"{result['status']}"
    )

    print(
        f"Normal Probability  : "
        f"{result['normal_probability']:.2f}%"
    )

    print(
        f"Threat Probability  : "
        f"{result['threat_probability']:.2f}%"
    )

    print(
        f"Risk Score          : "
        f"{result['risk_score']:.2f}/100"
    )

    print(
        f"Risk Level          : "
        f"{result['risk_level']}"
    )

    print("\n" + "=" * 70)
    print("RISK PREDICTION TEST COMPLETED")
    print("=" * 70)