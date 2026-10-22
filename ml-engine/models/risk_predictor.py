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

    probability = threat_probability * 100

    if probability < 25:
        return "LOW"

    elif probability < 50:
        return "MEDIUM"

    elif probability < 75:
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
    protocol
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
    # VNC DATA EXFILTRATION SURGE & BASELINE FUSION ENGINE
    # --------------------------------------------------------
    # In VNC (Port 5900), normal interactive screen updates are < 150 KB/s.
    # When an attacker transfers files (huge zip, documents, databases),
    # bytes_per_second surges into hundreds of KB/s or MB/s.
    # When idle or normal typing (< 150 KB/s), the connection is safe
    # and must not be false-alarmed by cumulative packet counter drift.
    # --------------------------------------------------------
    if bytes_per_second < 80000:
        # Idle / minimal screen changes (< 80 KB/s):
        # Guaranteed LOW risk (10.0% to 18.0%)
        risk_score = 10.0 + min(8.0, (bytes_per_second / 80000.0) * 8.0)
    elif bytes_per_second < 150000:
        # Normal typing / navigation / UI interactions (80 KB/s to 150 KB/s):
        # Guaranteed LOW risk (18.0% to 24.5%)
        risk_score = 18.0 + ((bytes_per_second - 80000.0) / 70000.0) * 6.5
    elif bytes_per_second < 500000:
        # Moderate transfer / continuous scrolling (150 KB/s to 500 KB/s):
        # MEDIUM risk (25.0% to 49.0%)
        surge = 25.0 + ((bytes_per_second - 150000.0) / 350000.0) * 24.0
        risk_score = max(surge, min(49.0, ml_risk_score))
    elif bytes_per_second < 1500000:
        # Active file transfer (500 KB/s to 1.5 MB/s):
        # HIGH risk (50.0% to 74.0%)
        surge = 50.0 + ((bytes_per_second - 500000.0) / 1000000.0) * 24.0
        risk_score = max(surge, min(74.0, ml_risk_score))
    else:
        # Massive exfiltration / zip archive download (>= 1.5 MB/s):
        # CRITICAL risk (75.0% to 98.0%)
        surge = 75.0 + min(23.0, (bytes_per_second - 1500000.0) / 2500000.0 * 23.0)
        risk_score = min(98.0, max(surge, ml_risk_score))

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