import numpy as np
import pandas as pd
import joblib
from pathlib import Path

# ============================================================
# SMARTVNC - BATCH RISK DETECTION MODULE
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

# ============================================================
# FILE PATHS
# ============================================================

INPUT_FILE = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "cicids_processed.csv"
)

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

OUTPUT_FILE = (
    BASE_DIR
    / "datasets"
    / "risk"
    / "smartvnc_batch_risk_results.csv"
)

OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
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
# RISK LEVEL
# ============================================================

def calculate_risk_level(risk_score):

    if risk_score < 25:
        return "LOW"

    elif risk_score < 50:
        return "MEDIUM"

    elif risk_score < 75:
        return "HIGH"

    else:
        return "CRITICAL"


# ============================================================
# RECOMMENDED ACTION
# ============================================================

def get_recommended_action(risk_level):

    if risk_level == "LOW":
        return "MONITOR"

    elif risk_level == "MEDIUM":
        return "REVIEW"

    elif risk_level == "HIGH":
        return "INVESTIGATE"

    elif risk_level == "CRITICAL":
        return "IMMEDIATE ACTION"

    return "UNKNOWN"


# ============================================================
# MAIN BATCH PROCESS
# ============================================================

def main():

    print("=" * 70)
    print("SMARTVNC - BATCH RISK DETECTION MODULE")
    print("=" * 70)

    # --------------------------------------------------------
    # Check input file
    # --------------------------------------------------------

    print("\nChecking input dataset...")

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"\nProcessed CICIDS dataset not found:\n{INPUT_FILE}"
        )

    print(f"Input dataset: {INPUT_FILE}")

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    print("\nLoading processed CICIDS dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(f"Dataset shape: {df.shape[0]:,} rows x {df.shape[1]} columns")

    print("\nDataset columns:")
    print(list(df.columns))

    # --------------------------------------------------------
    # Check required features
    # --------------------------------------------------------

    print("\nChecking required ML features...")

    missing_features = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in df.columns
    ]

    if missing_features:

        raise ValueError(
            "\nMissing required features:\n"
            + "\n".join(missing_features)
        )

    print("All 6 ML features found.")

    # --------------------------------------------------------
    # Preserve original target / label
    # --------------------------------------------------------

    target_columns = []

    for column in ["target", "label"]:

        if column in df.columns:
            target_columns.append(column)

    if target_columns:

        print(
            f"\nOriginal class information found: "
            f"{target_columns}"
        )

    else:

        print(
            "\nNo target/label column found. "
            "Predictions will still be generated."
        )

    # --------------------------------------------------------
    # Select features
    # --------------------------------------------------------

    print("\nSelecting 6 ML features...")

    features = df[FEATURE_COLUMNS].copy()

    # --------------------------------------------------------
    # Convert features to numeric
    # --------------------------------------------------------

    print("Converting features to numeric...")

    for column in FEATURE_COLUMNS:

        features[column] = pd.to_numeric(
            features[column],
            errors="coerce"
        )

    # --------------------------------------------------------
    # Replace infinity with NaN
    # --------------------------------------------------------

    infinity_count = np.isinf(
        features.to_numpy()
    ).sum()

    if infinity_count > 0:

        print(
            f"Replacing {infinity_count:,} "
            "infinite values with NaN..."
        )

        features = features.replace(
            [np.inf, -np.inf],
            np.nan
        )

    # --------------------------------------------------------
    # Remove rows containing NaN
    # --------------------------------------------------------

    rows_before = len(features)

    valid_mask = features.notna().all(axis=1)

    invalid_rows = (~valid_mask).sum()

    if invalid_rows > 0:

        print(
            f"Removing {invalid_rows:,} rows "
            "containing NaN/invalid values..."
        )

    # Keep only valid rows
    features = features.loc[valid_mask].copy()
    df_valid = df.loc[valid_mask].copy()

    print(
        f"Valid rows for prediction: "
        f"{len(features):,}"
    )

    if len(features) == 0:

        raise ValueError(
            "No valid rows remain after data cleaning."
        )

    # --------------------------------------------------------
    # Load scaler
    # --------------------------------------------------------

    print("\nLoading trained scaler...")

    if not SCALER_PATH.exists():

        raise FileNotFoundError(
            f"\nScaler not found:\n{SCALER_PATH}"
        )

    scaler = joblib.load(SCALER_PATH)

    print(f"Scaler loaded: {SCALER_PATH}")

    # --------------------------------------------------------
    # Load XGBoost model
    # --------------------------------------------------------

    print("\nLoading trained XGBoost model...")

    if not MODEL_PATH.exists():

        raise FileNotFoundError(
            f"\nXGBoost model not found:\n{MODEL_PATH}"
        )

    model = joblib.load(MODEL_PATH)

    print(f"Model loaded: {MODEL_PATH}")

    # --------------------------------------------------------
    # Scale features
    # --------------------------------------------------------

    print("\nScaling features...")

    features_scaled = scaler.transform(
        features
    )

    print("Feature scaling completed.")

    # --------------------------------------------------------
    # Generate predictions
    # --------------------------------------------------------

    print("\nGenerating predictions...")

    predictions = model.predict(
        features_scaled
    )

    probabilities = model.predict_proba(
        features_scaled
    )

    print("Predictions generated.")

    # --------------------------------------------------------
    # Extract probabilities
    # --------------------------------------------------------

    normal_probability = probabilities[:, 0]

    threat_probability = probabilities[:, 1]

    # Risk score = threat probability * 100
    risk_score = threat_probability * 100

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    risk_levels = [
        calculate_risk_level(score)
        for score in risk_score
    ]

    # --------------------------------------------------------
    # Recommended action
    # --------------------------------------------------------

    recommended_actions = [
        get_recommended_action(level)
        for level in risk_levels
    ]

    # --------------------------------------------------------
    # Create results
    # --------------------------------------------------------

    print("\nCreating batch risk results...")

    results = df_valid.copy()

    results["prediction"] = predictions.astype(int)

    results["status"] = np.where(
        predictions == 1,
        "THREAT",
        "NORMAL"
    )

    results["normal_probability"] = (
        normal_probability * 100
    ).round(2)

    results["threat_probability"] = (
        threat_probability * 100
    ).round(2)

    results["risk_score"] = (
        risk_score
    ).round(2)

    results["risk_level"] = risk_levels

    results["recommended_action"] = (
        recommended_actions
    )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    print("\nSaving results...")

    results.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(f"Results saved to:\n{OUTPUT_FILE}")

    # ========================================================
    # SUMMARY
    # ========================================================

    print("\n" + "=" * 70)
    print("BATCH PREDICTION SUMMARY")
    print("=" * 70)

    print(
        f"\nOriginal rows       : {rows_before:,}"
    )

    print(
        f"Invalid rows removed: {invalid_rows:,}"
    )

    print(
        f"Rows predicted      : {len(results):,}"
    )

    # --------------------------------------------------------
    # Prediction distribution
    # --------------------------------------------------------

    print("\nPrediction Distribution")
    print("-" * 40)

    prediction_counts = results["prediction"].value_counts()

    normal_count = prediction_counts.get(0, 0)
    threat_count = prediction_counts.get(1, 0)

    print(
        f"NORMAL : {normal_count:,} "
        f"({normal_count / len(results) * 100:.2f}%)"
    )

    print(
        f"THREAT : {threat_count:,} "
        f"({threat_count / len(results) * 100:.2f}%)"
    )

    # --------------------------------------------------------
    # Risk level distribution
    # --------------------------------------------------------

    print("\nRisk Level Distribution")
    print("-" * 40)

    risk_counts = results["risk_level"].value_counts()

    for level in [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]:

        count = risk_counts.get(level, 0)

        print(
            f"{level:<8}: "
            f"{count:,} "
            f"({count / len(results) * 100:.2f}%)"
        )

    # --------------------------------------------------------
    # Average risk
    # --------------------------------------------------------

    print("\nRisk Statistics")
    print("-" * 40)

    print(
        f"Average Risk Score : "
        f"{results['risk_score'].mean():.2f}"
    )

    print(
        f"Minimum Risk Score : "
        f"{results['risk_score'].min():.2f}"
    )

    print(
        f"Maximum Risk Score : "
        f"{results['risk_score'].max():.2f}"
    )

    # --------------------------------------------------------
    # Original target/label distribution
    # --------------------------------------------------------

    for column in target_columns:

        print(
            f"\nOriginal '{column}' Distribution"
        )

        print("-" * 40)

        print(
            results[column]
            .value_counts()
            .to_string()
        )

    # ========================================================
    # COMPLETED
    # ========================================================

    print("\n" + "=" * 70)
    print("SMARTVNC BATCH RISK DETECTION COMPLETED")
    print("=" * 70)

    print(
        f"\nOutput file:\n{OUTPUT_FILE}"
    )

    print(
        f"\nTotal sessions processed: "
        f"{len(results):,}"
    )


# ============================================================
# RUN MODULE
# ============================================================

if __name__ == "__main__":
    main()