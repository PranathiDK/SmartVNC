import pandas as pd
import numpy as np
import joblib

from pathlib import Path


# ============================================================
# SMARTVNC - Network Risk Engine
# ============================================================
#
# Uses the EXISTING:
#   - scaler.pkl
#   - final_xgboost_150.pkl
#
# No retraining is performed.
#
# Invalid CICIDS records are explicitly marked as INVALID_DATA.
# ============================================================


BASE_DIR = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------
# Input
# ------------------------------------------------------------

INPUT_FILE = (
    BASE_DIR
    / "datasets"
    / "ml_ready"
    / "cicids_ml_ready.csv"
)


# ------------------------------------------------------------
# Existing scaler
# ------------------------------------------------------------

SCALER_FILE = (
    BASE_DIR
    / "datasets"
    / "ml_ready"
    / "scaler.pkl"
)


# ------------------------------------------------------------
# Existing XGBoost model
# ------------------------------------------------------------

MODEL_FILE = (
    BASE_DIR
    / "ml-engine"
    / "models"
    / "saved_models"
    / "final_xgboost_150.pkl"
)


# ------------------------------------------------------------
# Output
# ------------------------------------------------------------

OUTPUT_DIR = (
    BASE_DIR
    / "datasets"
    / "risk"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "network_risk.csv"
)


# ============================================================
# Model features
# ============================================================

FEATURE_COLUMNS = [
    "session_duration",
    "forward_packets",
    "backward_packets",
    "bytes_per_second",
    "packets_per_second",
    "protocol",
]


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 70)
    print("SMARTVNC - NETWORK RISK ENGINE")
    print("=" * 70)

    # --------------------------------------------------------
    # 1. Load ML-ready dataset
    # --------------------------------------------------------

    print("\nLoading CICIDS ML-ready dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(
        f"Records loaded: {len(df):,}"
    )

    # --------------------------------------------------------
    # 2. Validate columns
    # --------------------------------------------------------

    required_columns = (
        FEATURE_COLUMNS + ["target"]
    )

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:

        raise ValueError(
            f"Missing required columns: "
            f"{missing_columns}"
        )

    # --------------------------------------------------------
    # 3. Load scaler
    # --------------------------------------------------------

    print("\nLoading scaler...")

    scaler = joblib.load(
        SCALER_FILE
    )

    print(
        f"Scaler: {SCALER_FILE}"
    )

    # --------------------------------------------------------
    # 4. Load model
    # --------------------------------------------------------

    print("\nLoading XGBoost model...")

    model = joblib.load(
        MODEL_FILE
    )

    print(
        f"Model: {MODEL_FILE}"
    )

    print(
        f"Model type: "
        f"{type(model).__name__}"
    )

    print(
        f"Number of estimators: "
        f"{getattr(model, 'n_estimators', 'N/A')}"
    )

    print(
        f"Max depth: "
        f"{getattr(model, 'max_depth', 'N/A')}"
    )

    print(
        f"Learning rate: "
        f"{getattr(model, 'learning_rate', 'N/A')}"
    )

    print(
        f"Expected features: "
        f"{getattr(model, 'n_features_in_', 'N/A')}"
    )

    # --------------------------------------------------------
    # 5. Prepare feature matrix
    # --------------------------------------------------------

    X = df[
        FEATURE_COLUMNS
    ].apply(
        pd.to_numeric,
        errors="coerce"
    )

    # --------------------------------------------------------
    # 6. Detect invalid rows
    # --------------------------------------------------------

    finite_mask = np.isfinite(
        X.to_numpy(dtype=np.float64)
    ).all(axis=1)

    valid_mask = finite_mask

    invalid_mask = ~valid_mask

    valid_count = int(
        valid_mask.sum()
    )

    invalid_count = int(
        invalid_mask.sum()
    )

    print(
        f"\nValid records  : {valid_count:,}"
    )

    print(
        f"Invalid records: {invalid_count:,}"
    )

    # --------------------------------------------------------
    # 7. Create output dataframe
    # --------------------------------------------------------

    result = df.copy()

    result["prediction"] = np.nan

    result["attack_probability"] = np.nan

    result["network_risk"] = np.nan

    result["risk_level"] = "INVALID_DATA"

    result["risk_reason"] = "Invalid network feature values"

    # --------------------------------------------------------
    # 8. Run model only on valid records
    # --------------------------------------------------------

    if valid_count > 0:

        print(
            "\nScaling valid network records..."
        )

        X_valid = X.loc[
            valid_mask
        ]

        X_scaled = scaler.transform(
            X_valid
        )

        print(
            "Running XGBoost inference..."
        )

        predictions = model.predict(
            X_scaled
        )

        probabilities = (
            model.predict_proba(
                X_scaled
            )
        )

        # ----------------------------------------------------
        # Determine attack probability
        # ----------------------------------------------------

        if probabilities.shape[1] == 2:

            attack_probability = (
                probabilities[:, 1]
            )

        else:

            attack_probability = np.max(
                probabilities,
                axis=1
            )

        # ----------------------------------------------------
        # Convert probability to risk
        # ----------------------------------------------------

        network_risk = (
            attack_probability * 100
        )

        network_risk = np.clip(
            network_risk,
            0,
            100
        )

        # ----------------------------------------------------
        # Risk level
        # ----------------------------------------------------

        risk_level = np.select(
            [
                network_risk < 40,
                network_risk < 70,
            ],
            [
                "LOW",
                "MEDIUM",
            ],
            default="HIGH"
        )

        # ----------------------------------------------------
        # Write predictions back
        # ----------------------------------------------------

        result.loc[
            valid_mask,
            "prediction"
        ] = predictions

        result.loc[
            valid_mask,
            "attack_probability"
        ] = np.round(
            attack_probability,
            6
        )

        result.loc[
            valid_mask,
            "network_risk"
        ] = np.round(
            network_risk,
            2
        )

        result.loc[
            valid_mask,
            "risk_level"
        ] = risk_level

        result.loc[
            valid_mask,
            "risk_reason"
        ] = np.where(
            network_risk >= 70,
            "High XGBoost network attack probability",
            np.where(
                network_risk >= 40,
                "Medium XGBoost network attack probability",
                "Low XGBoost network attack probability"
            )
        )

    # --------------------------------------------------------
    # 9. Preserve invalid records explicitly
    # --------------------------------------------------------

    if invalid_count > 0:

        result.loc[
            invalid_mask,
            "risk_reason"
        ] = (
            "Network features contain "
            "non-finite values"
        )

    # --------------------------------------------------------
    # 10. Save
    # --------------------------------------------------------

    print(
        "\nSaving network risk results..."
    )

    result.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # --------------------------------------------------------
    # 11. Statistics
    # --------------------------------------------------------

    print("\nRisk distribution:")

    print(
        result[
            "risk_level"
        ].value_counts()
    )

    print(
        "\nValid network risk statistics:"
    )

    valid_risk = result.loc[
        valid_mask,
        "network_risk"
    ]

    print(
        valid_risk.describe()
    )

    # --------------------------------------------------------
    # 12. Highest risk events
    # --------------------------------------------------------

    print(
        "\nTop 10 highest-risk network events:"
    )

    display_columns = [
        *FEATURE_COLUMNS,
        "target",
        "prediction",
        "attack_probability",
        "network_risk",
        "risk_level",
        "risk_reason",
    ]

    print(
        result.loc[
            valid_mask
        ]
        .sort_values(
            "network_risk",
            ascending=False
        )
        .head(10)[
            display_columns
        ]
        .to_string(
            index=False
        )
    )

    # --------------------------------------------------------
    # 13. Invalid rows
    # --------------------------------------------------------

    if invalid_count > 0:

        print(
            "\nInvalid network records:"
        )

        print(
            result.loc[
                invalid_mask,
                FEATURE_COLUMNS + [
                    "risk_level",
                    "risk_reason",
                ]
            ].to_string(
                index=True
            )
        )

    # --------------------------------------------------------
    # 14. Final
    # --------------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "NETWORK RISK ENGINE COMPLETED"
    )

    print(
        "=" * 70
    )

    print(
        "\nOutput file:"
    )

    print(
        OUTPUT_FILE
    )


if __name__ == "__main__":

    main()