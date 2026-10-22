import pandas as pd
import numpy as np
from pathlib import Path


# ============================================================
# SMARTVNC - CERT Host Risk Engine
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[1]

INPUT_FILE = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "cert_processed.csv"
)

OUTPUT_DIR = (
    BASE_DIR
    / "datasets"
    / "risk"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "host_risk.csv"


# ============================================================
# Configuration
# ============================================================

# File types that deserve additional attention.
# These are NOT considered malicious by themselves.
HIGH_ATTENTION_EXTENSIONS = {
    ".exe": 15,
    ".zip": 10,
}

MODERATE_ATTENTION_EXTENSIONS = {
    ".doc": 5,
    ".pdf": 5,
    ".txt": 3,
}


# ============================================================
# Utility functions
# ============================================================

def extension_score(file_name):
    """
    Return a small risk contribution based on file extension.

    This is only an activity/risk signal.
    It does NOT mean that the file itself is malicious.
    """

    if pd.isna(file_name) or file_name == "No File":
        return 0

    file_name = str(file_name).lower()

    extension = Path(file_name).suffix

    if extension in HIGH_ATTENTION_EXTENSIONS:
        return HIGH_ATTENTION_EXTENSIONS[extension]

    if extension in MODERATE_ATTENTION_EXTENSIONS:
        return MODERATE_ATTENTION_EXTENSIONS[extension]

    return 0


def calculate_host_risk(df):
    """
    Calculate an explainable 0-100 host risk score
    for every CERT event.
    """

    result = df.copy()

    # --------------------------------------------------------
    # Basic activity signals
    # --------------------------------------------------------

    result["usb_score"] = np.where(
        result["usb_activity"].eq("Connect"),
        15,
        0
    )

    result["login_score"] = np.where(
        result["login_activity"].eq("Logon"),
        5,
        0
    )

    result["file_score"] = np.where(
        result["file_name"].ne("No File"),
        10,
        0
    )

    # --------------------------------------------------------
    # File extension signal
    # --------------------------------------------------------

    result["extension_score"] = (
        result["file_name"]
        .apply(extension_score)
    )

    # --------------------------------------------------------
    # User-computer frequency
    # --------------------------------------------------------
    #
    # Rare user-computer relationships receive a small
    # anomaly contribution.
    #
    # We use the COMPLETE CERT dataset to establish
    # historical behavior.
    # --------------------------------------------------------

    pair_counts = (
        result
        .groupby(["user", "computer"])
        .size()
        .rename("pair_event_count")
        .reset_index()
    )

    result = result.merge(
        pair_counts,
        on=["user", "computer"],
        how="left"
    )

    result["relationship_score"] = np.select(
        [
            result["pair_event_count"] <= 2,
            result["pair_event_count"] <= 5,
        ],
        [
            15,
            8,
        ],
        default=0
    )

    # --------------------------------------------------------
    # User activity frequency
    # --------------------------------------------------------

    user_counts = (
        result
        .groupby("user")
        .size()
        .rename("user_event_count")
        .reset_index()
    )

    result = result.merge(
        user_counts,
        on="user",
        how="left"
    )

    # Very small historical user activity gets a small
    # anomaly signal.
    result["user_frequency_score"] = np.select(
        [
            result["user_event_count"] <= 10,
            result["user_event_count"] <= 50,
        ],
        [
            10,
            5,
        ],
        default=0
    )

    # --------------------------------------------------------
    # Computer activity frequency
    # --------------------------------------------------------

    computer_counts = (
        result
        .groupby("computer")
        .size()
        .rename("computer_event_count")
        .reset_index()
    )

    result = result.merge(
        computer_counts,
        on="computer",
        how="left"
    )

    result["computer_frequency_score"] = np.select(
        [
            result["computer_event_count"] <= 5,
            result["computer_event_count"] <= 20,
        ],
        [
            10,
            5,
        ],
        default=0
    )

    # --------------------------------------------------------
    # Combine scores
    # --------------------------------------------------------

    score_columns = [
        "usb_score",
        "login_score",
        "file_score",
        "extension_score",
        "relationship_score",
        "user_frequency_score",
        "computer_frequency_score",
    ]

    result["host_risk"] = result[score_columns].sum(axis=1)

    # Cap score at 100.
    result["host_risk"] = (
        result["host_risk"]
        .clip(0, 100)
        .round(2)
    )

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    result["risk_level"] = np.select(
        [
            result["host_risk"] < 40,
            result["host_risk"] < 70,
        ],
        [
            "LOW",
            "MEDIUM",
        ],
        default="HIGH"
    )

    # --------------------------------------------------------
    # Explanation
    # --------------------------------------------------------

    def create_reason(row):

        reasons = []

        if row["usb_score"] > 0:
            reasons.append("USB connect")

        if row["login_score"] > 0:
            reasons.append("Logon")

        if row["file_score"] > 0:
            reasons.append("File activity")

        if row["extension_score"] > 0:
            reasons.append("File type requires attention")

        if row["relationship_score"] > 0:
            reasons.append("Rare user-computer relationship")

        if row["user_frequency_score"] > 0:
            reasons.append("Low historical user activity")

        if row["computer_frequency_score"] > 0:
            reasons.append("Low historical computer activity")

        if not reasons:
            return "Normal activity"

        return "; ".join(reasons)

    result["risk_reason"] = result.apply(
        create_reason,
        axis=1
    )

    return result


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 70)
    print("SMARTVNC - CERT HOST RISK ENGINE")
    print("=" * 70)

    print("\nLoading CERT dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(f"Records loaded: {len(df):,}")

    # --------------------------------------------------------
    # Validate required columns
    # --------------------------------------------------------

    required_columns = [
        "timestamp",
        "user",
        "computer",
        "usb_activity",
        "login_activity",
        "file_name",
        "file_content",
    ]

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required columns: {missing}"
        )

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    print("\nCalculating host risk...")

    result = calculate_host_risk(df)

    # --------------------------------------------------------
    # Select output columns
    # --------------------------------------------------------

    output_columns = [
        "timestamp",
        "user",
        "computer",
        "usb_activity",
        "login_activity",
        "file_name",
        "host_risk",
        "risk_level",
        "risk_reason",
    ]

    result = result[output_columns]

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    result.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    print("\nRisk distribution:")

    print(
        result["risk_level"]
        .value_counts()
        .sort_index()
    )

    print("\nRisk score statistics:")

    print(
        result["host_risk"]
        .describe()
    )

    print("\nTop 10 highest-risk events:")

    print(
        result
        .sort_values(
            "host_risk",
            ascending=False
        )
        .head(10)
        .to_string(index=False)
    )

    print("\n" + "=" * 70)
    print("HOST RISK ENGINE COMPLETED")
    print("=" * 70)

    print(f"\nOutput file:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()