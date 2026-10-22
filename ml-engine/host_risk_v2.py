import pandas as pd
import numpy as np
from pathlib import Path


# ============================================================
# SMARTVNC - CERT Host Risk Engine V2
# Time-aware behavioral risk analysis
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

OUTPUT_FILE = OUTPUT_DIR / "host_risk_v2.csv"


# ============================================================
# Configuration
# ============================================================

# These are risk signals, NOT malware classifications.
FILE_TYPE_SCORES = {
    ".exe": 15,
    ".zip": 10,
    ".doc": 5,
    ".pdf": 5,
    ".txt": 3,
    ".jpg": 2,
}


# ============================================================
# File type scoring
# ============================================================

def get_file_extension(file_name):
    if pd.isna(file_name) or file_name == "No File":
        return ""

    return Path(str(file_name)).suffix.lower()


def get_file_type_score(file_name):
    extension = get_file_extension(file_name)
    return FILE_TYPE_SCORES.get(extension, 0)


# ============================================================
# Main risk calculation
# ============================================================

def calculate_risk(df):

    df = df.sort_values("timestamp").reset_index(drop=True)

    # --------------------------------------------------------
    # Historical counters
    # --------------------------------------------------------

    user_count = {}
    computer_count = {}
    pair_count = {}

    # User's historical activity by hour
    user_hour_count = {}

    risk_scores = []
    risk_reasons = []

    # --------------------------------------------------------
    # Process chronologically
    # --------------------------------------------------------

    for _, row in df.iterrows():

        user = row["user"]
        computer = row["computer"]

        timestamp = row["timestamp"]

        hour = timestamp.hour

        pair = (user, computer)
        user_hour = (user, hour)

        score = 0
        reasons = []

        # ====================================================
        # 1. USB activity
        # ====================================================

        if row["usb_activity"] == "Connect":

            score += 15
            reasons.append("USB connect")

        # Disconnect is normal activity and does not
        # increase risk by itself.

        # ====================================================
        # 2. Login activity
        # ====================================================

        if row["login_activity"] == "Logon":

            score += 5
            reasons.append("Logon")

        # Logoff and No Login Activity do not increase risk.

        # ====================================================
        # 3. File activity
        # ====================================================

        file_exists = (
            pd.notna(row["file_name"])
            and row["file_name"] != "No File"
        )

        if file_exists:

            score += 10
            reasons.append("File activity")

        # ====================================================
        # 4. File type
        # ====================================================

        file_type_score = get_file_type_score(
            row["file_name"]
        )

        if file_type_score > 0:

            score += file_type_score

            extension = get_file_extension(
                row["file_name"]
            )

            reasons.append(
                f"File type {extension}"
            )

        # ====================================================
        # 5. New user-computer relationship
        # ====================================================

        previous_pair_events = pair_count.get(pair, 0)

        if previous_pair_events == 0:

            score += 15

            reasons.append(
                "New user-computer relationship"
            )

        # ====================================================
        # 6. Low historical user activity
        # ====================================================

        previous_user_events = user_count.get(user, 0)

        if previous_user_events == 0:

            score += 10

            reasons.append(
                "First observed user activity"
            )

        elif previous_user_events <= 5:

            score += 5

            reasons.append(
                "Low historical user activity"
            )

        # ====================================================
        # 7. Low historical computer activity
        # ====================================================

        previous_computer_events = (
            computer_count.get(computer, 0)
        )

        if previous_computer_events == 0:

            score += 10

            reasons.append(
                "First observed computer activity"
            )

        elif previous_computer_events <= 5:

            score += 5

            reasons.append(
                "Low historical computer activity"
            )

        # ====================================================
        # 8. Time-of-day anomaly
        # ====================================================

        previous_user_hour_events = (
            user_hour_count.get(user_hour, 0)
        )

        # Once we have observed the user at other times,
        # an entirely new hour becomes a mild anomaly.
        if previous_user_events >= 10:

            if previous_user_hour_events == 0:

                score += 10

                reasons.append(
                    "Unusual activity hour for user"
                )

        # ====================================================
        # Cap risk
        # ====================================================

        score = min(score, 100)

        # ====================================================
        # Risk level
        # ====================================================

        if score < 40:

            level = "LOW"

        elif score < 70:

            level = "MEDIUM"

        else:

            level = "HIGH"

        # ====================================================
        # Explanation
        # ====================================================

        if not reasons:

            reason = "Normal activity"

        else:

            reason = "; ".join(reasons)

        risk_scores.append(score)
        risk_reasons.append(reason)

        # ====================================================
        # Update historical state AFTER scoring
        # ====================================================

        user_count[user] = (
            user_count.get(user, 0) + 1
        )

        computer_count[computer] = (
            computer_count.get(computer, 0) + 1
        )

        pair_count[pair] = (
            pair_count.get(pair, 0) + 1
        )

        user_hour_count[user_hour] = (
            user_hour_count.get(user_hour, 0) + 1
        )

    # --------------------------------------------------------
    # Add results
    # --------------------------------------------------------

    df["host_risk"] = risk_scores

    df["risk_level"] = np.select(
        [
            df["host_risk"] < 40,
            df["host_risk"] < 70,
        ],
        [
            "LOW",
            "MEDIUM",
        ],
        default="HIGH",
    )

    df["risk_reason"] = risk_reasons

    return df


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 70)
    print("SMARTVNC - CERT HOST RISK ENGINE V2")
    print("Time-aware behavioral analysis")
    print("=" * 70)

    print("\nLoading CERT dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(f"Records loaded: {len(df):,}")

    # --------------------------------------------------------
    # Validate columns
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

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:

        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    # --------------------------------------------------------
    # Timestamp conversion
    # --------------------------------------------------------

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
    )

    if df["timestamp"].isna().any():

        raise ValueError(
            "Invalid timestamp values found."
        )

    # --------------------------------------------------------
    # Calculate risk
    # --------------------------------------------------------

    print("\nPerforming chronological behavioral analysis...")

    result = calculate_risk(df)

    # --------------------------------------------------------
    # Output columns
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
        index=False,
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
        result["host_risk"].describe()
    )

    print("\nTop 10 highest-risk events:")

    print(
        result
        .sort_values(
            "host_risk",
            ascending=False,
        )
        .head(10)
        .to_string(index=False)
    )

    print("\n" + "=" * 70)
    print("HOST RISK ENGINE V2 COMPLETED")
    print("=" * 70)

    print("\nOutput file:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()