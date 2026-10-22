import pandas as pd
import numpy as np
from pathlib import Path

# ============================================================
# SMARTVNC - CICIDS Feature Quality Audit
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    BASE_DIR
    / "datasets"
    / "ml_ready"
    / "cicids_ml_ready.csv"
)

print("=" * 60)
print("SMARTVNC - CICIDS Feature Quality Audit")
print("=" * 60)

# ------------------------------------------------------------
# 1. Load dataset
# ------------------------------------------------------------

print("\nLoading dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Total records: {len(df):,}")

# ------------------------------------------------------------
# 2. Features to audit
# ------------------------------------------------------------

features = [
    "session_duration",
    "forward_packets",
    "backward_packets",
    "bytes_per_second",
    "packets_per_second",
    "protocol"
]

# ------------------------------------------------------------
# 3. Check infinity
# ------------------------------------------------------------

print("\nInfinity values:")

for feature in features:
    count = np.isinf(df[feature]).sum()
    print(f"{feature:25s}: {count:,}")

# ------------------------------------------------------------
# 4. Check negative values
# ------------------------------------------------------------

print("\nNegative values:")

for feature in features:
    count = (df[feature] < 0).sum()
    print(f"{feature:25s}: {count:,}")

# ------------------------------------------------------------
# 5. Check zero values
# ------------------------------------------------------------

print("\nZero values:")

for feature in features:
    count = (df[feature] == 0).sum()
    print(f"{feature:25s}: {count:,}")

# ------------------------------------------------------------
# 6. Detailed session duration audit
# ------------------------------------------------------------

print("\nSession Duration Audit")

negative_duration = df[df["session_duration"] < 0]

print(
    f"Negative session durations: "
    f"{len(negative_duration):,}"
)

if len(negative_duration) > 0:
    print("\nSmallest session durations:")
    print(
        negative_duration["session_duration"]
        .nsmallest(10)
        .to_string(index=False)
    )

# ------------------------------------------------------------
# 7. Detailed packets/sec audit
# ------------------------------------------------------------

print("\nPackets Per Second Audit")

negative_pps = df[df["packets_per_second"] < 0]

print(
    f"Negative packets_per_second: "
    f"{len(negative_pps):,}"
)

if len(negative_pps) > 0:
    print("\nSmallest packets_per_second values:")
    print(
        negative_pps["packets_per_second"]
        .nsmallest(10)
        .to_string(index=False)
    )

# ------------------------------------------------------------
# 8. Feature ranges
# ------------------------------------------------------------

print("\nFeature Ranges:")

for feature in features:

    print(
        f"\n{feature}"
    )

    print(
        f"  Minimum : {df[feature].min():.6g}"
    )

    print(
        f"  Maximum : {df[feature].max():.6g}"
    )

    print(
        f"  Mean    : {df[feature].mean():.6g}"
    )

    print(
        f"  Median  : {df[feature].median():.6g}"
    )

# ------------------------------------------------------------
# 9. Label distribution
# ------------------------------------------------------------

print("\nLabel Distribution:")

print(
    df["target"]
    .value_counts()
    .sort_index()
)

# ------------------------------------------------------------
# 10. Final summary
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("FEATURE QUALITY AUDIT COMPLETED")
print("=" * 60)