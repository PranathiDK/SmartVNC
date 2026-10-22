import pandas as pd
from pathlib import Path

# ============================================================
# SMARTVNC - ML Dataset Preparation
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "cicids_processed.csv"
)

OUTPUT_DIR = BASE_DIR / "datasets" / "ml_ready"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("SMARTVNC - ML Dataset Preparation")
print("=" * 60)

# ------------------------------------------------------------
# 1. Load dataset
# ------------------------------------------------------------

print("\nLoading dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Original records: {len(df):,}")

# ------------------------------------------------------------
# 2. Define input features and target
# ------------------------------------------------------------

feature_columns = [
    "session_duration",
    "forward_packets",
    "backward_packets",
    "bytes_per_second",
    "packets_per_second",
    "protocol"
]

target_column = "label"

# ------------------------------------------------------------
# 3. Check required columns
# ------------------------------------------------------------

required_columns = feature_columns + [target_column]

missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing_columns:
    raise ValueError(
        f"Missing columns: {missing_columns}"
    )

# ------------------------------------------------------------
# 4. Convert labels into binary classes
# ------------------------------------------------------------

df["target"] = (
    df["label"]
    .str.strip()
    .str.lower()
    .apply(lambda x: 0 if x == "benign" else 1)
)

# ------------------------------------------------------------
# 5. Display class distribution
# ------------------------------------------------------------

print("\nBinary Class Distribution:")

print(
    df["target"]
    .value_counts()
    .sort_index()
)

print("\nClass Meaning:")
print("0 = Normal / Benign")
print("1 = Threat / Attack")

# ------------------------------------------------------------
# 6. Select ML features
# ------------------------------------------------------------

X = df[feature_columns].copy()

y = df["target"].copy()

# ------------------------------------------------------------
# 7. Check missing values
# ------------------------------------------------------------

print("\nMissing values in features:")

print(X.isnull().sum())

# ------------------------------------------------------------
# 8. Save ML-ready dataset
# ------------------------------------------------------------

ml_ready_df = X.copy()

ml_ready_df["target"] = y

output_file = (
    OUTPUT_DIR
    / "cicids_ml_ready.csv"
)

ml_ready_df.to_csv(
    output_file,
    index=False
)

# ------------------------------------------------------------
# 9. Final information
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("ML DATASET PREPARATION COMPLETED")
print("=" * 60)

print(f"Total records : {len(ml_ready_df):,}")
print(f"Total features: {len(feature_columns)}")

print("\nFeatures:")
for feature in feature_columns:
    print(f" - {feature}")

print("\nTarget:")
print(" - target")

print("\nSaved to:")
print(output_file)