import pandas as pd
import numpy as np
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ============================================================
# SMARTVNC - Fair ML Dataset Split and Scaling
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    BASE_DIR
    / "datasets"
    / "ml_ready"
    / "cicids_ml_ready.csv"
)

OUTPUT_DIR = (
    BASE_DIR
    / "datasets"
    / "ml_ready"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

SAMPLE_SIZE = 500_000
TEST_SIZE = 0.20
RANDOM_STATE = 42

# ------------------------------------------------------------
# Start
# ------------------------------------------------------------

print("=" * 60)
print("SMARTVNC - Fair ML Dataset Split and Scaling")
print("=" * 60)

# ------------------------------------------------------------
# 1. Load dataset
# ------------------------------------------------------------

print("\nLoading ML-ready dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Full dataset records: {len(df):,}")

# ------------------------------------------------------------
# 2. Define features and target
# ------------------------------------------------------------

feature_columns = [
    "session_duration",
    "forward_packets",
    "backward_packets",
    "bytes_per_second",
    "packets_per_second",
    "protocol"
]

X = df[feature_columns]
y = df["target"]

# ------------------------------------------------------------
# 3. Create ONE fixed stratified sample
# ------------------------------------------------------------

print(f"\nCreating stratified sample of {SAMPLE_SIZE:,} records...")

X_sample, _, y_sample, _ = train_test_split(
    X,
    y,
    train_size=SAMPLE_SIZE,
    random_state=RANDOM_STATE,
    stratify=y
)

print(f"Selected records: {len(X_sample):,}")

print("\nSample class distribution:")
print(y_sample.value_counts().sort_index())

# ------------------------------------------------------------
# 4. 80/20 Stratified Train/Test Split
# ------------------------------------------------------------

print("\nCreating 80/20 stratified split...")

X_train, X_test, y_train, y_test = train_test_split(
    X_sample,
    y_sample,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y_sample
)

print(f"\nTraining records: {len(X_train):,}")
print(f"Testing records : {len(X_test):,}")

# ------------------------------------------------------------
# 5. Feature Scaling
# ------------------------------------------------------------

print("\nApplying StandardScaler...")

scaler = StandardScaler()

# Fit ONLY on training data
X_train_scaled = scaler.fit_transform(X_train)

# Transform test data using the same scaler
X_test_scaled = scaler.transform(X_test)

# ------------------------------------------------------------
# 6. Save training and testing data
# ------------------------------------------------------------

np.save(
    OUTPUT_DIR / "X_train.npy",
    X_train_scaled
)

np.save(
    OUTPUT_DIR / "X_test.npy",
    X_test_scaled
)

np.save(
    OUTPUT_DIR / "y_train.npy",
    y_train.to_numpy()
)

np.save(
    OUTPUT_DIR / "y_test.npy",
    y_test.to_numpy()
)

# ------------------------------------------------------------
# 7. Save scaler
# ------------------------------------------------------------

joblib.dump(
    scaler,
    OUTPUT_DIR / "scaler.pkl"
)

# ------------------------------------------------------------
# 8. Display final class distribution
# ------------------------------------------------------------

print("\nTraining class distribution:")
print(y_train.value_counts().sort_index())

print("\nTesting class distribution:")
print(y_test.value_counts().sort_index())

# ------------------------------------------------------------
# 9. Final output
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("FAIR TRAIN/TEST SPLIT AND SCALING COMPLETED")
print("=" * 60)

print("\nComparison dataset:")
print(f"Total sampled records: {SAMPLE_SIZE:,}")

print("\nTrain/Test split:")
print(f"Training: {len(X_train):,}")
print(f"Testing : {len(X_test):,}")

print("\nFeatures:")
for feature in feature_columns:
    print(f" - {feature}")

print("\nTarget:")
print(" - target")

print("\nGenerated files:")
print(" - X_train.npy")
print(" - X_test.npy")
print(" - y_train.npy")
print(" - y_test.npy")
print(" - scaler.pkl")

print("\nSaved to:")
print(OUTPUT_DIR)