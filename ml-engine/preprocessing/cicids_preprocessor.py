import pandas as pd
import numpy as np
from pathlib import Path

# ==================================================
# SMARTVNC - CICIDS Data Preprocessing
# ==================================================

BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_FILE = BASE_DIR / "datasets" / "extracted" / "cicids_features.csv"
OUTPUT_DIR = BASE_DIR / "datasets" / "processed"

OUTPUT_DIR.mkdir(exist_ok=True)

print("=" * 60)
print("SMARTVNC - CICIDS Preprocessing")
print("=" * 60)

# --------------------------------------------------
# Load Dataset
# --------------------------------------------------

df = pd.read_csv(INPUT_FILE)

print(f"Original Records : {len(df)}")

# --------------------------------------------------
# Remove Duplicate Rows
# --------------------------------------------------

df = df.drop_duplicates()

print(f"After Removing Duplicates : {len(df)}")

# --------------------------------------------------
# Replace Infinity
# --------------------------------------------------

df.replace([np.inf, -np.inf], np.nan, inplace=True)

# --------------------------------------------------
# Remove Missing Values
# --------------------------------------------------

df = df.dropna()

print(f"After Removing Missing Values : {len(df)}")

# --------------------------------------------------
# Convert Numeric Columns
# --------------------------------------------------

numeric_columns = [
    "session_duration",
    "forward_packets",
    "backward_packets",
    "bytes_per_second",
    "packets_per_second"
]

for column in numeric_columns:
    df[column] = pd.to_numeric(df[column], errors="coerce")

df = df.dropna()

# --------------------------------------------------
# Standardize Labels
# --------------------------------------------------

df["label"] = df["label"].astype(str).str.strip()

# --------------------------------------------------
# Save Processed Dataset
# --------------------------------------------------

output_file = OUTPUT_DIR / "cicids_processed.csv"

df.to_csv(output_file, index=False)

print("\nPreprocessing Completed Successfully!")

print(f"Final Records : {len(df)}")
print(f"Saved To : {output_file}")