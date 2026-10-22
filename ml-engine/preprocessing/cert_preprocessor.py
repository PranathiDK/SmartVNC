import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

INPUT_DIR = BASE_DIR / "datasets" / "extracted"
OUTPUT_DIR = BASE_DIR / "datasets" / "processed"

OUTPUT_DIR.mkdir(exist_ok=True)

print("=" * 60)
print("SMARTVNC - CERT Preprocessing")
print("=" * 60)

# ---------------------------------------------------
# Read extracted datasets
# ---------------------------------------------------

device_df = pd.read_csv(INPUT_DIR / "cert_device.csv")
logon_df = pd.read_csv(INPUT_DIR / "cert_logon.csv")
file_df = pd.read_csv(INPUT_DIR / "cert_file.csv")

# ---------------------------------------------------
# Common preprocessing function
# ---------------------------------------------------

def preprocess(df):

    # Remove duplicate rows
    df = df.drop_duplicates()

    # Remove missing values
    df = df.dropna()

    # Convert timestamp
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    # Remove invalid timestamps
    df = df.dropna(subset=["timestamp"])

    # Standardize usernames
    df["user"] = (
        df["user"]
        .str.lower()
        .str.strip()
    )

    # Standardize computer names
    df["computer"] = (
        df["computer"]
        .str.upper()
        .str.strip()
    )

    # Sort by timestamp
    df = df.sort_values("timestamp")

    return df


device_df = preprocess(device_df)
logon_df = preprocess(logon_df)
file_df = preprocess(file_df)

# ---------------------------------------------------
# Merge Device + Logon
# ---------------------------------------------------

cert_df = pd.merge_asof(
    device_df,
    logon_df,
    on="timestamp",
    by=["user", "computer"],
    direction="nearest",
    tolerance=pd.Timedelta("30min")
)

# ---------------------------------------------------
# Merge File Activity
# ---------------------------------------------------

cert_df = pd.merge_asof(
    cert_df,
    file_df,
    on="timestamp",
    by=["user", "computer"],
    direction="nearest",
    tolerance=pd.Timedelta("30min")
)

# ---------------------------------------------------
# Fill missing activities
# ---------------------------------------------------

cert_df["usb_activity"] = cert_df["usb_activity"].fillna("No USB Activity")

cert_df["login_activity"] = cert_df["login_activity"].fillna("No Login Activity")

cert_df["file_name"] = cert_df["file_name"].fillna("No File")

cert_df["file_content"] = cert_df["file_content"].fillna("No Activity")

# ---------------------------------------------------
# Save
# ---------------------------------------------------

output_file = OUTPUT_DIR / "cert_processed.csv"

cert_df.to_csv(
    output_file,
    index=False
)

print("\nCERT preprocessing completed successfully.\n")

print(f"Total Records : {len(cert_df)}")
print(f"Total Features: {len(cert_df.columns)}")

print("\nSaved to :")
print(output_file)