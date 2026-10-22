import pandas as pd
from pathlib import Path

# ==========================================================
# SMARTVNC - CICIDS Feature Extraction
# ==========================================================

# Project directories
BASE_DIR = Path(__file__).resolve().parents[2]

CICIDS_DIR = BASE_DIR / "datasets" / "cicids"
OUTPUT_DIR = BASE_DIR / "datasets" / "extracted"

# Create output folder if it doesn't exist
OUTPUT_DIR.mkdir(exist_ok=True)

# Columns required for SMARTVNC
FEATURE_MAPPING = {
    "Flow Duration": "session_duration",
    "Tot Fwd Pkts": "forward_packets",
    "Tot Bwd Pkts": "backward_packets",
    "Flow Byts/s": "bytes_per_second",
    "Flow Pkts/s": "packets_per_second",
    "Protocol": "protocol",
    "Label": "label"
}


def extract_features():
    """
    Reads all CICIDS CSV files, extracts only the required
    network flow features, renames the columns and combines
    them into a single CSV.
    """

    csv_files = sorted(CICIDS_DIR.glob("*.csv"))

    if not csv_files:
        print("No CSV files found in:", CICIDS_DIR)
        return

    print("=" * 60)
    print("SMARTVNC - CICIDS Feature Extraction")
    print("=" * 60)
    print(f"Found {len(csv_files)} CSV files.\n")

    extracted_data = []

    for file in csv_files:

        print(f"Processing: {file.name}")

        try:
            df = pd.read_csv(file)

            # Keep only required columns
            df = df[list(FEATURE_MAPPING.keys())]

            # Rename columns
            df.rename(columns=FEATURE_MAPPING, inplace=True)

            extracted_data.append(df)

            print(f"   Rows extracted: {len(df)}")

        except Exception as e:
            print(f"   Error processing {file.name}")
            print(e)

    print("\nCombining all extracted datasets...")

    combined_df = pd.concat(extracted_data, ignore_index=True)

    output_file = OUTPUT_DIR / "cicids_features.csv"

    combined_df.to_csv(output_file, index=False)

    print("\nExtraction Completed Successfully!")
    print(f"Total Records : {len(combined_df)}")
    print(f"Total Features: {len(combined_df.columns)}")
    print(f"Saved to      : {output_file}")


if __name__ == "__main__":
    extract_features()