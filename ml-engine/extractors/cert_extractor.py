import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

CERT_DIR = BASE_DIR / "datasets" / "cert"
OUTPUT_DIR = BASE_DIR / "datasets" / "extracted"

OUTPUT_DIR.mkdir(exist_ok=True)

device = pd.read_csv(CERT_DIR / "device.csv")

device = device[
    ["date", "user", "pc", "activity"]
]

device.columns = [
    "timestamp",
    "user",
    "computer",
    "usb_activity"
]

device.to_csv(
    OUTPUT_DIR / "cert_device.csv",
    index=False
)

print("Device dataset extracted successfully.")

logon = pd.read_csv(CERT_DIR / "logon.csv")

logon = logon[
    ["date", "user", "pc", "activity"]
]

logon.columns = [
    "timestamp",
    "user",
    "computer",
    "login_activity"
]

logon.to_csv(
    OUTPUT_DIR / "cert_logon.csv",
    index=False
)

print("Logon dataset extracted successfully.")

file_data = pd.read_csv(CERT_DIR / "file.csv")

file_data = file_data[
    ["date", "user", "pc", "filename", "content"]
]

file_data.columns = [
    "timestamp",
    "user",
    "computer",
    "file_name",
    "file_content"
]

file_data.to_csv(
    OUTPUT_DIR / "cert_file.csv",
    index=False
)

print("File dataset extracted successfully.")

print("\nCERT feature extraction completed successfully.")