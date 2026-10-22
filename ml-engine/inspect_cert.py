import pandas as pd
from pathlib import Path

base = Path("datasets/cert")

files = [
    "email.csv",
    "http.csv",
    "psychometric.csv"
]

for filename in files:
    print("\n" + "=" * 70)
    print(filename.upper())
    print("=" * 70)

    df = pd.read_csv(base / filename)

    print("\nShape:", df.shape)
    print("\nColumns:")
    print(df.columns.tolist())

    print("\nFirst 5 rows:")
    print(df.head().to_string(index=False))