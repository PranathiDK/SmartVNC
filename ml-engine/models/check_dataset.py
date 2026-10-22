import pandas as pd

file_path = "datasets/processed/cicids_processed.csv"

df = pd.read_csv(file_path)

print("=" * 60)
print("SMARTVNC - ML Dataset Verification")
print("=" * 60)

print("\nDataset Shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nMissing Values:")
print(df.isnull().sum())

print("\nLabel Distribution:")
print(df["label"].value_counts())

print("\nData Types:")
print(df.dtypes)