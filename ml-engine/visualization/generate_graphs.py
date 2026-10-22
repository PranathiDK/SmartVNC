import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# =====================================================
# SMARTVNC - Module 1 Visualization
# =====================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATASET = BASE_DIR / "datasets" / "processed" / "cicids_processed.csv"
GRAPH_DIR = BASE_DIR / "docs" / "graphs"

GRAPH_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("SMARTVNC - Generating Graphs")
print("=" * 60)

# -----------------------------------------------------
# Load Dataset
# -----------------------------------------------------

df = pd.read_csv(DATASET)

# =====================================================
# Graph 1 : Label Distribution
# =====================================================

plt.figure(figsize=(10, 7))

# Count labels
label_counts = df["label"].value_counts()

# Create legend labels with percentage
total = label_counts.sum()

legend_labels = [
    f"{label} ({count/total*100:.1f}%)"
    for label, count in zip(label_counts.index, label_counts.values)
]

# Draw pie chart (NO percentages inside)
wedges, texts = plt.pie(
    label_counts.values,
    startangle=90,
    explode=[0.03] * len(label_counts),
    labels=None,                 # No labels on pie
    autopct=None,                # Remove percentages
    wedgeprops={
        "edgecolor": "white",
        "linewidth": 1.2
    }
)

# Legend with class names + percentages
plt.legend(
    wedges,
    legend_labels,
    title="Classes",
    loc="center left",
    bbox_to_anchor=(1.02, 0.5),
    fontsize=10,
    title_fontsize=11
)

plt.title(
    "Distribution of Network Traffic Labels",
    fontsize=15,
    fontweight="bold"
)

plt.tight_layout()

plt.savefig(
    GRAPH_DIR / "label_distribution.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("✓ Label Distribution Graph Created")

# =====================================================
# Graph 2 : Missing Values (Before vs After)
# =====================================================

import numpy as np

# Load datasets
before_df = pd.read_csv(
    BASE_DIR / "datasets" / "extracted" / "cicids_features.csv"
)

after_df = pd.read_csv(
    BASE_DIR / "datasets" / "processed" / "cicids_processed.csv"
)

# Replace Infinity with NaN in the original dataset
before_df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Count missing values
before_missing = before_df.isnull().sum()
after_missing = after_df.isnull().sum()

# Common columns
columns = before_missing.index

x = np.arange(len(columns))
width = 0.35

plt.figure(figsize=(10,5))

plt.bar(
    x - width/2,
    before_missing.values,
    width,
    label="Before Preprocessing"
)

plt.bar(
    x + width/2,
    after_missing.values,
    width,
    label="After Preprocessing"
)

plt.xticks(x, columns, rotation=25)

plt.ylabel("Number of Missing Values")

plt.title("Missing Values Before and After Preprocessing")

plt.legend()

plt.tight_layout()

plt.savefig(
    GRAPH_DIR / "missing_values_before_after.png",
    dpi=300
)

plt.close()

print("✓ Missing Value Comparison Created")

# =====================================================
# Graph 3 : Session Duration Distribution
# =====================================================

import numpy as np

plt.figure(figsize=(8, 5))

# Remove invalid values
duration = df["session_duration"]
duration = duration[duration > 0]

# Log transform
log_duration = np.log10(duration)

plt.hist(log_duration, bins=50, edgecolor="black")

plt.title("Distribution of Network Session Duration", fontsize=14)

plt.xlabel("Log10(Session Duration)")

plt.ylabel("Number of Sessions")

plt.grid(axis="y", linestyle="--", alpha=0.5)

plt.tight_layout()

plt.savefig(
    GRAPH_DIR / "flow_duration_histogram.png",
    dpi=300
)

plt.close()

print("✓ Session Duration Histogram Created")

# =====================================================
# Graph 4 : Correlation Heatmap
# =====================================================

numeric = df.select_dtypes(include="number")

corr = numeric.corr()

plt.figure(figsize=(7,6))

plt.imshow(corr)

plt.colorbar()

plt.xticks(range(len(corr.columns)), corr.columns, rotation=45)

plt.yticks(range(len(corr.columns)), corr.columns)

plt.title("Feature Correlation Heatmap")

plt.tight_layout()

plt.savefig(
    GRAPH_DIR / "correlation_heatmap.png",
    dpi=300
)

plt.close()

print("✓ Correlation Heatmap Created")

print()
print("=" * 60)
print("All graphs generated successfully!")
print("=" * 60)