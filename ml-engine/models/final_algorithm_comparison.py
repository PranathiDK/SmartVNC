
import pandas as pd
from pathlib import Path

# ============================================================
# SMARTVNC - FINAL ALGORITHM COMPARISON
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

RESULTS_DIR = BASE_DIR / "datasets" / "risk"

OUTPUT_FILE = (
    RESULTS_DIR /
    "final_algorithm_comparison.csv"
)

print("=" * 80)
print("SMARTVNC - FINAL ALGORITHM COMPARISON")
print("=" * 80)

# ============================================================
# 1. RESULT FILES
# ============================================================

result_files = {
    "XGBoost": RESULTS_DIR / "xgboost_configuration_results.csv",
    "Random Forest": RESULTS_DIR / "random_forest_configuration_results.csv",
    "KNN": RESULTS_DIR / "knn_configuration_results.csv",
    "Linear SVM": RESULTS_DIR / "svm_configuration_results.csv"
}

# ============================================================
# 2. LOAD RESULTS
# ============================================================

all_results = []

for algorithm, file_path in result_files.items():

    print(f"\nLoading {algorithm} results...")

    if not file_path.exists():

        print(
            f"WARNING: Result file not found:"
            f"\n{file_path}"
        )

        continue

    df = pd.read_csv(file_path)

    print(
        f"Configurations found: {len(df)}"
    )

    # --------------------------------------------------------
    # Normalize column names
    # --------------------------------------------------------

    df.columns = [
        column.strip().lower().replace(" ", "_")
        for column in df.columns
    ]

    # --------------------------------------------------------
    # Add algorithm if missing
    # --------------------------------------------------------

    if "algorithm" not in df.columns:

        df["algorithm"] = algorithm

    all_results.append(df)

# ============================================================
# 3. CHECK RESULTS
# ============================================================

if not all_results:

    raise FileNotFoundError(
        "No algorithm result files were found."
    )

# ============================================================
# 4. COMBINE RESULTS
# ============================================================

combined_df = pd.concat(
    all_results,
    ignore_index=True,
    sort=False
)

# ============================================================
# 5. STANDARDIZE METRIC NAMES
# ============================================================

rename_map = {

    "f1": "f1_score",

    "F1 Score": "f1_score",

    "accuracy": "accuracy",

    "precision": "precision",

    "recall": "recall",

    "roc_auc": "roc_auc"
}

combined_df.rename(
    columns=rename_map,
    inplace=True
)

# ============================================================
# 6. KEEP IMPORTANT COLUMNS
# ============================================================

preferred_columns = [
    "algorithm",
    "n_estimators",
    "n_neighbors",
    "C",
    "max_depth",
    "learning_rate",
    "configuration",
    "accuracy",
    "precision",
    "recall",
    "f1_score",
    "roc_auc",
    "training_time",
    "prediction_time"
]

available_columns = [
    column
    for column in preferred_columns
    if column in combined_df.columns
]

combined_df = combined_df[
    available_columns
]

# ============================================================
# 7. REMOVE DUPLICATES
# ============================================================

combined_df = combined_df.drop_duplicates()

# ============================================================
# 8. SORT BY F1 SCORE
# ============================================================

combined_df = combined_df.sort_values(
    by="f1_score",
    ascending=False
).reset_index(drop=True)

# ============================================================
# 9. DISPLAY COMPLETE COMPARISON
# ============================================================

print("\n" + "=" * 100)

print(
    "ALL ALGORITHM CONFIGURATIONS"
)

print("=" * 100)

print(
    combined_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)

# ============================================================
# 10. SELECT BEST CONFIGURATION PER ALGORITHM
# ============================================================

print("\n" + "=" * 100)

print(
    "BEST CONFIGURATION FOR EACH ALGORITHM"
)

print("=" * 100)

best_per_algorithm = (
    combined_df
    .sort_values(
        by="f1_score",
        ascending=False
    )
    .groupby(
        "algorithm",
        as_index=False
    )
    .first()
)

best_per_algorithm = best_per_algorithm.sort_values(
    by="f1_score",
    ascending=False
).reset_index(drop=True)

print(
    best_per_algorithm.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)

# ============================================================
# 11. FINAL WINNER
# ============================================================

best_overall = best_per_algorithm.iloc[0]

print("\n" + "=" * 80)

print(
    "FINAL SMARTVNC MODEL SELECTION"
)

print("=" * 80)

print(
    f"\nAlgorithm : "
    f"{best_overall['algorithm']}"
)

if "n_estimators" in best_overall.index:

    if pd.notna(best_overall["n_estimators"]):

        print(
            f"Configuration : "
            f"{int(best_overall['n_estimators'])} estimators"
        )

if "n_neighbors" in best_overall.index:

    if pd.notna(best_overall["n_neighbors"]):

        print(
            f"Configuration : "
            f"K = "
            f"{int(best_overall['n_neighbors'])}"
        )

if "C" in best_overall.index:

    if pd.notna(best_overall["C"]):

        print(
            f"Configuration : "
            f"C = {best_overall['C']}"
        )

print(
    f"\nAccuracy  : "
    f"{best_overall['accuracy']:.4f}"
)

print(
    f"Precision : "
    f"{best_overall['precision']:.4f}"
)

print(
    f"Recall    : "
    f"{best_overall['recall']:.4f}"
)

print(
    f"F1 Score  : "
    f"{best_overall['f1_score']:.4f}"
)

print(
    f"ROC-AUC   : "
    f"{best_overall['roc_auc']:.4f}"
)

# ============================================================
# 12. SAVE FINAL COMPARISON
# ============================================================

combined_df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\n" + "=" * 80)

print(
    "FINAL COMPARISON SAVED"
)

print("=" * 80)

print(
    f"\nFile:"
    f"\n{OUTPUT_FILE}"
)

# ============================================================
# 13. FINAL CONCLUSION
# ============================================================

print("\n" + "=" * 80)

print(
    "SMARTVNC FINAL CONCLUSION"
)

print("=" * 80)

print(
    "\nBased on the current experiments, "
    "the highest-performing configuration "
    "will be selected using F1-score."
)

print(
    f"\nSelected algorithm: "
    f"{best_overall['algorithm']}"
)

print(
    f"F1 Score: "
    f"{best_overall['f1_score']:.4f}"
)

print(
    "\nThe selected model can now be used "
    "as the final SMARTVNC threat detection model."
)

print("\n" + "=" * 80)
print("FINAL ALGORITHM COMPARISON COMPLETED")
print("=" * 80)