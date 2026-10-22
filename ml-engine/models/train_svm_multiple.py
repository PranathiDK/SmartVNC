
# ============================================================
# SMARTVNC - SVM MULTI-CONFIGURATION EXPERIMENT
# FAIR COMPARISON VERSION
# ============================================================

import os
import time
import joblib
import numpy as np
import pandas as pd

from sklearn.svm import LinearSVC
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

# ============================================================
# 1. PATHS
# ============================================================

BASE_DIR = r"C:\SmartVNC"

DATA_DIR = os.path.join(
    BASE_DIR,
    "datasets",
    "ml_ready"
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "datasets",
    "risk"
)

MODELS_DIR = os.path.join(
    BASE_DIR,
    "ml-engine",
    "models",
    "saved_models"
)

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

# ============================================================
# 2. CONFIGURATION
# ============================================================

RANDOM_STATE = 42

# Same balanced methodology used for
# XGBoost, Random Forest and KNN

TRAIN_SAMPLES_PER_CLASS = 52_674
TEST_SAMPLES_PER_CLASS = 13_168

C_VALUES = [
    0.1,
    1,
    10,
    100
]

# ============================================================
# 3. START
# ============================================================

print("=" * 75)
print("SMARTVNC - SVM MULTIPLE CONFIGURATION EXPERIMENT")
print("=" * 75)

# ============================================================
# 4. LOAD SAME DATA USED BY OTHER MODELS
# ============================================================

print("\nLoading training and testing data...")

X_train_full = np.load(
    os.path.join(DATA_DIR, "X_train.npy")
)

X_test_full = np.load(
    os.path.join(DATA_DIR, "X_test.npy")
)

y_train_full = np.load(
    os.path.join(DATA_DIR, "y_train.npy")
)

y_test_full = np.load(
    os.path.join(DATA_DIR, "y_test.npy")
)

print(
    f"Training records available : "
    f"{len(X_train_full):,}"
)

print(
    f"Testing records available  : "
    f"{len(X_test_full):,}"
)

# ============================================================
# 5. ORIGINAL DISTRIBUTION
# ============================================================

print("\nOriginal training distribution:")

print(
    f"Normal : {(y_train_full == 0).sum():,}"
)

print(
    f"Threat : {(y_train_full == 1).sum():,}"
)

print("\nOriginal testing distribution:")

print(
    f"Normal : {(y_test_full == 0).sum():,}"
)

print(
    f"Threat : {(y_test_full == 1).sum():,}"
)

# ============================================================
# 6. BALANCED TRAINING DATASET
# ============================================================

print("\nBalanced training configuration:")

print(
    f"Samples per class: "
    f"{TRAIN_SAMPLES_PER_CLASS:,}"
)

rng_train = np.random.RandomState(
    RANDOM_STATE
)

train_indices = []

for class_value in [0, 1]:

    class_indices = np.where(
        y_train_full == class_value
    )[0]

    if len(class_indices) < TRAIN_SAMPLES_PER_CLASS:

        raise ValueError(
            f"Not enough samples for class "
            f"{class_value}. Available: "
            f"{len(class_indices):,}"
        )

    selected_indices = rng_train.choice(
        class_indices,
        size=TRAIN_SAMPLES_PER_CLASS,
        replace=False
    )

    train_indices.extend(
        selected_indices
    )

train_indices = np.array(
    train_indices
)

rng_train.shuffle(
    train_indices
)

X_train = X_train_full[
    train_indices
]

y_train = y_train_full[
    train_indices
]

print("\nBalanced training dataset:")

print(
    f"Total  : {len(X_train):,}"
)

print(
    f"Normal : {(y_train == 0).sum():,}"
)

print(
    f"Threat : {(y_train == 1).sum():,}"
)

# ============================================================
# 7. BALANCED TESTING DATASET
# ============================================================

print("\nBalanced testing configuration:")

print(
    f"Samples per class: "
    f"{TEST_SAMPLES_PER_CLASS:,}"
)

rng_test = np.random.RandomState(
    RANDOM_STATE
)

test_indices = []

for class_value in [0, 1]:

    class_indices = np.where(
        y_test_full == class_value
    )[0]

    if len(class_indices) < TEST_SAMPLES_PER_CLASS:

        raise ValueError(
            f"Not enough testing samples for class "
            f"{class_value}. Available: "
            f"{len(class_indices):,}"
        )

    selected_indices = rng_test.choice(
        class_indices,
        size=TEST_SAMPLES_PER_CLASS,
        replace=False
    )

    test_indices.extend(
        selected_indices
    )

test_indices = np.array(
    test_indices
)

rng_test.shuffle(
    test_indices
)

X_test = X_test_full[
    test_indices
]

y_test = y_test_full[
    test_indices
]

print("\nBalanced evaluation dataset:")

print(
    f"Total  : {len(X_test):,}"
)

print(
    f"Normal : {(y_test == 0).sum():,}"
)

print(
    f"Threat : {(y_test == 1).sum():,}"
)

# ============================================================
# 8. CHECK DATA
# ============================================================

print("\nChecking numerical data...")

if np.isfinite(X_train).all():
    print("Training data: VALID")
else:
    raise ValueError(
        "Training data contains "
        "NaN or infinite values."
    )

if np.isfinite(X_test).all():
    print("Testing data : VALID")
else:
    raise ValueError(
        "Testing data contains "
        "NaN or infinite values."
    )

# ============================================================
# 9. RUN SVM EXPERIMENTS
# ============================================================

results = []

for C in C_VALUES:

    print("\n" + "=" * 75)

    print(
        f"TRAINING LINEAR SVM - C = {C}"
    )

    print("=" * 75)

    model = LinearSVC(
        C=C,
        max_iter=10000,
        random_state=RANDOM_STATE
    )

    # --------------------------------------------------------
    # Training
    # --------------------------------------------------------

    print("\nTraining model...")

    start_time = time.time()

    model.fit(
        X_train,
        y_train
    )

    training_time = (
        time.time() - start_time
    )

    print(
        f"Training completed in "
        f"{training_time:.2f} seconds."
    )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    print("Generating predictions...")

    start_time = time.time()

    y_pred = model.predict(
        X_test
    )

    prediction_time = (
        time.time() - start_time
    )

    # --------------------------------------------------------
    # Decision scores for ROC-AUC
    # --------------------------------------------------------

    decision_scores = model.decision_function(
        X_test
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        decision_scores
    )

    # --------------------------------------------------------
    # Display performance
    # --------------------------------------------------------

    print("\nPerformance:")

    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1 Score  : {f1:.4f}"
    )

    print(
        f"ROC-AUC   : {roc_auc:.4f}"
    )

    print(
        f"Training Time  : "
        f"{training_time:.2f} seconds"
    )

    print(
        f"Prediction Time: "
        f"{prediction_time:.2f} seconds"
    )

    # --------------------------------------------------------
    # Confusion Matrix
    # --------------------------------------------------------

    print("\nConfusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            y_pred
        )
    )

    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    results.append({

        "algorithm": "Linear SVM",

        "C": C,

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1_score": f1,

        "roc_auc": roc_auc,

        "training_time": training_time,

        "prediction_time": prediction_time
    })

# ============================================================
# 10. RESULTS DATAFRAME
# ============================================================

results_df = pd.DataFrame(
    results
)

# ============================================================
# 11. FINAL COMPARISON
# ============================================================

print("\n\n")

print("=" * 100)

print(
    "LINEAR SVM CONFIGURATION COMPARISON"
)

print("=" * 100)

print(
    results_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)

# ============================================================
# 12. SAVE RESULTS
# ============================================================

results_file = os.path.join(
    RESULTS_DIR,
    "svm_configuration_results.csv"
)

results_df.to_csv(
    results_file,
    index=False
)

print("\nExperiment results saved to:")

print(results_file)

# ============================================================
# 13. SELECT BEST CONFIGURATION
# ============================================================

best_index = results_df[
    "f1_score"
].idxmax()

best_result = results_df.loc[
    best_index
]

best_C = best_result["C"]

print("\n" + "=" * 75)

print(
    "BEST SVM CONFIGURATION"
)

print("=" * 75)

print(
    f"\nC value      : {best_C}"
)

print(
    f"Accuracy     : "
    f"{best_result['accuracy']:.4f}"
)

print(
    f"Precision    : "
    f"{best_result['precision']:.4f}"
)

print(
    f"Recall       : "
    f"{best_result['recall']:.4f}"
)

print(
    f"F1 Score     : "
    f"{best_result['f1_score']:.4f}"
)

print(
    f"ROC-AUC      : "
    f"{best_result['roc_auc']:.4f}"
)

# ============================================================
# 14. TRAIN FINAL BEST SVM
# ============================================================

print(
    f"\nTraining final SVM model "
    f"with C = {best_C}..."
)

final_model = LinearSVC(
    C=best_C,
    max_iter=10000,
    random_state=RANDOM_STATE
)

final_model.fit(
    X_train,
    y_train
)

# ============================================================
# 15. SAVE FINAL MODEL
# ============================================================

model_file = os.path.join(
    MODELS_DIR,
    f"final_svm_C_{str(best_C).replace('.', '_')}.pkl"
)

joblib.dump(
    final_model,
    model_file
)

print("\nBest SVM model saved to:")

print(model_file)

# ============================================================
# 16. COMPLETION
# ============================================================

print("\n" + "=" * 75)

print(
    "SVM EXPERIMENT COMPLETED SUCCESSFULLY"
)

print("=" * 75)

print("\nGenerated files:")

print(
    f" - {results_file}"
)

print(
    f" - {model_file}"
)
