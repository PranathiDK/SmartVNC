# ============================================================
# SMARTVNC - KNN MULTI-CONFIGURATION EXPERIMENT
# ============================================================

import os
import time
import joblib
import numpy as np
import pandas as pd

from sklearn.neighbors import KNeighborsClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
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

# Use the same balanced configuration as
# XGBoost and Random Forest experiments.

TRAIN_SAMPLES_PER_CLASS = 52_674
TEST_SAMPLES_PER_CLASS = 13_168

K_VALUES = [
    3,
    5,
    7,
    9,
    11
]

# ============================================================
# 3. START
# ============================================================

print("=" * 75)
print("SMARTVNC - KNN MULTIPLE CONFIGURATION EXPERIMENT")
print("=" * 75)

# ============================================================
# 4. LOAD SAME TRAIN/TEST DATA
# ============================================================

print("\nLoading training and testing data...")

X_train = np.load(
    os.path.join(DATA_DIR, "X_train.npy")
)

X_test = np.load(
    os.path.join(DATA_DIR, "X_test.npy")
)

y_train = np.load(
    os.path.join(DATA_DIR, "y_train.npy")
)

y_test = np.load(
    os.path.join(DATA_DIR, "y_test.npy")
)

print(
    f"Training records available : {len(X_train):,}"
)

print(
    f"Testing records available  : {len(X_test):,}"
)

# ============================================================
# 5. ORIGINAL DISTRIBUTION
# ============================================================

print("\nOriginal training distribution:")

print(
    f"Normal : {(y_train == 0).sum():,}"
)

print(
    f"Threat : {(y_train == 1).sum():,}"
)

print("\nOriginal testing distribution:")

print(
    f"Normal : {(y_test == 0).sum():,}"
)

print(
    f"Threat : {(y_test == 1).sum():,}"
)

# ============================================================
# 6. CHECK AVAILABLE SAMPLES
# ============================================================

available_train_normal = np.sum(y_train == 0)
available_train_threat = np.sum(y_train == 1)

available_test_normal = np.sum(y_test == 0)
available_test_threat = np.sum(y_test == 1)

if available_train_normal < TRAIN_SAMPLES_PER_CLASS:
    raise ValueError(
        "Not enough training samples for Normal class."
    )

if available_train_threat < TRAIN_SAMPLES_PER_CLASS:
    raise ValueError(
        "Not enough training samples for Threat class."
    )

if available_test_normal < TEST_SAMPLES_PER_CLASS:
    raise ValueError(
        "Not enough testing samples for Normal class."
    )

if available_test_threat < TEST_SAMPLES_PER_CLASS:
    raise ValueError(
        "Not enough testing samples for Threat class."
    )

# ============================================================
# 7. CREATE BALANCED TRAINING SUBSET
# ============================================================

print("\nBalanced training configuration:")

print(
    f"Samples per class: "
    f"{TRAIN_SAMPLES_PER_CLASS:,}"
)

print("\nCreating balanced training subset...")

rng = np.random.RandomState(RANDOM_STATE)

train_indices = []

for class_value in [0, 1]:

    class_indices = np.where(
        y_train == class_value
    )[0]

    selected_indices = rng.choice(
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

rng.shuffle(
    train_indices
)

X_train_balanced = X_train[
    train_indices
]

y_train_balanced = y_train[
    train_indices
]

print("\nBalanced training dataset:")

print(
    f"Total  : {len(X_train_balanced):,}"
)

print(
    f"Normal : "
    f"{np.sum(y_train_balanced == 0):,}"
)

print(
    f"Threat : "
    f"{np.sum(y_train_balanced == 1):,}"
)

# ============================================================
# 8. CREATE BALANCED TESTING SUBSET
# ============================================================

print("\nBalanced testing configuration:")

print(
    f"Samples per class: "
    f"{TEST_SAMPLES_PER_CLASS:,}"
)

print("\nCreating balanced evaluation subset...")

test_indices = []

for class_value in [0, 1]:

    class_indices = np.where(
        y_test == class_value
    )[0]

    selected_indices = rng.choice(
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

rng.shuffle(
    test_indices
)

X_test_balanced = X_test[
    test_indices
]

y_test_balanced = y_test[
    test_indices
]

print("\nBalanced evaluation dataset:")

print(
    f"Total  : {len(X_test_balanced):,}"
)

print(
    f"Normal : "
    f"{np.sum(y_test_balanced == 0):,}"
)

print(
    f"Threat : "
    f"{np.sum(y_test_balanced == 1):,}"
)

# ============================================================
# 9. CHECK DATA
# ============================================================

print("\nChecking numerical data...")

train_valid = np.isfinite(
    X_train_balanced
).all()

test_valid = np.isfinite(
    X_test_balanced
).all()

print(
    "Training data:",
    "VALID" if train_valid else "INVALID"
)

print(
    "Testing data :",
    "VALID" if test_valid else "INVALID"
)

if not train_valid:
    raise ValueError(
        "Training data contains non-finite values."
    )

if not test_valid:
    raise ValueError(
        "Testing data contains non-finite values."
    )

# ============================================================
# 10. RUN KNN EXPERIMENT
# ============================================================

results = []

for k in K_VALUES:

    print("\n" + "=" * 75)

    print(
        f"TRAINING KNN - K = {k}"
    )

    print("=" * 75)

    # --------------------------------------------------------
    # Create model
    # --------------------------------------------------------

    model = KNeighborsClassifier(
        n_neighbors=k,
        n_jobs=-1
    )

    # --------------------------------------------------------
    # Training
    # --------------------------------------------------------

    print("\nTraining model...")

    start_time = time.time()

    model.fit(
        X_train_balanced,
        y_train_balanced
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

    print(
        "Generating predictions..."
    )

    start_time = time.time()

    y_pred = model.predict(
        X_test_balanced
    )

    prediction_time = (
        time.time() - start_time
    )

    # --------------------------------------------------------
    # Probability
    # --------------------------------------------------------

    y_probability = model.predict_proba(
        X_test_balanced
    )[:, 1]

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test_balanced,
        y_pred
    )

    precision = precision_score(
        y_test_balanced,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test_balanced,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test_balanced,
        y_pred,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test_balanced,
        y_probability
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
            y_test_balanced,
            y_pred
        )
    )

    # --------------------------------------------------------
    # Save result
    # --------------------------------------------------------

    results.append({

        "algorithm": "KNN",

        "n_neighbors": k,

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1_score": f1,

        "roc_auc": roc_auc,

        "training_time": training_time,

        "prediction_time": prediction_time
    })

# ============================================================
# 11. CREATE RESULTS DATAFRAME
# ============================================================

results_df = pd.DataFrame(
    results
)

# ============================================================
# 12. DISPLAY COMPARISON
# ============================================================

print("\n\n" + "=" * 95)

print(
    "KNN CONFIGURATION COMPARISON"
)

print("=" * 95)

print(
    results_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)

# ============================================================
# 13. SAVE RESULTS
# ============================================================

results_file = os.path.join(
    RESULTS_DIR,
    "knn_configuration_results.csv"
)

results_df.to_csv(
    results_file,
    index=False
)

print("\nExperiment results saved to:")

print(
    results_file
)

# ============================================================
# 14. SELECT BEST CONFIGURATION
# ============================================================

best_index = results_df[
    "f1_score"
].idxmax()

best = results_df.loc[
    best_index
]

best_k = int(
    best["n_neighbors"]
)

print("\n" + "=" * 75)

print(
    "BEST KNN CONFIGURATION"
)

print("=" * 75)

print(
    f"\nK value    : {best_k}"
)

print(
    f"Accuracy   : "
    f"{best['accuracy']:.4f}"
)

print(
    f"Precision  : "
    f"{best['precision']:.4f}"
)

print(
    f"Recall     : "
    f"{best['recall']:.4f}"
)

print(
    f"F1 Score   : "
    f"{best['f1_score']:.4f}"
)

print(
    f"ROC-AUC    : "
    f"{best['roc_auc']:.4f}"
)

# ============================================================
# 15. TRAIN FINAL KNN MODEL
# ============================================================

print(
    f"\nTraining final KNN model "
    f"with K = {best_k}..."
)

final_model = KNeighborsClassifier(
    n_neighbors=best_k,
    n_jobs=-1
)

final_model.fit(
    X_train_balanced,
    y_train_balanced
)

# ============================================================
# 16. SAVE FINAL MODEL
# ============================================================

model_file = os.path.join(
    MODELS_DIR,
    f"final_knn_{best_k}.pkl"
)

joblib.dump(
    final_model,
    model_file
)

print("\nBest KNN model saved to:")

print(
    model_file
)

# ============================================================
# 17. FINAL REPORT
# ============================================================

print("\n" + "=" * 75)

print(
    "KNN EXPERIMENT COMPLETED"
)

print("=" * 75)

print(
    "\nBest configuration:"
)

print(
    f"K = {best_k}"
)

print(
    f"Accuracy = "
    f"{best['accuracy']:.4f}"
)

print(
    f"F1 Score = "
    f"{best['f1_score']:.4f}"
)

print(
    f"ROC-AUC = "
    f"{best['roc_auc']:.4f}"
)

print("\nFiles generated:")

print(
    f" - {results_file}"
)

print(
    f" - {model_file}"
)