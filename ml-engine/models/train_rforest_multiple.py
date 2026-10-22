import numpy as np
import pandas as pd
import joblib

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

# ============================================================
# SMARTVNC - Random Forest Multiple Configuration Experiment
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "datasets" / "ml_ready"

MODEL_DIR = (
    BASE_DIR
    / "ml-engine"
    / "models"
    / "saved_models"
)

RESULT_DIR = BASE_DIR / "datasets" / "risk"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 75)
print("SMARTVNC - RANDOM FOREST MULTIPLE CONFIGURATION EXPERIMENT")
print("=" * 75)

# ------------------------------------------------------------
# 1. Load training and testing data
# ------------------------------------------------------------

print("\nLoading training and testing data...")

X_train = np.load(DATA_DIR / "X_train.npy")
X_test = np.load(DATA_DIR / "X_test.npy")

y_train = np.load(DATA_DIR / "y_train.npy")
y_test = np.load(DATA_DIR / "y_test.npy")

print(f"Training records available : {len(X_train):,}")
print(f"Testing records available  : {len(X_test):,}")

print("\nOriginal training distribution:")
print(f"Normal : {(y_train == 0).sum():,}")
print(f"Threat : {(y_train == 1).sum():,}")

print("\nOriginal testing distribution:")
print(f"Normal : {(y_test == 0).sum():,}")
print(f"Threat : {(y_test == 1).sum():,}")

# ------------------------------------------------------------
# 2. Create balanced training subset
# ------------------------------------------------------------

train_class_counts = [
    np.sum(y_train == 0),
    np.sum(y_train == 1)
]

TRAIN_SAMPLES_PER_CLASS = min(train_class_counts)

print("\nBalanced training configuration:")
print(
    f"Samples per class: {TRAIN_SAMPLES_PER_CLASS:,}"
)

rng_train = np.random.RandomState(42)

train_indices = []

for class_value in [0, 1]:

    class_indices = np.where(
        y_train == class_value
    )[0]

    selected_indices = rng_train.choice(
        class_indices,
        size=TRAIN_SAMPLES_PER_CLASS,
        replace=False
    )

    train_indices.extend(selected_indices)

train_indices = np.array(train_indices)

rng_train.shuffle(train_indices)

X_train_balanced = X_train[train_indices]
y_train_balanced = y_train[train_indices]

print("\nBalanced training dataset:")
print(f"Total  : {len(y_train_balanced):,}")
print(
    f"Normal : {(y_train_balanced == 0).sum():,}"
)
print(
    f"Threat : {(y_train_balanced == 1).sum():,}"
)

# ------------------------------------------------------------
# 3. Create balanced testing subset
# ------------------------------------------------------------

test_class_counts = [
    np.sum(y_test == 0),
    np.sum(y_test == 1)
]

TEST_SAMPLES_PER_CLASS = min(test_class_counts)

print("\nBalanced testing configuration:")
print(
    f"Samples per class: {TEST_SAMPLES_PER_CLASS:,}"
)

rng_test = np.random.RandomState(42)

test_indices = []

for class_value in [0, 1]:

    class_indices = np.where(
        y_test == class_value
    )[0]

    selected_indices = rng_test.choice(
        class_indices,
        size=TEST_SAMPLES_PER_CLASS,
        replace=False
    )

    test_indices.extend(selected_indices)

test_indices = np.array(test_indices)

rng_test.shuffle(test_indices)

X_test_balanced = X_test[test_indices]
y_test_balanced = y_test[test_indices]

print("\nBalanced evaluation dataset:")
print(f"Total  : {len(y_test_balanced):,}")
print(
    f"Normal : {(y_test_balanced == 0).sum():,}"
)
print(
    f"Threat : {(y_test_balanced == 1).sum():,}"
)

# ------------------------------------------------------------
# 4. Validate numerical data
# ------------------------------------------------------------

print("\nChecking numerical data...")

if not np.isfinite(X_train_balanced).all():
    raise ValueError(
        "Training data contains non-finite values."
    )

if not np.isfinite(X_test_balanced).all():
    raise ValueError(
        "Testing data contains non-finite values."
    )

print("Training data: VALID")
print("Testing data : VALID")

# ------------------------------------------------------------
# 5. Random Forest configurations
# ------------------------------------------------------------

configurations = [
    {
        "n_estimators": 50,
        "max_depth": None
    },
    {
        "n_estimators": 100,
        "max_depth": None
    },
    {
        "n_estimators": 150,
        "max_depth": None
    }
]

results = []

best_model = None
best_result = None

# ------------------------------------------------------------
# 6. Train configurations
# ------------------------------------------------------------

for config in configurations:

    n_estimators = config["n_estimators"]
    max_depth = config["max_depth"]

    print("\n" + "=" * 75)
    print(
        f"TRAINING RANDOM FOREST - "
        f"{n_estimators} TREES"
    )
    print("=" * 75)

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=42,
        n_jobs=-1,
        class_weight=None
    )

    print("\nTraining model...")

    model.fit(
        X_train_balanced,
        y_train_balanced
    )

    print("Training completed.")

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    print("Generating predictions...")

    y_pred = model.predict(
        X_test_balanced
    )

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

    cm = confusion_matrix(
        y_test_balanced,
        y_pred
    )

    result = {
        "algorithm": "Random Forest",
        "n_estimators": n_estimators,
        "max_depth": (
            "None"
            if max_depth is None
            else max_depth
        ),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "roc_auc": roc_auc
    }

    results.append(result)

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

    print("\nConfusion Matrix:")
    print(cm)

    # --------------------------------------------------------
    # Select best model using F1 score
    # --------------------------------------------------------

    if (
        best_result is None
        or f1 > best_result["f1_score"]
    ):

        best_result = result
        best_model = model

# ------------------------------------------------------------
# 7. Final comparison
# ------------------------------------------------------------

results_df = pd.DataFrame(results)

print("\n\n" + "=" * 90)
print("RANDOM FOREST CONFIGURATION COMPARISON")
print("=" * 90)

print(
    results_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)

# ------------------------------------------------------------
# 8. Save experiment results
# ------------------------------------------------------------

results_file = (
    RESULT_DIR
    / "random_forest_configuration_results.csv"
)

results_df.to_csv(
    results_file,
    index=False
)

print("\nExperiment results saved to:")
print(results_file)

# ------------------------------------------------------------
# 9. Save best Random Forest model
# ------------------------------------------------------------

best_estimators = best_result["n_estimators"]

model_file = (
    MODEL_DIR
    / f"final_random_forest_{best_estimators}.pkl"
)

joblib.dump(
    best_model,
    model_file
)

# ------------------------------------------------------------
# 10. Display best configuration
# ------------------------------------------------------------

print("\n" + "=" * 75)
print("BEST RANDOM FOREST CONFIGURATION")
print("=" * 75)

print(
    f"\nNumber of trees : "
    f"{best_result['n_estimators']}"
)

print(
    f"Accuracy        : "
    f"{best_result['accuracy']:.4f}"
)

print(
    f"Precision       : "
    f"{best_result['precision']:.4f}"
)

print(
    f"Recall          : "
    f"{best_result['recall']:.4f}"
)

print(
    f"F1 Score        : "
    f"{best_result['f1_score']:.4f}"
)

print(
    f"ROC-AUC         : "
    f"{best_result['roc_auc']:.4f}"
)

print("\nBest model saved to:")
print(model_file)

# ------------------------------------------------------------
# 11. Final
# ------------------------------------------------------------

print("\n" + "=" * 75)
print("RANDOM FOREST EXPERIMENT COMPLETED")
print("=" * 75)