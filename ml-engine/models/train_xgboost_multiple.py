import numpy as np
import pandas as pd
import joblib
import xgboost as xgb

from pathlib import Path

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

# ============================================================
# SMARTVNC - XGBoost Multiple Configuration Experiment
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "datasets" / "ml_ready"

MODEL_DIR = (
    BASE_DIR
    / "ml-engine"
    / "models"
    / "saved_models"
)

RESULT_DIR = (
    BASE_DIR
    / "datasets"
    / "risk"
)

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("SMARTVNC - XGBoost Multiple Configuration Experiment")
print("=" * 70)

# ============================================================
# 1. Load data
# ============================================================

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

# ============================================================
# 2. Determine balanced training size automatically
# ============================================================

rng = np.random.RandomState(42)

normal_train_count = np.sum(y_train == 0)
threat_train_count = np.sum(y_train == 1)

TRAIN_SAMPLES_PER_CLASS = min(
    normal_train_count,
    threat_train_count
)

print("\nBalanced training configuration:")
print(
    f"Samples per class: {TRAIN_SAMPLES_PER_CLASS:,}"
)

# ============================================================
# 3. Create balanced training subset
# ============================================================

print("\nCreating balanced training subset...")

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

    train_indices.extend(selected_indices)

train_indices = np.array(train_indices)

rng.shuffle(train_indices)

X_train_balanced = X_train[train_indices]
y_train_balanced = y_train[train_indices]

print("\nBalanced training dataset:")
print(f"Total  : {len(y_train_balanced):,}")
print(f"Normal : {(y_train_balanced == 0).sum():,}")
print(f"Threat : {(y_train_balanced == 1).sum():,}")

# ============================================================
# 4. Determine balanced test size automatically
# ============================================================

normal_test_count = np.sum(y_test == 0)
threat_test_count = np.sum(y_test == 1)

TEST_SAMPLES_PER_CLASS = min(
    normal_test_count,
    threat_test_count
)

print("\nBalanced testing configuration:")
print(
    f"Samples per class: {TEST_SAMPLES_PER_CLASS:,}"
)

# ============================================================
# 5. Create balanced test subset
# ============================================================

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

    test_indices.extend(selected_indices)

test_indices = np.array(test_indices)

rng.shuffle(test_indices)

X_test_balanced = X_test[test_indices]
y_test_balanced = y_test[test_indices]

print("\nBalanced evaluation dataset:")
print(f"Total  : {len(y_test_balanced):,}")
print(f"Normal : {(y_test_balanced == 0).sum():,}")
print(f"Threat : {(y_test_balanced == 1).sum():,}")

# ============================================================
# 6. Verify numerical data
# ============================================================

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

# ============================================================
# 7. XGBoost configurations
# ============================================================

boosting_rounds = [50, 100, 150]

results = []

best_model = None
best_result = None

# ============================================================
# 8. Train configurations
# ============================================================

for rounds in boosting_rounds:

    print("\n" + "=" * 70)
    print(
        f"TRAINING XGBOOST - {rounds} BOOSTING ROUNDS"
    )
    print("=" * 70)

    model = xgb.XGBClassifier(

        n_estimators=rounds,

        max_depth=6,

        learning_rate=0.1,

        subsample=0.8,

        colsample_bytree=0.8,

        objective="binary:logistic",

        eval_metric="logloss",

        random_state=42,

        n_jobs=-1

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

    # --------------------------------------------------------
    # Store result
    # --------------------------------------------------------

    result = {

        "algorithm": "XGBoost",

        "n_estimators": rounds,

        "max_depth": 6,

        "learning_rate": 0.1,

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1_score": f1,

        "roc_auc": roc_auc

    }

    results.append(result)

    # --------------------------------------------------------
    # Display results
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

# ============================================================
# 9. Final comparison
# ============================================================

results_df = pd.DataFrame(results)

print("\n\n" + "=" * 85)
print("XGBOOST CONFIGURATION COMPARISON")
print("=" * 85)

print(
    results_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)

# ============================================================
# 10. Save experiment results
# ============================================================

results_file = (
    RESULT_DIR
    / "xgboost_configuration_results.csv"
)

results_df.to_csv(
    results_file,
    index=False
)

print("\nExperiment results saved to:")
print(results_file)

# ============================================================
# 11. Save best model
# ============================================================

if best_model is None:

    raise RuntimeError(
        "No best model was selected."
    )

best_rounds = best_result["n_estimators"]

best_model_file = (
    MODEL_DIR
    / f"final_xgboost_{best_rounds}.pkl"
)

joblib.dump(
    best_model,
    best_model_file
)

# ============================================================
# 12. Final result
# ============================================================

print("\n" + "=" * 70)
print("BEST XGBOOST CONFIGURATION")
print("=" * 70)

print(
    f"\nBoosting rounds : {best_rounds}"
)

print(
    f"Accuracy        : {best_result['accuracy']:.4f}"
)

print(
    f"Precision       : {best_result['precision']:.4f}"
)

print(
    f"Recall          : {best_result['recall']:.4f}"
)

print(
    f"F1 Score        : {best_result['f1_score']:.4f}"
)

print(
    f"ROC-AUC         : {best_result['roc_auc']:.4f}"
)

print("\nBest model saved to:")
print(best_model_file)

print("\n" + "=" * 70)
print("XGBOOST EXPERIMENT COMPLETED")
print("=" * 70)