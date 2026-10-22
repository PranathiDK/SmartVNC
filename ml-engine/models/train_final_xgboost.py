import numpy as np
import joblib
import xgboost as xgb

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

# ============================================================
# SMARTVNC - FINAL XGBOOST MODEL TRAINING
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "datasets" / "ml_ready"
MODEL_DIR = BASE_DIR / "ml-engine" / "models" / "saved_models"
RISK_DIR = BASE_DIR / "datasets" / "risk"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RISK_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 75)
print("SMARTVNC - FINAL XGBOOST MODEL TRAINING")
print("=" * 75)

# ============================================================
# 1. LOAD TRAIN/TEST DATA
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
# 2. CREATE BALANCED TRAINING DATA
# ============================================================

rng = np.random.RandomState(42)

train_normal_indices = np.where(y_train == 0)[0]
train_threat_indices = np.where(y_train == 1)[0]

samples_per_class = min(
    len(train_normal_indices),
    len(train_threat_indices)
)

print("\nBalanced training configuration:")
print(f"Samples per class: {samples_per_class:,}")

selected_normal = rng.choice(
    train_normal_indices,
    size=samples_per_class,
    replace=False
)

selected_threat = rng.choice(
    train_threat_indices,
    size=samples_per_class,
    replace=False
)

train_indices = np.concatenate(
    [selected_normal, selected_threat]
)

rng.shuffle(train_indices)

X_train_final = X_train[train_indices]
y_train_final = y_train[train_indices]

print("\nFinal balanced training dataset:")
print(f"Total  : {len(X_train_final):,}")
print(f"Normal : {(y_train_final == 0).sum():,}")
print(f"Threat : {(y_train_final == 1).sum():,}")

# ============================================================
# 3. CREATE BALANCED TESTING DATA
# ============================================================

test_normal_indices = np.where(y_test == 0)[0]
test_threat_indices = np.where(y_test == 1)[0]

test_samples_per_class = min(
    len(test_normal_indices),
    len(test_threat_indices)
)

print("\nBalanced testing configuration:")
print(f"Samples per class: {test_samples_per_class:,}")

selected_normal_test = rng.choice(
    test_normal_indices,
    size=test_samples_per_class,
    replace=False
)

selected_threat_test = rng.choice(
    test_threat_indices,
    size=test_samples_per_class,
    replace=False
)

test_indices = np.concatenate(
    [
        selected_normal_test,
        selected_threat_test
    ]
)

rng.shuffle(test_indices)

X_test_final = X_test[test_indices]
y_test_final = y_test[test_indices]

print("\nFinal balanced testing dataset:")
print(f"Total  : {len(X_test_final):,}")
print(f"Normal : {(y_test_final == 0).sum():,}")
print(f"Threat : {(y_test_final == 1).sum():,}")

# ============================================================
# 4. CHECK DATA
# ============================================================

print("\nChecking numerical data...")

if not np.isfinite(X_train_final).all():
    raise ValueError("Training data contains non-finite values.")

if not np.isfinite(X_test_final).all():
    raise ValueError("Testing data contains non-finite values.")

print("Training data: VALID")
print("Testing data : VALID")

# ============================================================
# 5. CREATE FINAL XGBOOST MODEL
# ============================================================

print("\n" + "=" * 75)
print("CREATING FINAL XGBOOST MODEL")
print("=" * 75)

print("\nConfiguration:")
print("Algorithm       : XGBoost")
print("Estimators      : 150")
print("Max depth       : 6")
print("Learning rate   : 0.1")
print("Subsample       : 0.8")
print("Column sampling : 0.8")
print("Random state    : 42")

model = xgb.XGBClassifier(
    n_estimators=150,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

# ============================================================
# 6. TRAIN FINAL MODEL
# ============================================================

print("\nTraining final XGBoost model...")
print("Please wait...")

model.fit(
    X_train_final,
    y_train_final
)

print("Final XGBoost training completed.")

# ============================================================
# 7. PREDICTIONS
# ============================================================

print("\nGenerating predictions...")

y_pred = model.predict(X_test_final)

y_probability = model.predict_proba(
    X_test_final
)[:, 1]

print("Predictions completed.")

# ============================================================
# 8. CALCULATE METRICS
# ============================================================

accuracy = accuracy_score(
    y_test_final,
    y_pred
)

precision = precision_score(
    y_test_final,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test_final,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test_final,
    y_pred,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test_final,
    y_probability
)

cm = confusion_matrix(
    y_test_final,
    y_pred
)

report = classification_report(
    y_test_final,
    y_pred,
    target_names=[
        "Normal",
        "Threat"
    ],
    zero_division=0
)

# ============================================================
# 9. DISPLAY FINAL PERFORMANCE
# ============================================================

print("\n" + "=" * 75)
print("FINAL XGBOOST MODEL PERFORMANCE")
print("=" * 75)

print(f"\nAccuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")
print(f"ROC-AUC   : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(report)

# ============================================================
# 10. FEATURE IMPORTANCE
# ============================================================

feature_names = [
    "session_duration",
    "forward_packets",
    "backward_packets",
    "bytes_per_second",
    "packets_per_second",
    "protocol"
]

print("=" * 75)
print("FEATURE IMPORTANCE")
print("=" * 75)

importance = model.feature_importances_

for name, value in sorted(
    zip(feature_names, importance),
    key=lambda x: x[1],
    reverse=True
):
    print(f"{name:<25}: {value:.6f}")

# ============================================================
# 11. SAVE FINAL MODEL
# ============================================================

model_path = (
    MODEL_DIR /
    "final_xgboost_150.pkl"
)

joblib.dump(
    model,
    model_path
)

print("\nFinal model saved to:")
print(model_path)

# ============================================================
# 12. SAVE FINAL VALIDATION REPORT
# ============================================================

report_path = (
    RISK_DIR /
    "final_xgboost_150_training_report.txt"
)

with open(
    report_path,
    "w",
    encoding="utf-8"
) as f:

    f.write("=" * 75 + "\n")
    f.write("SMARTVNC - FINAL XGBOOST MODEL REPORT\n")
    f.write("=" * 75 + "\n\n")

    f.write("MODEL CONFIGURATION\n")
    f.write("-" * 75 + "\n")
    f.write("Algorithm       : XGBoost\n")
    f.write("Estimators      : 150\n")
    f.write("Max depth       : 6\n")
    f.write("Learning rate   : 0.1\n")
    f.write("Subsample       : 0.8\n")
    f.write("Column sampling : 0.8\n")
    f.write("Random state    : 42\n\n")

    f.write("DATASET\n")
    f.write("-" * 75 + "\n")
    f.write(
        f"Training records : {len(X_train_final):,}\n"
    )
    f.write(
        f"Testing records  : {len(X_test_final):,}\n"
    )
    f.write(
        f"Training Normal  : {(y_train_final == 0).sum():,}\n"
    )
    f.write(
        f"Training Threat  : {(y_train_final == 1).sum():,}\n"
    )
    f.write(
        f"Testing Normal   : {(y_test_final == 0).sum():,}\n"
    )
    f.write(
        f"Testing Threat   : {(y_test_final == 1).sum():,}\n\n"
    )

    f.write("FINAL PERFORMANCE\n")
    f.write("-" * 75 + "\n")
    f.write(f"Accuracy  : {accuracy:.4f}\n")
    f.write(f"Precision : {precision:.4f}\n")
    f.write(f"Recall    : {recall:.4f}\n")
    f.write(f"F1 Score  : {f1:.4f}\n")
    f.write(f"ROC-AUC   : {roc_auc:.4f}\n\n")

    f.write("CONFUSION MATRIX\n")
    f.write("-" * 75 + "\n")
    f.write(str(cm))
    f.write("\n\n")

    f.write("CLASSIFICATION REPORT\n")
    f.write("-" * 75 + "\n")
    f.write(report)

    f.write("\nFEATURE IMPORTANCE\n")
    f.write("-" * 75 + "\n")

    for name, value in sorted(
        zip(feature_names, importance),
        key=lambda x: x[1],
        reverse=True
    ):
        f.write(
            f"{name:<25}: {value:.6f}\n"
        )

print("\nFinal report saved to:")
print(report_path)

# ============================================================
# 13. COMPLETED
# ============================================================

print("\n" + "=" * 75)
print("FINAL XGBOOST MODEL TRAINING COMPLETED")
print("=" * 75)