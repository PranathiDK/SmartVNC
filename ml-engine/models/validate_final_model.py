import numpy as np
import joblib

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score
)

# ============================================================
# SMARTVNC - FINAL XGBOOST MODEL VALIDATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_FILE = (
    BASE_DIR
    / "ml-engine"
    / "models"
    / "saved_models"
    / "final_xgboost_150.pkl"
)

X_TEST_FILE = BASE_DIR / "datasets" / "ml_ready" / "X_test.npy"
Y_TEST_FILE = BASE_DIR / "datasets" / "ml_ready" / "y_test.npy"

print("=" * 70)
print("SMARTVNC - FINAL XGBOOST MODEL VALIDATION")
print("=" * 70)

# ------------------------------------------------------------
# 1. Load model
# ------------------------------------------------------------

print("\nLoading XGBoost model...")

model = joblib.load(MODEL_FILE)

print(f"Model: {MODEL_FILE}")
print(f"Model type: {type(model).__name__}")
print(f"Number of estimators: {model.n_estimators}")
print(f"Max depth: {model.max_depth}")
print(f"Learning rate: {model.learning_rate}")
print(f"Expected features: {model.n_features_in_}")

# ------------------------------------------------------------
# 2. Load test data
# ------------------------------------------------------------

print("\nLoading test dataset...")

X_test = np.load(X_TEST_FILE)
y_test = np.load(Y_TEST_FILE)

print(f"X_test shape: {X_test.shape}")
print(f"y_test shape: {y_test.shape}")

# ------------------------------------------------------------
# 3. Data validation
# ------------------------------------------------------------

print("\nChecking test data...")

print("Non-finite X values:",
      np.sum(~np.isfinite(X_test)))

print("Non-finite y values:",
      np.sum(~np.isfinite(y_test)))

if not np.isfinite(X_test).all():
    raise ValueError("X_test contains non-finite values.")

if not np.isfinite(y_test).all():
    raise ValueError("y_test contains non-finite values.")

# ------------------------------------------------------------
# 4. Prediction
# ------------------------------------------------------------

print("\nRunning XGBoost prediction...")

y_pred = model.predict(X_test)

# Probability for positive/attack class

if hasattr(model, "predict_proba"):
    y_probability = model.predict_proba(X_test)[:, 1]
else:
    y_probability = None

# ------------------------------------------------------------
# 5. Metrics
# ------------------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)

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

# ROC-AUC

if y_probability is not None:
    try:
        roc_auc = roc_auc_score(
            y_test,
            y_probability
        )
    except ValueError:
        roc_auc = None
else:
    roc_auc = None

# ------------------------------------------------------------
# 6. Display results
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("FINAL MODEL PERFORMANCE")
print("=" * 70)

print(f"\nAccuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

if roc_auc is not None:
    print(f"ROC-AUC   : {roc_auc:.4f}")

# ------------------------------------------------------------
# 7. Confusion Matrix
# ------------------------------------------------------------

cm = confusion_matrix(y_test, y_pred)

print("\n" + "=" * 70)
print("CONFUSION MATRIX")
print("=" * 70)

print(cm)

# ------------------------------------------------------------
# 8. Classification report
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("CLASSIFICATION REPORT")
print("=" * 70)

print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)

# ------------------------------------------------------------
# 9. Class distribution
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("TEST CLASS DISTRIBUTION")
print("=" * 70)

unique, counts = np.unique(
    y_test,
    return_counts=True
)

for label, count in zip(unique, counts):
    print(f"Class {label}: {count:,}")

# ------------------------------------------------------------
# 10. Feature importance
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("FEATURE IMPORTANCE")
print("=" * 70)

feature_names = [
    "session_duration",
    "forward_packets",
    "backward_packets",
    "bytes_per_second",
    "packets_per_second",
    "protocol"
]

importance = model.feature_importances_

for name, value in sorted(
    zip(feature_names, importance),
    key=lambda x: x[1],
    reverse=True
):
    print(f"{name:25s}: {value:.6f}")

# ------------------------------------------------------------
# 11. Save validation summary
# ------------------------------------------------------------

output_file = (
    BASE_DIR
    / "datasets"
    / "risk"
    / "final_model_validation.txt"
)

with open(output_file, "w", encoding="utf-8") as f:

    f.write("SMARTVNC - FINAL XGBOOST MODEL VALIDATION\n")
    f.write("=" * 60 + "\n\n")

    f.write(f"Model: final_xgboost_150.pkl\n")
    f.write(f"Estimators: {model.n_estimators}\n")
    f.write(f"Max depth: {model.max_depth}\n")
    f.write(f"Learning rate: {model.learning_rate}\n\n")

    f.write(f"Accuracy: {accuracy:.6f}\n")
    f.write(f"Precision: {precision:.6f}\n")
    f.write(f"Recall: {recall:.6f}\n")
    f.write(f"F1 Score: {f1:.6f}\n")

    if roc_auc is not None:
        f.write(f"ROC-AUC: {roc_auc:.6f}\n")

    f.write("\nConfusion Matrix:\n")
    f.write(str(cm))

    f.write("\n\nClassification Report:\n")
    f.write(
        classification_report(
            y_test,
            y_pred,
            zero_division=0
        )
    )

    f.write("\nFeature Importance:\n")

    for name, value in sorted(
        zip(feature_names, importance),
        key=lambda x: x[1],
        reverse=True
    ):
        f.write(f"{name}: {value:.6f}\n")

print("\n" + "=" * 70)
print("MODEL VALIDATION COMPLETED")
print("=" * 70)

print(f"\nValidation report:")
print(output_file)