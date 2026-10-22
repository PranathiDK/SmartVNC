import numpy as np
import joblib

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "datasets" / "ml_ready"
MODEL_FILE = BASE_DIR / "ml-engine" / "models" / "saved" / "xgboost_model.pkl"

print("=" * 60)
print("SMARTVNC - XGBoost Full Test Validation")
print("=" * 60)

print("\nLoading test data...")

X_test = np.load(DATA_DIR / "X_test.npy")
y_test = np.load(DATA_DIR / "y_test.npy")

print(f"Testing records: {len(X_test):,}")

print("\nLoading saved XGBoost model...")

model = joblib.load(MODEL_FILE)

print("Model loaded successfully.")

print("\nGenerating predictions on FULL test set...")

y_pred = model.predict(X_test)

print("Predictions completed.")

print("\nCalculating prediction probabilities...")

y_probability = model.predict_proba(X_test)[:, 1]

print("Probability calculation completed.")

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

roc_auc = roc_auc_score(
    y_test,
    y_probability
)

print("\n" + "=" * 60)
print("XGBOOST FULL TEST PERFORMANCE")
print("=" * 60)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Normal", "Threat"],
        zero_division=0
    )
)

print("Confusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)

print("\n" + "=" * 60)
print("FULL TEST VALIDATION COMPLETED")
print("=" * 60)