import numpy as np
import joblib

from pathlib import Path
from sklearn.svm import LinearSVC
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
# SMARTVNC - Linear SVM Model Training and Evaluation
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "datasets" / "ml_ready"
MODEL_DIR = BASE_DIR / "ml-engine" / "models" / "saved"

MODEL_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("SMARTVNC - Linear SVM Training and Evaluation")
print("=" * 60)

# ------------------------------------------------------------
# 1. Load data
# ------------------------------------------------------------

print("\nLoading data...")

X_train = np.load(DATA_DIR / "X_train.npy")
X_test = np.load(DATA_DIR / "X_test.npy")

y_train = np.load(DATA_DIR / "y_train.npy")
y_test = np.load(DATA_DIR / "y_test.npy")

print(f"Training records: {len(X_train):,}")
print(f"Testing records : {len(X_test):,}")

# ------------------------------------------------------------
# 2. Create Linear SVM
# ------------------------------------------------------------

print("\nCreating Linear SVM...")

svm_model = LinearSVC(
    C=1.0,
    max_iter=2000,
    class_weight="balanced",
    random_state=42
)

# ------------------------------------------------------------
# 3. Train
# ------------------------------------------------------------

print("\nTraining Linear SVM...")
print("Please wait...")

svm_model.fit(
    X_train,
    y_train
)

print("Linear SVM training completed.")

# ------------------------------------------------------------
# 4. Prediction
# ------------------------------------------------------------

print("\nGenerating predictions...")

y_pred = svm_model.predict(X_test)

print("Predictions completed.")

# ------------------------------------------------------------
# 5. Decision scores
# ------------------------------------------------------------

print("\nCalculating decision scores...")

y_score = svm_model.decision_function(X_test)

print("Decision scores completed.")

# ------------------------------------------------------------
# 6. Evaluation
# ------------------------------------------------------------

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
    y_score
)

# ------------------------------------------------------------
# 7. Display results
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("LINEAR SVM PERFORMANCE")
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
        target_names=[
            "Normal",
            "Threat"
        ],
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

# ------------------------------------------------------------
# 8. Save model
# ------------------------------------------------------------

model_file = MODEL_DIR / "linear_svm_model.pkl"

joblib.dump(
    svm_model,
    model_file
)

print("\nModel saved to:")
print(model_file)

print("\n" + "=" * 60)
print("LINEAR SVM EXPERIMENT COMPLETED")
print("=" * 60)