import numpy as np
import joblib

from pathlib import Path
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
# SMARTVNC - KNN Training and Evaluation
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "datasets" / "ml_ready"

MODEL_DIR = (
    BASE_DIR
    / "ml-engine"
    / "models"
    / "saved"
)

MODEL_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("SMARTVNC - KNN Training and Evaluation")
print("=" * 60)

# ------------------------------------------------------------
# 1. Load SAME train/test data used by SVM
# ------------------------------------------------------------

print("\nLoading data...")

X_train = np.load(DATA_DIR / "X_train.npy")
X_test = np.load(DATA_DIR / "X_test.npy")

y_train = np.load(DATA_DIR / "y_train.npy")
y_test = np.load(DATA_DIR / "y_test.npy")

print(f"Training records: {len(X_train):,}")
print(f"Testing records : {len(X_test):,}")

print("\nTraining class distribution:")
print(np.unique(y_train, return_counts=True))

print("\nTesting class distribution:")
print(np.unique(y_test, return_counts=True))

# ------------------------------------------------------------
# 2. Create KNN model
# ------------------------------------------------------------

print("\nCreating KNN model...")

knn = KNeighborsClassifier(
    n_neighbors=5,
    weights="distance",
    n_jobs=-1
)

# ------------------------------------------------------------
# 3. Train
# ------------------------------------------------------------

print("\nTraining KNN...")
print("Please wait...")

knn.fit(X_train, y_train)

print("KNN training completed.")

# ------------------------------------------------------------
# 4. Predictions
# ------------------------------------------------------------

print("\nGenerating predictions...")

y_pred = knn.predict(X_test)

print("Predictions completed.")

# ------------------------------------------------------------
# 5. Probability scores
# ------------------------------------------------------------

print("\nCalculating probability scores...")

y_probability = knn.predict_proba(X_test)[:, 1]

print("Probability scores completed.")

# ------------------------------------------------------------
# 6. Evaluation
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

roc_auc = roc_auc_score(
    y_test,
    y_probability
)

# ------------------------------------------------------------
# 7. Display results
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("KNN PERFORMANCE")
print("=" * 60)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

# ------------------------------------------------------------
# 8. Classification report
# ------------------------------------------------------------

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Normal", "Threat"],
        zero_division=0
    )
)

# ------------------------------------------------------------
# 9. Confusion matrix
# ------------------------------------------------------------

print("Confusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)

# ------------------------------------------------------------
# 10. Save model
# ------------------------------------------------------------

model_file = MODEL_DIR / "knn_model.pkl"

joblib.dump(
    knn,
    model_file
)

print("\nModel saved to:")
print(model_file)

print("\n" + "=" * 60)
print("KNN EXPERIMENT COMPLETED")
print("=" * 60)