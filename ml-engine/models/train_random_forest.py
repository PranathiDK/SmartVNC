import numpy as np
import joblib

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
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
# SMARTVNC - Random Forest Training and Evaluation
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "datasets" / "ml_ready"

MODEL_DIR = BASE_DIR / "ml-engine" / "models" / "saved"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("SMARTVNC - Random Forest Training and Evaluation")
print("=" * 60)

# ------------------------------------------------------------
# 1. Load SAME data used by SVM and KNN
# ------------------------------------------------------------

print("\nLoading data...")

X_train = np.load(DATA_DIR / "X_train.npy")
X_test = np.load(DATA_DIR / "X_test.npy")

y_train = np.load(DATA_DIR / "y_train.npy")
y_test = np.load(DATA_DIR / "y_test.npy")

print(f"Training records: {len(X_train):,}")
print(f"Testing records : {len(X_test):,}")

# ------------------------------------------------------------
# 2. Create Random Forest
# ------------------------------------------------------------

print("\nCreating Random Forest model...")

rf = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

# ------------------------------------------------------------
# 3. Train
# ------------------------------------------------------------

print("\nTraining Random Forest...")
print("Please wait...")

rf.fit(X_train, y_train)

print("Random Forest training completed.")

# ------------------------------------------------------------
# 4. Predictions
# ------------------------------------------------------------

print("\nGenerating predictions...")

y_pred = rf.predict(X_test)

print("Predictions completed.")

# ------------------------------------------------------------
# 5. Probability scores
# ------------------------------------------------------------

print("\nCalculating prediction probabilities...")

y_probability = rf.predict_proba(X_test)[:, 1]

print("Probability calculation completed.")

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
# 7. Results
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("RANDOM FOREST PERFORMANCE")
print("=" * 60)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

# ------------------------------------------------------------
# 8. Classification Report
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
# 9. Confusion Matrix
# ------------------------------------------------------------

print("Confusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)

# ------------------------------------------------------------
# 10. Feature Importance
# ------------------------------------------------------------

feature_names = [
    "session_duration",
    "forward_packets",
    "backward_packets",
    "bytes_per_second",
    "packets_per_second",
    "protocol"
]

print("\nFeature Importance:")

for feature, importance in zip(
    feature_names,
    rf.feature_importances_
):
    print(f"{feature:25s}: {importance:.6f}")

# ------------------------------------------------------------
# 11. Save model
# ------------------------------------------------------------

model_file = MODEL_DIR / "random_forest_model.pkl"

joblib.dump(
    rf,
    model_file
)

print("\nRandom Forest model saved to:")
print(model_file)

print("\n" + "=" * 60)
print("RANDOM FOREST EXPERIMENT COMPLETED")
print("=" * 60)