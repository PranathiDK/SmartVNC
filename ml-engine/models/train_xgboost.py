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
    classification_report,
    confusion_matrix
)

# ============================================================
# SMARTVNC - XGBoost Training and Evaluation
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = BASE_DIR / "datasets" / "ml_ready"

MODEL_DIR = BASE_DIR / "ml-engine" / "models" / "saved"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("SMARTVNC - XGBoost Training and Evaluation")
print("=" * 60)

# ------------------------------------------------------------
# 1. Load SAME data used by all other models
# ------------------------------------------------------------

print("\nLoading data...")

X_train = np.load(DATA_DIR / "X_train.npy")
X_test = np.load(DATA_DIR / "X_test.npy")

y_train = np.load(DATA_DIR / "y_train.npy")
y_test = np.load(DATA_DIR / "y_test.npy")

print(f"Training records: {len(X_train):,}")
print(f"Testing records : {len(X_test):,}")

# ------------------------------------------------------------
# 2. Calculate class imbalance weight
# ------------------------------------------------------------

normal_count = np.sum(y_train == 0)
threat_count = np.sum(y_train == 1)

scale_pos_weight = normal_count / threat_count

print(f"\nScale position weight: {scale_pos_weight:.4f}")

# ------------------------------------------------------------
# 3. Create XGBoost model
# ------------------------------------------------------------

print("\nCreating XGBoost model...")

model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",
    eval_metric="logloss",
    scale_pos_weight=scale_pos_weight,
    random_state=42,
    n_jobs=-1
)

# ------------------------------------------------------------
# 4. Train
# ------------------------------------------------------------

print("\nTraining XGBoost...")
print("Please wait...")

model.fit(
    X_train,
    y_train
)

print("XGBoost training completed.")

# ------------------------------------------------------------
# 5. Predictions
# ------------------------------------------------------------

print("\nGenerating predictions...")

y_pred = model.predict(X_test)

print("Predictions completed.")

# ------------------------------------------------------------
# 6. Probability scores
# ------------------------------------------------------------

print("\nCalculating prediction probabilities...")

y_probability = model.predict_proba(X_test)[:, 1]

print("Probability calculation completed.")

# ------------------------------------------------------------
# 7. Evaluation
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
# 8. Results
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("XGBOOST PERFORMANCE")
print("=" * 60)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

# ------------------------------------------------------------
# 9. Classification Report
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
# 10. Confusion Matrix
# ------------------------------------------------------------

print("Confusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)

# ------------------------------------------------------------
# 11. Save model
# ------------------------------------------------------------

model_file = MODEL_DIR / "xgboost_model.pkl"

joblib.dump(
    model,
    model_file
)

print("\nXGBoost model saved to:")
print(model_file)

print("\n" + "=" * 60)
print("XGBOOST EXPERIMENT COMPLETED")
print("=" * 60)