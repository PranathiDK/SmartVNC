import os
import time
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score

from xgboost import XGBClassifier


# ============================================================
# PATHS
# ============================================================

BASE_DIR = r"C:\SmartVNC"

DATASET_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "ml_ready",
    "cicids_ml_ready.csv"
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "ml-engine",
    "models",
    "results"
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
# CONFIGURATION
# ============================================================

SAMPLE_SIZE = 500_000

TEST_SIZE = 0.20

RANDOM_STATE = 42

FEATURE_COLUMNS = [
    "session_duration",
    "forward_packets",
    "backward_packets",
    "bytes_per_second",
    "packets_per_second",
    "protocol"
]

TARGET_COLUMN = "target"


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 75)
print("SMARTVNC - FINAL COMMON TEST SET COMPARISON")
print("=" * 75)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print(
    f"Original dataset shape: {df.shape}"
)


# ============================================================
# CLEAN INFINITY VALUES
# ============================================================

print("\nCleaning infinity values...")

df[FEATURE_COLUMNS] = df[
    FEATURE_COLUMNS
].replace(
    [np.inf, -np.inf],
    np.nan
)

before = len(df)

df = df.dropna(
    subset=FEATURE_COLUMNS
).reset_index(drop=True)

after = len(df)

print(
    f"Rows before cleaning: {before}"
)

print(
    f"Rows after cleaning : {after}"
)

print(
    f"Rows removed        : {before - after}"
)


# ============================================================
# CREATE FEATURES / TARGET
# ============================================================

X = df[FEATURE_COLUMNS]

y = df[TARGET_COLUMN]

print("\nComplete target distribution:")

print(y.value_counts())


# ============================================================
# CREATE COMMON 500K STRATIFIED DATASET
# ============================================================

print("\nCreating common stratified dataset...")

X_common, _, y_common, _ = train_test_split(
    X,
    y,
    train_size=SAMPLE_SIZE,
    random_state=RANDOM_STATE,
    stratify=y
)

print(
    f"Common dataset size: {len(X_common)}"
)

print("\nCommon dataset target distribution:")

print(y_common.value_counts())


# ============================================================
# COMMON TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X_common,
    y_common,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y_common
)

print("\nCommon Train/Test split:")

print(
    f"Training samples: {len(X_train)}"
)

print(
    f"Testing samples : {len(X_test)}"
)

print("\nIMPORTANT:")
print("All four algorithms will use the SAME test set.")


# ============================================================
# SCALE DATA FOR KNN AND SVM
# ============================================================

print("\nScaling features for KNN/SVM...")

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(
    X_train
)

X_test_scaled = scaler.transform(
    X_test
)


# ============================================================
# RESULTS
# ============================================================

results = []


# ============================================================
# 1. RANDOM FOREST
# ============================================================

print("\n")
print("=" * 75)
print("1. RANDOM FOREST - 150 TREES")
print("=" * 75)

rf = RandomForestClassifier(
    n_estimators=150,
    random_state=RANDOM_STATE,
    n_jobs=-1
)

start = time.time()

rf.fit(
    X_train,
    y_train
)

rf_train_time = time.time() - start

start = time.time()

rf_pred = rf.predict(
    X_test
)

rf_prediction_time = time.time() - start

rf_accuracy = accuracy_score(
    y_test,
    rf_pred
)

print(
    f"Accuracy       : {rf_accuracy:.4f}"
)

print(
    f"Training Time  : {rf_train_time:.2f} seconds"
)

print(
    f"Prediction Time: {rf_prediction_time:.2f} seconds"
)

results.append({
    "Algorithm": "Random Forest",
    "Configuration": "150 Trees",
    "Accuracy": rf_accuracy,
    "Training Time": rf_train_time,
    "Prediction Time": rf_prediction_time
})


# ============================================================
# 2. KNN
# ============================================================

print("\n")
print("=" * 75)
print("2. KNN - K = 11")
print("=" * 75)

knn = KNeighborsClassifier(
    n_neighbors=11,
    n_jobs=-1
)

start = time.time()

knn.fit(
    X_train_scaled,
    y_train
)

knn_train_time = time.time() - start

start = time.time()

knn_pred = knn.predict(
    X_test_scaled
)

knn_prediction_time = time.time() - start

knn_accuracy = accuracy_score(
    y_test,
    knn_pred
)

print(
    f"Accuracy       : {knn_accuracy:.4f}"
)

print(
    f"Training Time  : {knn_train_time:.2f} seconds"
)

print(
    f"Prediction Time: {knn_prediction_time:.2f} seconds"
)

results.append({
    "Algorithm": "KNN",
    "Configuration": "K = 11",
    "Accuracy": knn_accuracy,
    "Training Time": knn_train_time,
    "Prediction Time": knn_prediction_time
})


# ============================================================
# 3. LINEAR SVM
# ============================================================

print("\n")
print("=" * 75)
print("3. LINEAR SVM - C = 0.1")
print("=" * 75)

svm = LinearSVC(
    C=0.1,
    max_iter=5000,
    random_state=RANDOM_STATE
)

start = time.time()

svm.fit(
    X_train_scaled,
    y_train
)

svm_train_time = time.time() - start

start = time.time()

svm_pred = svm.predict(
    X_test_scaled
)

svm_prediction_time = time.time() - start

svm_accuracy = accuracy_score(
    y_test,
    svm_pred
)

print(
    f"Accuracy       : {svm_accuracy:.4f}"
)

print(
    f"Training Time  : {svm_train_time:.2f} seconds"
)

print(
    f"Prediction Time: {svm_prediction_time:.2f} seconds"
)

results.append({
    "Algorithm": "Linear SVM",
    "Configuration": "C = 0.1",
    "Accuracy": svm_accuracy,
    "Training Time": svm_train_time,
    "Prediction Time": svm_prediction_time
})


# ============================================================
# 4. XGBOOST
# ============================================================

print("\n")
print("=" * 75)
print("4. XGBOOST - 150 BOOSTING ROUNDS")
print("=" * 75)

xgb = XGBClassifier(
    n_estimators=150,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=RANDOM_STATE,
    n_jobs=-1
)

start = time.time()

xgb.fit(
    X_train,
    y_train
)

xgb_train_time = time.time() - start

start = time.time()

xgb_pred = xgb.predict(
    X_test
)

xgb_prediction_time = time.time() - start

xgb_accuracy = accuracy_score(
    y_test,
    xgb_pred
)

print(
    f"Accuracy       : {xgb_accuracy:.4f}"
)

print(
    f"Training Time  : {xgb_train_time:.2f} seconds"
)

print(
    f"Prediction Time: {xgb_prediction_time:.2f} seconds"
)

results.append({
    "Algorithm": "XGBoost",
    "Configuration": "150 Boosting Rounds",
    "Accuracy": xgb_accuracy,
    "Training Time": xgb_train_time,
    "Prediction Time": xgb_prediction_time
})


# ============================================================
# FINAL COMPARISON
# ============================================================

results_df = pd.DataFrame(results)

results_df = results_df.sort_values(
    by="Accuracy",
    ascending=False
).reset_index(drop=True)


print("\n\n")

print("=" * 100)

print("FINAL SMARTVNC ALGORITHM COMPARISON")

print("=" * 100)

print(
    results_df.to_string(
        index=False
    )
)


# ============================================================
# RANKING
# ============================================================

results_df.insert(
    0,
    "Rank",
    range(1, len(results_df) + 1)
)

print("\n")

print("=" * 75)

print("ACCURACY-BASED RANKING")

print("=" * 75)

for _, row in results_df.iterrows():

    print(
        f"{int(row['Rank'])}. "
        f"{row['Algorithm']} "
        f"({row['Configuration']}) "
        f"-> {row['Accuracy']:.4%}"
    )


# ============================================================
# BEST MODEL
# ============================================================

best = results_df.iloc[0]

print("\n")

print("=" * 75)

print("BEST SMARTVNC MODEL")
print("=" * 75)

print(
    f"Algorithm     : {best['Algorithm']}"
)

print(
    f"Configuration : {best['Configuration']}"
)

print(
    f"Accuracy      : {best['Accuracy']:.4%}"
)


# ============================================================
# SAVE RESULTS
# ============================================================

results_path = os.path.join(
    RESULTS_DIR,
    "final_common_comparison.csv"
)

results_df.to_csv(
    results_path,
    index=False
)

print("\nFinal comparison saved to:")

print(results_path)


# ============================================================
# SAVE THE FOUR MODELS
# ============================================================

print("\nSaving models...")

joblib.dump(
    rf,
    os.path.join(
        MODELS_DIR,
        "final_random_forest_150.pkl"
    )
)

joblib.dump(
    knn,
    os.path.join(
        MODELS_DIR,
        "final_knn_11.pkl"
    )
)

joblib.dump(
    svm,
    os.path.join(
        MODELS_DIR,
        "final_svm_c01.pkl"
    )
)

joblib.dump(
    xgb,
    os.path.join(
        MODELS_DIR,
        "final_xgboost_150.pkl"
    )
)

joblib.dump(
    scaler,
    os.path.join(
        MODELS_DIR,
        "final_scaler.pkl"
    )
)

print("All final models saved.")


# ============================================================
# COMPLETED
# ============================================================

print("\n")

print("=" * 75)

print("FINAL COMMON COMPARISON COMPLETED")

print("=" * 75)