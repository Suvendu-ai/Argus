# ml/train_cicids_classifier.py
# ─────────────────────────────────────────
# ARGUS — CICIDS2017 Classifier Training
# Trains Random Forest on modern 2017 dataset
# Covers 14 attack types including DDoS,
# Web Attacks, Botnet, Infiltration & more
# ─────────────────────────────────────────

import pandas as pd
import numpy as np
import os
import glob
import logging
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────
# Path to CICIDS2017 CSV files
# ─────────────────────────────────────────
CICIDS_DIR  = "data/raw/CICIDS2017/MachineLearningCVE/"
MODELS_DIR  = "ml/models/"

# ─────────────────────────────────────────
# CICIDS2017 has 14 attack categories
# We group them into clean labels
# ─────────────────────────────────────────
LABEL_MAP = {
    "BENIGN"                        : "NORMAL",
    "DDoS"                          : "DDoS",
    "DoS Hulk"                      : "DoS",
    "DoS GoldenEye"                 : "DoS",
    "DoS slowloris"                 : "DoS",
    "DoS Slowhttptest"              : "DoS",
    "Heartbleed"                    : "DoS",
    "PortScan"                      : "PortScan",
    "FTP-Patator"                   : "BruteForce",
    "SSH-Patator"                   : "BruteForce",
    "Web Attack – Brute Force"      : "WebAttack",
    "Web Attack – XSS"              : "WebAttack",
    "Web Attack – Sql Injection"    : "WebAttack",
    "Infiltration"                  : "Infiltration",
    "Bot"                           : "Botnet",
}


def load_cicids_data(data_dir: str) -> pd.DataFrame:
    """
    Loads all 8 CICIDS2017 CSV files and combines them.
    """
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))

    if not csv_files:
        logger.error(f"No CSV files found in {data_dir}")
        logger.error("Make sure CICIDS2017 files are in the right folder!")
        exit(1)

    logger.info(f"Found {len(csv_files)} CSV files:")
    dfs = []

    for f in csv_files:
        filename = os.path.basename(f)
        logger.info(f"   Loading → {filename}")
        try:
            df = pd.read_csv(f, encoding='utf-8', low_memory=False)
            dfs.append(df)
            logger.info(f"   ✅ {len(df):,} rows loaded")
        except Exception as e:
            logger.warning(f"   ⚠️  Skipping {filename} — {e}")

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"\n✅ Total combined rows: {len(combined):,}")
    return combined


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans the CICIDS2017 dataset.
    Fixes column names, removes bad values.
    """
    logger.info("Cleaning data...")

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Find the label column
    label_col = None
    for col in df.columns:
        if "label" in col.lower():
            label_col = col
            break

    if not label_col:
        logger.error("Could not find label column!")
        exit(1)

    logger.info(f"Label column found: '{label_col}'")

    # Strip whitespace from labels
    df[label_col] = df[label_col].astype(str).str.strip()

    # Map labels to clean categories
    df["attack_category"] = df[label_col].map(
        lambda x: LABEL_MAP.get(x, "Unknown")
    )

    # Drop original label column
    df.drop(columns=[label_col], inplace=True)

    # Show attack distribution
    logger.info("\n📊 Attack distribution:")
    counts = df["attack_category"].value_counts()
    for label, count in counts.items():
        bar = "█" * min(30, int(count / counts.max() * 30))
        logger.info(f"   {label:<15} → {count:>8,}  {bar}")

    # Replace infinite values with NaN then fill
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    # Remove non-numeric columns except label
    feature_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    df = df[feature_cols + ["attack_category"]]

    logger.info(f"\n✅ Features after cleaning: {len(feature_cols)}")
    return df


def balance_data(df: pd.DataFrame, max_per_class: int = 50000) -> pd.DataFrame:
    """
    Balances the dataset so no single class dominates.
    CICIDS2017 has 2.2M BENIGN rows vs ~1000 Infiltration rows.
    We cap each class at max_per_class samples.
    """
    logger.info(f"Balancing dataset (max {max_per_class:,} per class)...")

    balanced_dfs = []
    for label in df["attack_category"].unique():
        subset = df[df["attack_category"] == label]
        if len(subset) > max_per_class:
            subset = subset.sample(n=max_per_class, random_state=42)
        balanced_dfs.append(subset)

    balanced = pd.concat(balanced_dfs, ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)

    logger.info(f"✅ Balanced dataset size: {len(balanced):,} rows")
    return balanced


def train_cicids_model(df: pd.DataFrame):
    """
    Trains Random Forest on CICIDS2017.
    """
    logger.info("Preparing features and labels...")

    # Encode target labels
    le = LabelEncoder()
    y = le.fit_transform(df["attack_category"])
    X = df.drop("attack_category", axis=1)

    logger.info(f"✅ Classes: {list(le.classes_)}")
    logger.info(f"✅ Features: {X.shape[1]}")
    logger.info(f"✅ Samples : {X.shape[0]:,}")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    logger.info("─" * 50)
    logger.info("Training Random Forest on CICIDS2017...")
    logger.info("Using 100 trees | All CPU cores | Please wait...")
    logger.info("─" * 50)

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        verbose=0
    )

    model.fit(X_train, y_train)
    logger.info("✅ Training complete!")

    # Evaluate
    y_pred   = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    logger.info(f"✅ Accuracy: {accuracy * 100:.2f}%")

    print("\n📊 Detailed Classification Report:")
    print("─" * 60)
    print(classification_report(
        y_test, y_pred,
        target_names=le.classes_,
        zero_division=0
    ))

    # Feature importance
    feature_names = X.columns.tolist()
    importances   = model.feature_importances_
    top_features  = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1], reverse=True
    )[:10]

    print("\n🔍 Top 10 Most Important Features:")
    print("─" * 50)
    for feat, score in top_features:
        bar = "█" * int(score * 100)
        print(f"  {feat:<35} {bar} {score:.4f}")

    return model, le, X.columns.tolist(), accuracy


def save_cicids_model(model, label_encoder, feature_cols, accuracy):
    """
    Saves the CICIDS2017 trained model.
    """
    os.makedirs(MODELS_DIR, exist_ok=True)

    joblib.dump(model,         f"{MODELS_DIR}cicids_classifier.pkl")
    joblib.dump(label_encoder, f"{MODELS_DIR}cicids_label_encoder.pkl")
    joblib.dump(feature_cols,  f"{MODELS_DIR}cicids_feature_cols.pkl")

    logger.info(f"✅ CICIDS model saved   → {MODELS_DIR}cicids_classifier.pkl")
    logger.info(f"✅ Label encoder saved  → {MODELS_DIR}cicids_label_encoder.pkl")
    logger.info(f"✅ Feature cols saved   → {MODELS_DIR}cicids_feature_cols.pkl")

    # Save model info
    info = {
        "dataset"    : "CICIDS2017",
        "accuracy"   : f"{accuracy * 100:.2f}%",
        "classes"    : list(label_encoder.classes_),
        "n_features" : len(feature_cols),
        "n_estimators": 100
    }
    joblib.dump(info, f"{MODELS_DIR}cicids_model_info.pkl")
    logger.info(f"✅ Model info saved     → {MODELS_DIR}cicids_model_info.pkl")


# ─────────────────────────────────────────
# Run
# ─────────────────────────────────────────
if __name__ == "__main__":
    logger.info("=" * 55)
    logger.info("  ARGUS — CICIDS2017 Classifier Training")
    logger.info("  14 Modern Attack Categories")
    logger.info("=" * 55)

    # 1. Load all CSV files
    df = load_cicids_data(CICIDS_DIR)

    # 2. Clean data
    df = clean_data(df)

    # 3. Balance dataset
    df = balance_data(df, max_per_class=50000)

    # 4. Train model
    model, le, feature_cols, accuracy = train_cicids_model(df)

    # 5. Save
    save_cicids_model(model, le, feature_cols, accuracy)

    logger.info("=" * 55)
    logger.info("  CICIDS2017 Classifier Ready!")
    logger.info(f"  Accuracy: {accuracy * 100:.2f}%")
    logger.info(f"  Classes : {list(le.classes_)}")
    logger.info("=" * 55)