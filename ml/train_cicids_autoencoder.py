# ml/train_cicids_autoencoder.py
# ─────────────────────────────────────────
# ARGUS — CICIDS2017 Autoencoder Training
# Detects unknown/zero-day attacks on
# modern 2017 network traffic patterns
# ─────────────────────────────────────────

import pandas as pd
import numpy as np
import os
import glob
import logging
import joblib
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

CICIDS_DIR = "data/raw/CICIDS2017/MachineLearningCVE/"
MODELS_DIR = "ml/models/"

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
    "Web Attack \x96 Brute Force"   : "WebAttack",
    "Web Attack \x96 XSS"           : "WebAttack",
    "Web Attack \x96 Sql Injection" : "WebAttack",
    "Web Attack – Brute Force"      : "WebAttack",
    "Web Attack – XSS"              : "WebAttack",
    "Web Attack – Sql Injection"    : "WebAttack",
    "Infiltration"                  : "Infiltration",
    "Bot"                           : "Botnet",
}


def load_and_prepare(data_dir: str):
    """
    Loads CICIDS2017 data and prepares it
    for autoencoder training.
    Trains ONLY on normal traffic.
    """
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    logger.info(f"Loading {len(csv_files)} CSV files...")

    dfs = []
    for f in csv_files:
        try:
            df = pd.read_csv(f, encoding='utf-8', low_memory=False)
            dfs.append(df)
        except Exception as e:
            logger.warning(f"Skipping {os.path.basename(f)} — {e}")

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"✅ Total rows: {len(combined):,}")

    # Clean columns
    combined.columns = combined.columns.str.strip()

    # Find label column
    label_col = next(
        (c for c in combined.columns if "label" in c.lower()), None
    )
    combined[label_col] = combined[label_col].astype(str).str.strip()

    # Map labels
    combined["attack_category"] = combined[label_col].map(
        lambda x: LABEL_MAP.get(x, "Unknown")
    )
    combined.drop(columns=[label_col], inplace=True)

    # Fix infinite and NaN values
    combined.replace([np.inf, -np.inf], np.nan, inplace=True)
    combined.fillna(0, inplace=True)

    # Keep only numeric features
    feature_cols = combined.select_dtypes(
        include=[np.number]
    ).columns.tolist()
    combined = combined[feature_cols + ["attack_category"]]

    # Split normal vs attack
    normal_df = combined[combined["attack_category"] == "NORMAL"]
    attack_df = combined[combined["attack_category"] != "NORMAL"]

    logger.info(f"✅ Normal samples : {len(normal_df):,}")
    logger.info(f"✅ Attack samples : {len(attack_df):,}")

    # Sample for speed
    normal_sample = normal_df.sample(
        n=min(100000, len(normal_df)), random_state=42
    )
    attack_sample = attack_df.sample(
        n=min(50000, len(attack_df)), random_state=42
    )

    # Features only
    X_normal = normal_sample.drop("attack_category", axis=1)
    X_attack  = attack_sample.drop("attack_category", axis=1)
    y_attack  = np.ones(len(X_attack))
    y_normal  = np.zeros(len(X_normal))

    # Scale
    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)
    X_attack_scaled = scaler.transform(X_attack)

    logger.info(f"✅ Features: {X_normal_scaled.shape[1]}")

    return X_normal_scaled, X_attack_scaled, y_normal, y_attack, scaler


def build_cicids_autoencoder(input_dim: int) -> Model:
    """
    Builds a deeper Autoencoder for CICIDS2017.
    More layers because 78 features vs 41 in NSL-KDD.

    Architecture:
    INPUT(78) → 64 → 32 → 16 → BOTTLENECK(8)
              → 16 → 32 → 64 → OUTPUT(78)
    """
    logger.info(f"Building Autoencoder — input dim: {input_dim}")

    inputs = Input(shape=(input_dim,), name="input")

    # ── ENCODER ──────────────────────────
    x = Dense(64, activation="relu",  name="enc_1")(inputs)
    x = BatchNormalization()(x)
    x = Dropout(0.1)(x)
    x = Dense(32, activation="relu",  name="enc_2")(x)
    x = BatchNormalization()(x)
    x = Dense(16, activation="relu",  name="enc_3")(x)
    x = Dense(8,  activation="relu",  name="bottleneck")(x)

    # ── DECODER ──────────────────────────
    x = Dense(16, activation="relu",  name="dec_1")(x)
    x = Dense(32, activation="relu",  name="dec_2")(x)
    x = BatchNormalization()(x)
    x = Dense(64, activation="relu",  name="dec_3")(x)
    outputs = Dense(input_dim, activation="linear", name="output")(x)

    model = Model(inputs, outputs, name="ArgusAutoencoder_CICIDS")
    model.compile(optimizer="adam", loss="mse")
    model.summary()

    return model


def train_autoencoder(model, X_normal):
    """
    Trains autoencoder ONLY on normal traffic.
    """
    logger.info("─" * 50)
    logger.info("Training on normal CICIDS2017 traffic...")
    logger.info("─" * 50)

    callbacks = [
        EarlyStopping(
            monitor="val_loss",
            patience=5,
            restore_best_weights=True,
            verbose=1
        ),
        ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=3,
            verbose=1
        )
    ]

    history = model.fit(
        X_normal, X_normal,
        epochs=50,
        batch_size=512,
        validation_split=0.1,
        callbacks=callbacks,
        verbose=1
    )

    logger.info("✅ Autoencoder training complete!")
    return model, history


def find_threshold(model, X_normal):
    """
    Calculates anomaly threshold from normal traffic.
    """
    logger.info("Finding anomaly threshold...")

    X_reconstructed = model.predict(X_normal, verbose=0)
    mse_errors = np.mean(
        np.power(X_normal - X_reconstructed, 2), axis=1
    )

    threshold = np.percentile(mse_errors, 95)

    logger.info(f"✅ Mean normal error : {np.mean(mse_errors):.6f}")
    logger.info(f"✅ Max normal error  : {np.max(mse_errors):.6f}")
    logger.info(f"✅ Threshold (95th%) : {threshold:.6f}")

    return threshold


def evaluate(model, X_normal, X_attack, y_normal, y_attack, threshold):
    """
    Evaluates autoencoder on both normal and attack traffic.
    """
    logger.info("Evaluating on test data...")

    # Reconstruct both
    X_all   = np.vstack([X_normal[:10000], X_attack[:10000]])
    y_all   = np.hstack([y_normal[:10000], y_attack[:10000]])

    X_recon = model.predict(X_all, verbose=0)
    errors  = np.mean(np.power(X_all - X_recon, 2), axis=1)
    y_pred  = (errors > threshold).astype(int)

    accuracy = (y_pred == y_all).mean()
    logger.info(f"✅ Accuracy: {accuracy * 100:.2f}%")

    try:
        auc = roc_auc_score(y_all, errors)
        logger.info(f"✅ AUC Score: {auc:.4f}")
    except Exception:
        pass

    print("\n📊 CICIDS2017 Autoencoder Report:")
    print("─" * 50)
    print(classification_report(
        y_all, y_pred,
        target_names=["Normal", "Attack"],
        zero_division=0
    ))

    return accuracy


def save_model(model, scaler, threshold):
    """
    Saves CICIDS2017 autoencoder model.
    """
    os.makedirs(MODELS_DIR, exist_ok=True)

    model.save(f"{MODELS_DIR}cicids_autoencoder.keras")
    joblib.dump(scaler,    f"{MODELS_DIR}cicids_ae_scaler.pkl")
    joblib.dump(threshold, f"{MODELS_DIR}cicids_ae_threshold.pkl")

    logger.info(f"✅ Autoencoder → {MODELS_DIR}cicids_autoencoder.keras")
    logger.info(f"✅ Scaler      → {MODELS_DIR}cicids_ae_scaler.pkl")
    logger.info(f"✅ Threshold   → {MODELS_DIR}cicids_ae_threshold.pkl")


# ─────────────────────────────────────────
# Run
# ─────────────────────────────────────────
if __name__ == "__main__":
    logger.info("=" * 55)
    logger.info("  ARGUS — CICIDS2017 Autoencoder Training")
    logger.info("  Zero-Day Anomaly Detection on Modern Data")
    logger.info("=" * 55)

    # 1. Load and prepare
    X_normal, X_attack, y_normal, y_attack, scaler = load_and_prepare(
        CICIDS_DIR
    )

    # 2. Build model
    model = build_cicids_autoencoder(input_dim=X_normal.shape[1])

    # 3. Train
    model, history = train_autoencoder(model, X_normal)

    # 4. Find threshold
    threshold = find_threshold(model, X_normal)

    # 5. Evaluate
    accuracy = evaluate(
        model, X_normal, X_attack,
        y_normal, y_attack, threshold
    )

    # 6. Save
    save_model(model, scaler, threshold)

    logger.info("=" * 55)
    logger.info("  CICIDS2017 Autoencoder Ready!")
    logger.info(f"  Threshold : {threshold:.6f}")
    logger.info("=" * 55)