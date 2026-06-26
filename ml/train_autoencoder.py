# ml/train_autoencoder.py
# ─────────────────────────────────────────
# ARGUS — Autoencoder Anomaly Detector
# Detects UNKNOWN attacks never seen before
# ─────────────────────────────────────────

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, roc_auc_score
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
import joblib
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# Same columns as before
COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]


def load_and_preprocess(train_path, test_path):
    """
    Loads data and prepares it for the Autoencoder.
    Key difference from Random Forest:
    We train ONLY on normal traffic.
    The model learns what normal looks like.
    Anything different = anomaly = attack.
    """
    logger.info("Loading dataset...")
    train_df = pd.read_csv(train_path, header=None, names=COLUMNS)
    test_df  = pd.read_csv(test_path,  header=None, names=COLUMNS)

    # Encode categorical columns
    cat_cols = ["protocol_type", "service", "flag"]
    for col in cat_cols:
        le = LabelEncoder()
        train_df[col] = le.fit_transform(train_df[col].astype(str))
        test_df[col]  = test_df[col].map(
            lambda x: le.transform([x])[0]
            if x in le.classes_ else 0
        )

    # Create binary label: 0 = normal, 1 = attack
    train_df["is_attack"] = (train_df["label"] != "normal").astype(int)
    test_df["is_attack"]  = (test_df["label"]  != "normal").astype(int)

    # Drop non-feature columns
    drop_cols = ["label", "difficulty"]
    train_df.drop(drop_cols, axis=1, inplace=True)
    test_df.drop(drop_cols,  axis=1, inplace=True)

    # Separate features and labels
    X_train_full = train_df.drop("is_attack", axis=1)
    y_train      = train_df["is_attack"]
    X_test       = test_df.drop("is_attack",  axis=1)
    y_test       = test_df["is_attack"]

    # ─────────────────────────────────────
    # CRITICAL STEP:
    # Train autoencoder ONLY on normal traffic
    # It learns what "normal" looks like
    # ─────────────────────────────────────
    X_train_normal = X_train_full[y_train == 0]
    logger.info(f"✅ Normal training samples : {len(X_train_normal):,}")
    logger.info(f"✅ Test samples            : {len(X_test):,}")
    logger.info(f"✅ Attack ratio in test    : {y_test.mean()*100:.1f}%")

    # Scale features to range [0,1]
    # Neural networks work much better with scaled data
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_normal)
    X_test_scaled  = scaler.transform(X_test)

    return X_train_scaled, X_test_scaled, y_test, scaler


def build_autoencoder(input_dim):
    """
    Builds the Autoencoder neural network.

    How it works:
    ┌─────────────────────────────────────┐
    │  INPUT (41 features)                │
    │       ↓ Encoder                     │
    │  Compress to 8 numbers              │  ← bottleneck
    │       ↓ Decoder                     │
    │  Reconstruct back to 41 features    │
    │       ↓                             │
    │  Compare original vs reconstructed  │
    │  Big difference = ANOMALY DETECTED  │
    └─────────────────────────────────────┘

    Trained only on normal traffic →
    Normal traffic reconstructs well (low error)
    Attack traffic reconstructs badly (high error)
    """
    logger.info("Building Autoencoder architecture...")

    inputs = Input(shape=(input_dim,), name="input")

    # ── ENCODER ──────────────────────────
    x = Dense(32, activation="relu",  name="enc_1")(inputs)
    x = Dropout(0.1)(x)
    x = Dense(16, activation="relu",  name="enc_2")(x)
    x = Dense(8,  activation="relu",  name="bottleneck")(x)

    # ── DECODER ──────────────────────────
    x = Dense(16, activation="relu",  name="dec_1")(x)
    x = Dense(32, activation="relu",  name="dec_2")(x)
    outputs = Dense(input_dim, activation="linear", name="output")(x)

    model = Model(inputs, outputs, name="ArgusAutoencoder")

    model.compile(
        optimizer="adam",
        loss="mse"          # Mean Squared Error — measures reconstruction quality
    )

    model.summary()
    return model


def train_autoencoder(model, X_train):
    """
    Trains the autoencoder on normal traffic only.
    """
    logger.info("─" * 50)
    logger.info("Training Autoencoder on normal traffic...")
    logger.info("─" * 50)

    # Stop training early if no improvement
    early_stop = EarlyStopping(
        monitor="val_loss",
        patience=5,           # Stop if no improvement for 5 epochs
        restore_best_weights=True
    )

    history = model.fit(
        X_train, X_train,     # Input = Output (reconstruction task)
        epochs=50,
        batch_size=256,
        validation_split=0.1, # 10% for validation
        callbacks=[early_stop],
        verbose=1
    )

    logger.info("✅ Autoencoder training complete!")
    return model, history


def find_threshold(model, X_train):
    """
    Finds the reconstruction error threshold.

    Logic:
    - Calculate reconstruction error for all NORMAL traffic
    - Set threshold at 95th percentile
    - Any error ABOVE threshold = anomaly = attack
    """
    logger.info("Finding anomaly threshold...")

    # Reconstruct normal training data
    X_reconstructed = model.predict(X_train, verbose=0)

    # Calculate reconstruction error per sample
    mse_errors = np.mean(np.power(X_train - X_reconstructed, 2), axis=1)

    # Set threshold at 95th percentile of normal errors
    threshold = np.percentile(mse_errors, 95)

    logger.info(f"✅ Mean normal error    : {np.mean(mse_errors):.6f}")
    logger.info(f"✅ Max normal error     : {np.max(mse_errors):.6f}")
    logger.info(f"✅ Anomaly threshold    : {threshold:.6f}")
    logger.info("   (errors above this = attack detected)")

    return threshold


def evaluate_autoencoder(model, X_test, y_test, threshold):
    """
    Tests the autoencoder on real test data.
    """
    logger.info("Evaluating on test data...")

    # Reconstruct test data
    X_reconstructed = model.predict(X_test, verbose=0)

    # Calculate reconstruction error
    mse_errors = np.mean(np.power(X_test - X_reconstructed, 2), axis=1)

    # Classify: error > threshold = attack (1), else normal (0)
    y_pred = (mse_errors > threshold).astype(int)

    # Results
    print("\n📊 Autoencoder Detection Report:")
    print("─" * 50)
    print(classification_report(
        y_test, y_pred,
        target_names=["Normal", "Attack"],
        zero_division=0
    ))

    # AUC score (higher = better, 1.0 = perfect)
    try:
        auc = roc_auc_score(y_test, mse_errors)
        logger.info(f"✅ AUC Score: {auc:.4f} (higher = better)")
    except:
        pass

    # Accuracy
    accuracy = (y_pred == y_test).mean()
    logger.info(f"✅ Accuracy: {accuracy * 100:.2f}%")

    return accuracy, threshold


def save_autoencoder(model, scaler, threshold):
    """
    Saves the autoencoder model, scaler and threshold.
    """
    save_dir = "ml/models/"
    os.makedirs(save_dir, exist_ok=True)

    model.save(f"{save_dir}argus_autoencoder.keras")
    joblib.dump(scaler,    f"{save_dir}autoencoder_scaler.pkl")
    joblib.dump(threshold, f"{save_dir}anomaly_threshold.pkl")

    logger.info(f"✅ Autoencoder saved  → {save_dir}argus_autoencoder.keras")
    logger.info(f"✅ Scaler saved       → {save_dir}autoencoder_scaler.pkl")
    logger.info(f"✅ Threshold saved    → {save_dir}anomaly_threshold.pkl")


# ─────────────────────────────────────────
# Run directly to train
# ─────────────────────────────────────────
if __name__ == "__main__":

    TRAIN_PATH = "data/raw/KDDTrain+.txt"
    TEST_PATH  = "data/raw/KDDTest+.txt"

    # 1. Load and preprocess
    X_train, X_test, y_test, scaler = load_and_preprocess(
        TRAIN_PATH, TEST_PATH
    )

    # 2. Build model
    model = build_autoencoder(input_dim=X_train.shape[1])

    # 3. Train
    model, history = train_autoencoder(model, X_train)

    # 4. Find threshold
    threshold = find_threshold(model, X_train)

    # 5. Evaluate
    accuracy, threshold = evaluate_autoencoder(
        model, X_test, y_test, threshold
    )

    # 6. Save
    save_autoencoder(model, scaler, threshold)

    logger.info("=" * 50)
    logger.info("  ARGUS Autoencoder Ready!")
    logger.info(f"  Anomaly Threshold : {threshold:.6f}")
    logger.info("=" * 50)