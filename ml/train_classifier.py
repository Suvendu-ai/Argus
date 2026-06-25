# ml/train_classifier.py
# ─────────────────────────────────────────
# ARGUS — ML Classifier Training
# Trains a Random Forest on NSL-KDD dataset
# ─────────────────────────────────────────

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────
# NSL-KDD has 41 features + label + difficulty
# We define all column names manually
# ─────────────────────────────────────────
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

# ─────────────────────────────────────────
# Group 40+ specific attack names into
# 5 main categories Argus will detect
# ─────────────────────────────────────────
ATTACK_CATEGORIES = {
    # Normal traffic
    "normal"          : "NORMAL",

    # DoS — Denial of Service attacks
    "neptune"         : "DoS",
    "back"            : "DoS",
    "land"            : "DoS",
    "pod"             : "DoS",
    "smurf"           : "DoS",
    "teardrop"        : "DoS",
    "mailbomb"        : "DoS",
    "apache2"         : "DoS",
    "processtable"    : "DoS",
    "udpstorm"        : "DoS",

    # Probe — Port scanning & reconnaissance
    "portsweep"       : "Probe",
    "ipsweep"         : "Probe",
    "nmap"            : "Probe",
    "satan"           : "Probe",
    "mscan"           : "Probe",
    "saint"           : "Probe",

    # R2L — Remote to Local (unauthorized access)
    "ftp_write"       : "R2L",
    "guess_passwd"    : "R2L",
    "imap"            : "R2L",
    "multihop"        : "R2L",
    "phf"             : "R2L",
    "spy"             : "R2L",
    "warezclient"     : "R2L",
    "warezmaster"     : "R2L",

    # U2R — User to Root (privilege escalation)
    "buffer_overflow" : "U2R",
    "loadmodule"      : "U2R",
    "perl"            : "U2R",
    "rootkit"         : "U2R",
    "httptunnel"      : "U2R",
    "ps"              : "U2R",
    "sqlattack"       : "U2R",
    "xterm"           : "U2R",
}


def load_data(train_path, test_path):
    """
    Loads the NSL-KDD dataset from CSV files.
    """
    logger.info("Loading NSL-KDD dataset...")

    train_df = pd.read_csv(train_path, header=None, names=COLUMNS)
    test_df  = pd.read_csv(test_path,  header=None, names=COLUMNS)

    logger.info(f"✅ Train: {len(train_df):,} rows")
    logger.info(f"✅ Test : {len(test_df):,} rows")

    # Show attack distribution
    logger.info("\n Attack distribution in training data:")
    counts = train_df["label"].value_counts().head(10)
    for label, count in counts.items():
        logger.info(f"   {label:<20} → {count:,}")

    return train_df, test_df


def preprocess(df, label_encoders=None, is_train=True):
    """
    Cleans and encodes the dataset so ML model can read it.
    Converts text columns to numbers.
    """
    logger.info("Preprocessing data...")

    df = df.copy()

    # Remove difficulty column (not useful for training)
    df.drop("difficulty", axis=1, inplace=True)

    # Map specific attacks → attack categories
    df["attack_category"] = df["label"].map(
        lambda x: ATTACK_CATEGORIES.get(x.strip(), "Unknown")
    )
    df.drop("label", axis=1, inplace=True)

    # Encode text columns (protocol_type, service, flag)
    # e.g. "tcp" → 2, "udp" → 3, "icmp" → 1
    cat_cols = ["protocol_type", "service", "flag"]

    if is_train:
        label_encoders = {}
        for col in cat_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le  # Save encoder for later use
    else:
        for col in cat_cols:
            le = label_encoders[col]
            # Handle unseen labels gracefully
            df[col] = df[col].map(
                lambda x: le.transform([x])[0]
                if x in le.classes_ else -1
            )

    # Encode target label
    target_le = LabelEncoder()
    df["attack_category"] = target_le.fit_transform(df["attack_category"])

    # Split into features (X) and target (y)
    X = df.drop("attack_category", axis=1)
    y = df["attack_category"]

    logger.info(f"✅ Features shape: {X.shape}")
    logger.info(f"✅ Classes: {list(target_le.classes_)}")

    return X, y, label_encoders, target_le


def train_model(X_train, y_train):
    """
    Trains the Random Forest classifier.
    Random Forest = many decision trees working together.
    Like asking 100 experts and taking a majority vote.
    """
    logger.info("─" * 50)
    logger.info("Training Random Forest Classifier...")
    logger.info("Using 100 trees | All CPU cores | Please wait...")
    logger.info("─" * 50)

    model = RandomForestClassifier(
        n_estimators=100,   # 100 decision trees
        max_depth=20,       # Max depth per tree
        random_state=42,    # For reproducibility
        n_jobs=-1,          # Use all CPU cores → faster
        verbose=0
    )

    model.fit(X_train, y_train)
    logger.info("✅ Training complete!")

    return model


def evaluate_model(model, X_test, y_test, target_le):
    """
    Tests the model on unseen data and prints results.
    """
    logger.info("Evaluating model on test data...")

    y_pred    = model.predict(X_test)
    accuracy  = accuracy_score(y_test, y_pred)

    logger.info(f"✅ Accuracy: {accuracy * 100:.2f}%")

    print("\n📊 Detailed Classification Report:")
    print("─" * 60)

    # Dynamically get actual classes from predictions
    unique_labels = sorted(set(list(y_test) + list(y_pred)))
    try:
        names = target_le.inverse_transform(unique_labels)
    except:
        names = [str(l) for l in unique_labels]

    print(classification_report(
        y_test, y_pred,
        labels=unique_labels,
        target_names=names,
        zero_division=0
    ))

    # Show top 10 most important features
    feature_names   = X_test.columns.tolist()
    importances     = model.feature_importances_
    top_features    = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    print("\n🔍 Top 10 Most Important Features:")
    print("─" * 40)
    for feat, score in top_features:
        bar = "█" * int(score * 100)
        print(f"  {feat:<30} {bar} {score:.4f}")

    return accuracy


def save_model(model, label_encoders, target_le):
    """
    Saves trained model and encoders to disk.
    These will be loaded later by the classifier module.
    """
    save_dir = "ml/models/"
    os.makedirs(save_dir, exist_ok=True)

    joblib.dump(model,          f"{save_dir}argus_classifier.pkl")
    joblib.dump(label_encoders, f"{save_dir}label_encoders.pkl")
    joblib.dump(target_le,      f"{save_dir}target_encoder.pkl")

    logger.info(f"✅ Model saved       → {save_dir}argus_classifier.pkl")
    logger.info(f"✅ Encoders saved    → {save_dir}label_encoders.pkl")
    logger.info(f"✅ Target enc saved  → {save_dir}target_encoder.pkl")


# ─────────────────────────────────────────
# Run directly to train
# ─────────────────────────────────────────
if __name__ == "__main__":

    TRAIN_PATH = "data/raw/KDDTrain+.txt"
    TEST_PATH  = "data/raw/KDDTest+.txt"

    # 1. Load dataset
    train_df, test_df = load_data(TRAIN_PATH, TEST_PATH)

    # 2. Preprocess
    X_train, y_train, label_encoders, target_le = preprocess(train_df, is_train=True)
    X_test,  y_test,  _,              _          = preprocess(test_df,  label_encoders, is_train=False)

    # 3. Train
    model = train_model(X_train, y_train)

    # 4. Evaluate
    accuracy = evaluate_model(model, X_test, y_test, target_le)

    # 5. Save
    save_model(model, label_encoders, target_le)

    logger.info("=" * 50)
    logger.info(f"  ARGUS Classifier Ready!")
    logger.info(f"  Final Accuracy: {accuracy * 100:.2f}%")
    logger.info("=" * 50)   