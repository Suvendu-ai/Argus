# core/classifier.py
# ─────────────────────────────────────────
# ARGUS — Real-time Threat Classifier
# Bridges ML models with live traffic
# Loads both Random Forest + Autoencoder
# and runs predictions on live flows
# ─────────────────────────────────────────

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────
# Model paths
# ─────────────────────────────────────────
MODEL_DIR         = "ml/models/"
RF_MODEL_PATH     = f"{MODEL_DIR}argus_classifier.pkl"
RF_ENCODERS_PATH  = f"{MODEL_DIR}label_encoders.pkl"
RF_TARGET_PATH    = f"{MODEL_DIR}target_encoder.pkl"
AE_MODEL_PATH     = f"{MODEL_DIR}argus_autoencoder.keras"
AE_SCALER_PATH    = f"{MODEL_DIR}autoencoder_scaler.pkl"
AE_THRESHOLD_PATH = f"{MODEL_DIR}anomaly_threshold.pkl"

# ─────────────────────────────────────────
# NSL-KDD feature columns the model expects
# ─────────────────────────────────────────
FEATURE_COLUMNS = [
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
    "dst_host_srv_rerror_rate"
]


class ArgusClassifier:
    """
    Main classifier that combines:
    - Random Forest  → identifies KNOWN attack types
    - Autoencoder    → detects UNKNOWN anomalies

    Both models vote on every flow.
    If either flags it — Argus raises an alert.
    """

    def __init__(self):
        self.rf_model      = None
        self.rf_encoders   = None
        self.rf_target     = None
        self.ae_model      = None
        self.ae_scaler     = None
        self.ae_threshold  = None
        self.is_loaded     = False

    def load_models(self):
        """
        Loads all trained models from disk.
        Must be called before any predictions.
        """
        logger.info("Loading ARGUS models...")

        try:
            # ── Random Forest ──────────────────────
            if not os.path.exists(RF_MODEL_PATH):
                logger.error(f"Model not found: {RF_MODEL_PATH}")
                logger.error("Run: python ml/train_classifier.py first!")
                return False

            self.rf_model    = joblib.load(RF_MODEL_PATH)
            self.rf_encoders = joblib.load(RF_ENCODERS_PATH)
            self.rf_target   = joblib.load(RF_TARGET_PATH)
            logger.info("✅ Random Forest loaded")

            # ── Autoencoder ────────────────────────
            if not os.path.exists(AE_MODEL_PATH):
                logger.error(f"Model not found: {AE_MODEL_PATH}")
                logger.error("Run: python ml/train_autoencoder.py first!")
                return False

            self.ae_model     = tf.keras.models.load_model(AE_MODEL_PATH)
            self.ae_scaler    = joblib.load(AE_SCALER_PATH)
            self.ae_threshold = joblib.load(AE_THRESHOLD_PATH)
            logger.info("✅ Autoencoder loaded")
            logger.info(f"   Anomaly threshold: {self.ae_threshold:.6f}")

            self.is_loaded = True
            logger.info("✅ All models ready — ARGUS is watching!")
            return True

        except Exception as e:
            logger.error(f"Error loading models: {e}")
            return False

    def flow_to_features(self, flow: dict) -> pd.DataFrame:
        """
        Converts a live network flow (from extractor.py)
        into the feature format the ML models expect.

        Maps live flow features → NSL-KDD style features.
        Missing features are filled with 0 (safe default).
        """
        # Start with all zeros
        features = {col: 0 for col in FEATURE_COLUMNS}

        # Map what we have from live capture
        protocol_map = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp"}
        proto        = flow.get("protocol", "TCP")
        features["protocol_type"] = protocol_map.get(proto, "tcp")

        features["src_bytes"]   = flow.get("total_bytes",     0)
        features["dst_bytes"]   = flow.get("total_bytes",     0) // 2
        features["duration"]    = int(flow.get("flow_duration", 0))
        features["count"]       = flow.get("packet_count",    0)
        features["srv_count"]   = flow.get("packet_count",    0)
        features["wrong_fragment"] = 0
        features["urgent"]      = 0
        features["flag"]        = "SF"  # Normal flag
        features["service"]     = "http"

        # TCP flag features
        features["serror_rate"]     = 1.0 if flow.get("syn_count", 0) > 10 else 0.0
        features["srv_serror_rate"] = features["serror_rate"]
        features["rerror_rate"]     = 1.0 if flow.get("rst_count", 0) > 5  else 0.0

        # Derived rate features
        pps = flow.get("packets_per_sec", 0)
        features["same_srv_rate"]      = min(1.0, pps / 100)
        features["diff_srv_rate"]      = 1.0 - features["same_srv_rate"]
        features["dst_host_count"]     = min(255, flow.get("packet_count", 0))
        features["dst_host_srv_count"] = features["dst_host_count"]

        df = pd.DataFrame([features])

        # Encode categorical columns
        cat_cols = ["protocol_type", "service", "flag"]
        for col in cat_cols:
            le = self.rf_encoders.get(col)
            if le:
                val = df[col].iloc[0]
                if val in le.classes_:
                    df[col] = le.transform([val])[0]
                else:
                    df[col] = 0

        return df

    def predict_rf(self, features_df: pd.DataFrame) -> dict:
        """
        Random Forest prediction — identifies attack TYPE.
        Returns attack category and confidence score.
        """
        try:
            prediction   = self.rf_model.predict(features_df)[0]
            probabilities = self.rf_model.predict_proba(features_df)[0]
            confidence   = float(np.max(probabilities))
            attack_type  = self.rf_target.inverse_transform([prediction])[0]

            return {
                "attack_type" : attack_type,
                "confidence"  : round(confidence * 100, 2),
                "model"       : "RandomForest"
            }
        except Exception as e:
            logger.error(f"RF prediction error: {e}")
            return {"attack_type": "Unknown", "confidence": 0, "model": "RandomForest"}

    def predict_autoencoder(self, features_df: pd.DataFrame) -> dict:
        """
        Autoencoder prediction — detects ANOMALIES.
        High reconstruction error = something unusual = potential attack.
        """
        try:
            # Scale features
            X_scaled = self.ae_scaler.transform(features_df)

            # Reconstruct
            X_reconstructed = self.ae_model.predict(X_scaled, verbose=0)

            # Calculate reconstruction error
            mse_error = float(np.mean(np.power(X_scaled - X_reconstructed, 2)))

            # Is it an anomaly?
            is_anomaly = mse_error > self.ae_threshold

            return {
                "is_anomaly"  : is_anomaly,
                "error"       : round(mse_error, 6),
                "threshold"   : round(self.ae_threshold, 6),
                "model"       : "Autoencoder"
            }
        except Exception as e:
            logger.error(f"Autoencoder prediction error: {e}")
            return {"is_anomaly": False, "error": 0, "threshold": 0, "model": "Autoencoder"}

    def classify_flow(self, flow: dict) -> dict:
        """
        Master function — classifies a single live flow.
        Combines both model results into one final verdict.

        Returns a threat dict ready for the LLM explainer.
        """
        if not self.is_loaded:
            logger.error("Models not loaded! Call load_models() first.")
            return None

        # Convert flow to features
        features_df = self.flow_to_features(flow)

        # Get predictions from both models
        rf_result  = self.predict_rf(features_df)
        ae_result  = self.predict_autoencoder(features_df)

        # ── Final Verdict Logic ────────────────
        # If RF says it's an attack → trust it
        # If Autoencoder says anomaly → flag it
        # If both say normal → it's normal
        attack_type = rf_result["attack_type"]
        is_threat   = False

        if attack_type != "NORMAL":
            is_threat = True
        elif ae_result["is_anomaly"]:
            is_threat   = True
            attack_type = "Unknown"  # Anomaly not in known categories

        # Build result
        result = {
            # Flow info
            "src_ip"          : flow.get("src_ip",          "Unknown"),
            "dst_ip"          : flow.get("dst_ip",          "Unknown"),
            "protocol"        : flow.get("protocol",        "Unknown"),
            "packet_count"    : flow.get("packet_count",    0),
            "total_bytes"     : flow.get("total_bytes",     0),
            "packets_per_sec" : flow.get("packets_per_sec", 0),
            "flow_duration"   : flow.get("flow_duration",   0),

            # Verdict
            "attack_type"     : attack_type,
            "is_threat"       : is_threat,
            "rf_confidence"   : rf_result["confidence"],
            "ae_error"        : ae_result["error"],
            "ae_is_anomaly"   : ae_result["is_anomaly"],
        }

        # Log result
        if is_threat:
            logger.warning(
                f"🚨 THREAT DETECTED | {attack_type} | "
                f"{flow.get('src_ip')} → {flow.get('dst_ip')} | "
                f"RF: {rf_result['confidence']}% | "
                f"AE Error: {ae_result['error']:.4f}"
            )
        else:
            logger.info(
                f"✅ Normal traffic  | "
                f"{flow.get('src_ip')} → {flow.get('dst_ip')} | "
                f"RF: {rf_result['confidence']}%"
            )

        return result


# ─────────────────────────────────────────
# Run directly to test
# ─────────────────────────────────────────
if __name__ == "__main__":

    classifier = ArgusClassifier()

    # Load models
    if not classifier.load_models():
        exit(1)

    # Simulate test flows
    test_flows = [
        {
            "src_ip"          : "192.168.1.100",
            "dst_ip"          : "10.203.189.103",
            "protocol"        : "TCP",
            "packet_count"    : 850,
            "total_bytes"     : 425000,
            "packets_per_sec" : 48.5,
            "flow_duration"   : 17.5,
            "syn_count"       : 800,
            "rst_count"       : 5,
        },
        {
            "src_ip"          : "10.203.189.103",
            "dst_ip"          : "142.251.220.14",
            "protocol"        : "TCP",
            "packet_count"    : 12,
            "total_bytes"     : 5400,
            "packets_per_sec" : 3.2,
            "flow_duration"   : 3.7,
            "syn_count"       : 1,
            "rst_count"       : 0,
        },
        {
            "src_ip"          : "203.0.113.45",
            "dst_ip"          : "10.203.189.103",
            "protocol"        : "TCP",
            "packet_count"    : 120,
            "total_bytes"     : 6000,
            "packets_per_sec" : 22.3,
            "flow_duration"   : 5.3,
            "syn_count"       : 90,
            "rst_count"       : 30,
        },
    ]

    print("\n" + "═" * 60)
    print("  ARGUS — Live Classification Test")
    print("═" * 60)

    threats_found = []
    for i, flow in enumerate(test_flows, 1):
        print(f"\n[Flow #{i}] {flow['src_ip']} → {flow['dst_ip']}")
        print("─" * 40)
        result = classifier.classify_flow(flow)

        print(f"  Attack Type   : {result['attack_type']}")
        print(f"  Is Threat     : {'🚨 YES' if result['is_threat'] else '✅ NO'}")
        print(f"  RF Confidence : {result['rf_confidence']}%")
        print(f"  AE Error      : {result['ae_error']}")
        print(f"  AE Anomaly    : {result['ae_is_anomaly']}")

        if result["is_threat"]:
            threats_found.append(result)

    print(f"\n{'═' * 60}")
    print(f"  Total flows   : {len(test_flows)}")
    print(f"  Threats found : {len(threats_found)}")
    print(f"{'═' * 60}\n")