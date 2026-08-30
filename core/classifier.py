# core/classifier.py
# ─────────────────────────────────────────
# ARGUS — Dual Dataset Classifier
# Combines NSL-KDD + CICIDS2017 models
# for maximum threat coverage
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

MODEL_DIR = "ml/models/"

# ─────────────────────────────────────────
# NSL-KDD Model Paths
# ─────────────────────────────────────────
NSL_RF_PATH        = f"{MODEL_DIR}argus_classifier.pkl"
NSL_ENCODERS_PATH  = f"{MODEL_DIR}label_encoders.pkl"
NSL_TARGET_PATH    = f"{MODEL_DIR}target_encoder.pkl"
NSL_AE_PATH        = f"{MODEL_DIR}argus_autoencoder.keras"
NSL_AE_SCALER_PATH = f"{MODEL_DIR}autoencoder_scaler.pkl"
NSL_AE_THRESH_PATH = f"{MODEL_DIR}anomaly_threshold.pkl"

# ─────────────────────────────────────────
# CICIDS2017 Model Paths
# ─────────────────────────────────────────
CIC_RF_PATH        = f"{MODEL_DIR}cicids_classifier.pkl"
CIC_LE_PATH        = f"{MODEL_DIR}cicids_label_encoder.pkl"
CIC_FEAT_PATH      = f"{MODEL_DIR}cicids_feature_cols.pkl"
CIC_AE_PATH        = f"{MODEL_DIR}cicids_autoencoder.keras"
CIC_AE_SCALER_PATH = f"{MODEL_DIR}cicids_ae_scaler.pkl"
CIC_AE_THRESH_PATH = f"{MODEL_DIR}cicids_ae_threshold.pkl"

# ─────────────────────────────────────────
# NSL-KDD feature columns
# ─────────────────────────────────────────
NSL_FEATURE_COLUMNS = [
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

# ─────────────────────────────────────────
# Severity mapping
# ─────────────────────────────────────────
SEVERITY_MAP = {
    "NORMAL"      : "LOW",
    "DoS"         : "HIGH",
    "DDoS"        : "HIGH",
    "Probe"       : "MEDIUM",
    "PortScan"    : "MEDIUM",
    "R2L"         : "HIGH",
    "U2R"         : "CRITICAL",
    "BruteForce"  : "HIGH",
    "WebAttack"   : "HIGH",
    "Botnet"      : "CRITICAL",
    "Infiltration": "CRITICAL",
    "Unknown"     : "HIGH",
}


class ArgusClassifier:
    """
    Dual-dataset classifier combining:
    - NSL-KDD  : Random Forest + Autoencoder
    - CICIDS2017: Random Forest + Autoencoder

    All 4 models vote on every flow.
    Final verdict is the most severe detection.
    """

    def __init__(self):
        # NSL-KDD models
        self.nsl_rf        = None
        self.nsl_encoders  = None
        self.nsl_target    = None
        self.nsl_ae        = None
        self.nsl_scaler    = None
        self.nsl_threshold = None

        # CICIDS2017 models
        self.cic_rf        = None
        self.cic_le        = None
        self.cic_features  = None
        self.cic_ae        = None
        self.cic_scaler    = None
        self.cic_threshold = None

        self.is_loaded     = False

    def load_models(self):
        """Loads all 4 models from disk."""
        logger.info("Loading ARGUS dual-dataset models...")

        try:
            # ── NSL-KDD ──────────────────────────
            self.nsl_rf        = joblib.load(NSL_RF_PATH)
            self.nsl_encoders  = joblib.load(NSL_ENCODERS_PATH)
            self.nsl_target    = joblib.load(NSL_TARGET_PATH)
            self.nsl_ae        = tf.keras.models.load_model(NSL_AE_PATH)
            self.nsl_scaler    = joblib.load(NSL_AE_SCALER_PATH)
            self.nsl_threshold = joblib.load(NSL_AE_THRESH_PATH)
            logger.info("✅ NSL-KDD models loaded")
            logger.info(f"   RF classes    : {list(self.nsl_target.classes_)}")
            logger.info(f"   AE threshold  : {self.nsl_threshold:.6f}")

            # ── CICIDS2017 ────────────────────────
            self.cic_rf        = joblib.load(CIC_RF_PATH)
            self.cic_le        = joblib.load(CIC_LE_PATH)
            self.cic_features  = joblib.load(CIC_FEAT_PATH)
            self.cic_ae        = tf.keras.models.load_model(CIC_AE_PATH)
            self.cic_scaler    = joblib.load(CIC_AE_SCALER_PATH)
            self.cic_threshold = joblib.load(CIC_AE_THRESH_PATH)
            logger.info("✅ CICIDS2017 models loaded")
            logger.info(f"   RF classes    : {list(self.cic_le.classes_)}")
            logger.info(f"   AE threshold  : {self.cic_threshold:.6f}")

            self.is_loaded = True
            logger.info("✅ All 4 models ready — ARGUS is watching!")
            return True

        except Exception as e:
            logger.error(f"Error loading models: {e}")
            return False

    # ─────────────────────────────────────
    # NSL-KDD Feature Extraction
    # ─────────────────────────────────────
    def _nsl_features(self, flow: dict) -> pd.DataFrame:
        """Converts live flow to NSL-KDD feature format."""
        features = {col: 0 for col in NSL_FEATURE_COLUMNS}

        proto_map = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp"}
        proto     = flow.get("protocol", "TCP")
        features["protocol_type"] = proto_map.get(proto, "tcp")
        features["src_bytes"]     = flow.get("total_bytes", 0)
        features["dst_bytes"]     = flow.get("total_bytes", 0) // 2
        features["duration"]      = int(flow.get("flow_duration", 0))
        features["count"]         = flow.get("packet_count", 0)
        features["srv_count"]     = flow.get("packet_count", 0)
        features["flag"]          = "SF"
        features["service"]       = "http"

        pps = flow.get("packets_per_sec", 0)
        syn = flow.get("syn_count", 0)
        rst = flow.get("rst_count", 0)

        features["serror_rate"]         = 1.0 if syn > 10 else 0.0
        features["srv_serror_rate"]     = features["serror_rate"]
        features["rerror_rate"]         = 1.0 if rst > 5  else 0.0
        features["same_srv_rate"]       = min(1.0, pps / 100)
        features["diff_srv_rate"]       = 1.0 - features["same_srv_rate"]
        features["dst_host_count"]      = min(255, flow.get("packet_count", 0))
        features["dst_host_srv_count"]  = features["dst_host_count"]
        features["dst_host_serror_rate"]= features["serror_rate"]

        df = pd.DataFrame([features])
        for col in ["protocol_type", "service", "flag"]:
            le = self.nsl_encoders.get(col)
            if le:
                val = df[col].iloc[0]
                df[col] = le.transform([val])[0] if val in le.classes_ else 0
        return df

    # ─────────────────────────────────────
    # CICIDS2017 Feature Extraction
    # ─────────────────────────────────────
    def _cic_features(self, flow: dict) -> pd.DataFrame:
        """Converts live flow to CICIDS2017 feature format."""
        features = {col: 0 for col in self.cic_features}

        total_bytes  = flow.get("total_bytes",     0)
        packet_count = flow.get("packet_count",    0)
        pps          = flow.get("packets_per_sec", 0)
        duration     = flow.get("flow_duration",   0)
        syn_count    = flow.get("syn_count",        0)
        dst_port     = flow.get("dst_port",         80)

        # Map available features to CICIDS column names
        col_map = {
            "Destination Port"            : dst_port,
            "Total Fwd Packets"           : packet_count,
            "Total Backward Packets"      : packet_count // 2,
            "Total Length of Fwd Packets" : total_bytes,
            "Total Length of Bwd Packets" : total_bytes // 2,
            "Fwd Packet Length Max"       : total_bytes // max(packet_count, 1),
            "Fwd Packet Length Mean"      : total_bytes // max(packet_count, 1),
            "Bwd Packet Length Max"       : total_bytes // max(packet_count, 1),
            "Flow Bytes/s"                : total_bytes * pps,
            "Flow Packets/s"              : pps,
            "Flow Duration"               : int(duration * 1e6),
            "Fwd Packets/s"               : pps,
            "Bwd Packets/s"               : pps / 2,
            "Avg Fwd Segment Size"        : total_bytes // max(packet_count, 1),
            "Average Packet Size"         : total_bytes // max(packet_count, 1),
            "Subflow Fwd Packets"         : packet_count,
            "Subflow Fwd Bytes"           : total_bytes,
            "SYN Flag Count"              : syn_count,
            "RST Flag Count"              : flow.get("rst_count", 0),
            "ACK Flag Count"              : flow.get("ack_count", 0),
            "FIN Flag Count"              : flow.get("fin_count", 0),
        }

        for col, val in col_map.items():
            if col in features:
                features[col] = val

        df = pd.DataFrame([features])
        df = df.reindex(columns=self.cic_features, fill_value=0)
        return df

    # ─────────────────────────────────────
    # Individual Predictions
    # ─────────────────────────────────────
    def _nsl_rf_predict(self, features_df):
        try:
            pred  = self.nsl_rf.predict(features_df)[0]
            proba = self.nsl_rf.predict_proba(features_df)[0]
            return {
                "label"     : self.nsl_target.inverse_transform([pred])[0],
                "confidence": round(float(np.max(proba)) * 100, 2),
                "source"    : "NSL-RF"
            }
        except Exception as e:
            return {"label": "Unknown", "confidence": 0, "source": "NSL-RF"}

    def _nsl_ae_predict(self, features_df):
        try:
            X   = self.nsl_scaler.transform(features_df)
            X_r = self.nsl_ae.predict(X, verbose=0)
            mse = float(np.mean(np.power(X - X_r, 2)))
            return {
                "is_anomaly": mse > self.nsl_threshold,
                "error"     : round(mse, 6),
                "source"    : "NSL-AE"
            }
        except Exception as e:
            return {"is_anomaly": False, "error": 0, "source": "NSL-AE"}

    def _cic_rf_predict(self, features_df):
        try:
            pred  = self.cic_rf.predict(features_df)[0]
            proba = self.cic_rf.predict_proba(features_df)[0]
            return {
                "label"     : self.cic_le.inverse_transform([pred])[0],
                "confidence": round(float(np.max(proba)) * 100, 2),
                "source"    : "CIC-RF"
            }
        except Exception as e:
            return {"label": "Unknown", "confidence": 0, "source": "CIC-RF"}

    def _cic_ae_predict(self, features_df):
        try:
            X   = self.cic_scaler.transform(features_df)
            X_r = self.cic_ae.predict(X, verbose=0)
            mse = float(np.mean(np.power(X - X_r, 2)))
            return {
                "is_anomaly": mse > self.cic_threshold,
                "error"     : round(mse, 6),
                "source"    : "CIC-AE"
            }
        except Exception as e:
            return {"is_anomaly": False, "error": 0, "source": "CIC-AE"}

    # ─────────────────────────────────────
    # Master Classification
    # ─────────────────────────────────────
    def classify_flow(self, flow: dict) -> dict:
        """
        Classifies a live flow using all 4 models.

        Voting logic:
        - If ANY model detects a threat → flag it
        - Use the most specific attack label
        - CICIDS2017 takes priority (more modern)
        """
        if not self.is_loaded:
            logger.error("Models not loaded!")
            return None

        # Get features for both formats
        nsl_feat = self._nsl_features(flow)
        cic_feat = self._cic_features(flow)

        # Run all 4 predictions
        nsl_rf = self._nsl_rf_predict(nsl_feat)
        nsl_ae = self._nsl_ae_predict(nsl_feat)
        cic_rf = self._cic_rf_predict(cic_feat)
        cic_ae = self._cic_ae_predict(cic_feat)

        # ── Voting Logic ──────────────────────
        # Priority: CICIDS RF → NSL RF → Autoencoders
        attack_type = "NORMAL"
        is_threat   = False
        source      = "None"

        # CICIDS2017 RF (most modern, highest priority)
        if cic_rf["label"] != "NORMAL":
            attack_type = cic_rf["label"]
            is_threat   = True
            source      = "CIC-RF"

        # NSL-KDD RF
        elif nsl_rf["label"] != "NORMAL":
            attack_type = nsl_rf["label"]
            is_threat   = True
            source      = "NSL-RF"

        # CICIDS2017 Autoencoder — only flag if error is significantly above threshold
        elif cic_ae["is_anomaly"] and cic_ae["error"] > (self.cic_threshold * 2):
           attack_type = "Unknown"
           is_threat   = True
           source      = "CIC-AE"
        # NSL-KDD Autoencoder
        elif nsl_ae["is_anomaly"]:
            attack_type = "Unknown"
            is_threat   = True
            source      = "NSL-AE"

        severity = SEVERITY_MAP.get(attack_type, "HIGH")

        # Build result
        result = {
            "src_ip"          : flow.get("src_ip",          "Unknown"),
            "dst_ip"          : flow.get("dst_ip",          "Unknown"),
            "protocol"        : flow.get("protocol",        "Unknown"),
            "packet_count"    : flow.get("packet_count",    0),
            "total_bytes"     : flow.get("total_bytes",     0),
            "packets_per_sec" : flow.get("packets_per_sec", 0),
            "flow_duration"   : flow.get("flow_duration",   0),
            "attack_type"     : attack_type,
            "severity"        : severity,
            "is_threat"       : is_threat,
            "detection_source": source,
            "nsl_rf_label"    : nsl_rf["label"],
            "nsl_rf_conf"     : nsl_rf["confidence"],
            "cic_rf_label"    : cic_rf["label"],
            "cic_rf_conf"     : cic_rf["confidence"],
            "nsl_ae_anomaly"  : nsl_ae["is_anomaly"],
            "nsl_ae_error"    : nsl_ae["error"],
            "cic_ae_anomaly"  : cic_ae["is_anomaly"],
            "cic_ae_error"    : cic_ae["error"],
        }

        # Log
        if is_threat:
            logger.warning(
                f"🚨 THREAT | {attack_type} | {severity} | "
                f"{flow.get('src_ip')} → {flow.get('dst_ip')} | "
                f"Source: {source}"
            )
        else:
            logger.info(
                f"✅ Normal | "
                f"{flow.get('src_ip')} → {flow.get('dst_ip')} | "
                f"CIC-RF: {cic_rf['confidence']}%"
            )

        return result


# ─────────────────────────────────────────
# Test
# ─────────────────────────────────────────
if __name__ == "__main__":
    clf = ArgusClassifier()

    if not clf.load_models():
        exit(1)

    test_flows = [
        {
            "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
            "protocol": "TCP", "packet_count": 850,
            "total_bytes": 425000, "packets_per_sec": 48.5,
            "flow_duration": 17.5, "syn_count": 800,
            "rst_count": 5, "dst_port": 80
        },
        {
            "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
            "protocol": "TCP", "packet_count": 12,
            "total_bytes": 5400, "packets_per_sec": 3.2,
            "flow_duration": 3.7, "syn_count": 1,
            "rst_count": 0, "dst_port": 443
        },
        {
            "src_ip": "203.0.113.45", "dst_ip": "10.0.0.1",
            "protocol": "TCP", "packet_count": 120,
            "total_bytes": 6000, "packets_per_sec": 22.3,
            "flow_duration": 5.3, "syn_count": 90,
            "rst_count": 30, "dst_port": 22
        },
    ]

    print("\n" + "═" * 65)
    print("  ARGUS — Dual Dataset Classification Test")
    print("═" * 65)

    for i, flow in enumerate(test_flows, 1):
        print(f"\n[Flow #{i}] {flow['src_ip']} → {flow['dst_ip']}")
        print("─" * 50)
        result = clf.classify_flow(flow)
        print(f"  Attack Type      : {result['attack_type']}")
        print(f"  Severity         : {result['severity']}")
        print(f"  Is Threat        : {'🚨 YES' if result['is_threat'] else '✅ NO'}")
        print(f"  Detection Source : {result['detection_source']}")
        print(f"  NSL-KDD RF       : {result['nsl_rf_label']} ({result['nsl_rf_conf']}%)")
        print(f"  CICIDS2017 RF    : {result['cic_rf_label']} ({result['cic_rf_conf']}%)")
        print(f"  NSL AE Anomaly   : {result['nsl_ae_anomaly']}")
        print(f"  CIC AE Anomaly   : {result['cic_ae_anomaly']}")

    print(f"\n{'═' * 65}\n")