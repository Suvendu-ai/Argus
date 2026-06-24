# core/extractor.py
# ─────────────────────────────────────────
# ARGUS — Feature Extraction Module
# Converts raw packets into ML-ready features
# ─────────────────────────────────────────

from scapy.all import sniff, get_if_list
from datetime import datetime
from collections import defaultdict
import pandas as pd
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Groups packets into FLOWS and extracts features from each flow.
    
    A FLOW = all packets between same source IP → destination IP
    on the same port, within a time window.
    
    Think of it like: instead of reading one car,
    we observe the entire convoy and take notes.
    """

    def __init__(self, window_seconds=5):
        # How many seconds to group packets into one flow
        self.window_seconds = window_seconds

        # Storage: key = (src_ip, dst_ip, src_port, dst_port, protocol)
        self.flows = defaultdict(list)
        self.start_time = time.time()
        self.extracted_features = []

    def get_flow_key(self, packet):
        """
        Creates a unique ID for each flow based on
        source IP, destination IP, ports and protocol.
        """
        if packet.haslayer("IP"):
            src_ip  = packet["IP"].src
            dst_ip  = packet["IP"].dst
            proto   = packet["IP"].proto

            src_port = 0
            dst_port = 0

            if packet.haslayer("TCP"):
                src_port = packet["TCP"].sport
                dst_port = packet["TCP"].dport
            elif packet.haslayer("UDP"):
                src_port = packet["UDP"].sport
                dst_port = packet["UDP"].dport

            return (src_ip, dst_ip, src_port, dst_port, proto)
        return None

    def extract_packet_info(self, packet):
        """
        Pulls raw info from a single packet.
        """
        info = {
            "timestamp" : time.time(),
            "length"    : len(packet),
            "protocol"  : 0,
            "src_port"  : 0,
            "dst_port"  : 0,
            "tcp_flags" : 0,
            "ttl"       : 0,
        }

        if packet.haslayer("IP"):
            info["protocol"] = packet["IP"].proto
            info["ttl"]      = packet["IP"].ttl

        if packet.haslayer("TCP"):
            info["src_port"]  = packet["TCP"].sport
            info["dst_port"]  = packet["TCP"].dport
            info["tcp_flags"] = int(packet["TCP"].flags)

        elif packet.haslayer("UDP"):
            info["src_port"] = packet["UDP"].sport
            info["dst_port"] = packet["UDP"].dport

        return info

    def compute_flow_features(self, flow_key, packets):
        """
        Takes a group of packets (a flow) and computes
        statistical features the ML model will use.
        """
        src_ip, dst_ip, src_port, dst_port, proto = flow_key

        lengths     = [p["length"]    for p in packets]
        timestamps  = [p["timestamp"] for p in packets]
        flags       = [p["tcp_flags"] for p in packets]

        # Time duration of this flow
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0

        # Packets per second
        pps = len(packets) / duration if duration > 0 else len(packets)

        # Protocol name
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "OTHER")

        features = {
            # Identity
            "src_ip"            : src_ip,
            "dst_ip"            : dst_ip,
            "src_port"          : src_port,
            "dst_port"          : dst_port,
            "protocol"          : proto_name,

            # Volume features
            "packet_count"      : len(packets),
            "total_bytes"       : sum(lengths),
            "avg_packet_size"   : sum(lengths) / len(lengths),
            "max_packet_size"   : max(lengths),
            "min_packet_size"   : min(lengths),

            # Time features
            "flow_duration"     : round(duration, 4),
            "packets_per_sec"   : round(pps, 4),

            # TCP flag features (useful for detecting SYN floods, scans)
            "syn_count"         : sum(1 for f in flags if f & 0x02),
            "ack_count"         : sum(1 for f in flags if f & 0x10),
            "fin_count"         : sum(1 for f in flags if f & 0x01),
            "rst_count"         : sum(1 for f in flags if f & 0x04),

            # Metadata
            "timestamp"         : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "label"             : "unknown"   # ML will fill this later
        }

        return features

    def process_packet(self, packet):
        """
        Called for every captured packet.
        Adds it to its flow and checks if window has expired.
        """
        flow_key = self.get_flow_key(packet)
        if not flow_key:
            return  # Skip non-IP packets

        packet_info = self.extract_packet_info(packet)
        self.flows[flow_key].append(packet_info)

        # Check if time window has expired → compute features
        elapsed = time.time() - self.start_time
        if elapsed >= self.window_seconds:
            self.flush_flows()
            self.start_time = time.time()

    def flush_flows(self):
        """
        Processes all current flows and extracts features.
        Clears flows after processing.
        """
        if not self.flows:
            return

        logger.info(f"⚡ Processing {len(self.flows)} flows...")

        for flow_key, packets in self.flows.items():
            if len(packets) < 2:
                continue  # Skip single-packet flows

            features = self.compute_flow_features(flow_key, packets)
            self.extracted_features.append(features)

            logger.info(
                f"  FLOW | {features['src_ip']} → {features['dst_ip']} "
                f"| {features['protocol']} "
                f"| Packets: {features['packet_count']} "
                f"| Bytes: {features['total_bytes']} "
                f"| PPS: {features['packets_per_sec']}"
            )

        self.flows.clear()

    def save_to_csv(self, path="data/processed/live_flows.csv"):
        """
        Saves all extracted features to a CSV file.
        This CSV is what the ML model will read.
        """
        if not self.extracted_features:
            logger.warning("No features to save yet.")
            return

        df = pd.DataFrame(self.extracted_features)
        df.to_csv(path, index=False)
        logger.info(f"✅ Saved {len(df)} flows to {path}")
        return df

    def start(self, interface=None, duration_seconds=30):
        """
        Starts live capture and feature extraction.
        Runs for duration_seconds then saves results.
        """
        logger.info("=" * 50)
        logger.info("  ARGUS — Feature Extractor Started")
        logger.info(f"  Window : {self.window_seconds}s | Duration: {duration_seconds}s")
        logger.info("=" * 50)

        sniff(
            iface=interface,
            prn=self.process_packet,
            timeout=duration_seconds,
            store=False
        )

        # Final flush
        self.flush_flows()

        # Save results
        df = self.save_to_csv()
        return df


# ─────────────────────────────────────────
# Run directly to test
# ─────────────────────────────────────────
if __name__ == "__main__":
    extractor = FeatureExtractor(window_seconds=5)

    # Capture for 30 seconds and extract features
    df = extractor.start(
        interface=None,
        duration_seconds=30
    )

    if df is not None:
        print("\n📊 Extracted Feature Sample:")
        print("─" * 60)
        print(df[["src_ip", "dst_ip", "protocol",
                   "packet_count", "total_bytes",
                   "packets_per_sec"]].to_string(index=False))