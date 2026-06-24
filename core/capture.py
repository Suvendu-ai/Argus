# core/capture.py
# ─────────────────────────────────────────
# ARGUS — Packet Capture Module
# Captures live network traffic using Scapy
# ─────────────────────────────────────────

from scapy.all import sniff, get_if_list
from datetime import datetime
import logging

# Setup logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)


def list_interfaces():
    """
    Lists all available network interfaces on this machine.
    Run this first to find the right interface to monitor.
    """
    interfaces = get_if_list()
    print("\n Available Network Interfaces:")
    print("─" * 35)
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")
    print("─" * 35)
    return interfaces


def process_packet(packet):
    """
    Called automatically for every packet captured.
    Extracts and prints basic info about each packet.
    """
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Check if packet has IP layer
    if packet.haslayer("IP"):
        src_ip  = packet["IP"].src
        dst_ip  = packet["IP"].dst
        proto   = packet["IP"].proto
        length  = len(packet)

        # Identify protocol name
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"OTHER({proto})")

        logger.info(f"{timestamp} | {proto_name} | {src_ip} → {dst_ip} | {length} bytes")

    else:
        # Non-IP packet (ARP, etc.)
        logger.info(f"{timestamp} | NON-IP | {packet.summary()}")


def start_capture(interface=None, packet_count=0, filter_rule=""):
    """
    Starts capturing live packets.

    Args:
        interface   : Network interface to listen on (None = auto)
        packet_count: How many packets to capture (0 = infinite)
        filter_rule : BPF filter e.g. 'tcp', 'udp', 'port 80'
    """
    logger.info("=" * 45)
    logger.info("  ARGUS — Network Capture Started")
    logger.info("=" * 45)

    if interface:
        logger.info(f"Interface   : {interface}")
    else:
        logger.info("Interface   : Auto (default)")

    logger.info(f"Packet Limit: {'Infinite' if packet_count == 0 else packet_count}")
    logger.info(f"Filter      : '{filter_rule}' " if filter_rule else "Filter      : None (capture all)")
    logger.info("─" * 45)
    logger.info("Listening... Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=interface,
            prn=process_packet,       # Call process_packet for each packet
            count=packet_count,       # 0 = run forever
            filter=filter_rule,       # BPF filter
            store=False               # Don't store in memory (saves RAM)
        )
    except KeyboardInterrupt:
        logger.info("\n Capture stopped by user.")
    except Exception as e:
        logger.error(f"Error during capture: {e}")


# ─────────────────────────────────────────
# Run directly to test
# ─────────────────────────────────────────
if __name__ == "__main__":

    # Step 1 — Show available interfaces
    interfaces = list_interfaces()

    # Step 2 — Start capturing (auto interface, first 20 packets)
    # Change packet_count=0 for infinite capture
    start_capture(
        interface=None,
        packet_count=20,
        filter_rule=""
    )