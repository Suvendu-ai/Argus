# core/ip_blocker.py
# ─────────────────────────────────────────
# ARGUS — Auto IP Blocking
# Automatically blocks attacker IPs
# using Windows Firewall rules
# ─────────────────────────────────────────

import subprocess
import logging
import json
import os
from datetime import datetime
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
BLOCKED_IPS_FILE  = "alerts/blocked_ips.json"
BLOCK_LOG_FILE    = "alerts/block_log.txt"

# Only block if severity is HIGH or CRITICAL
BLOCK_SEVERITIES  = {"HIGH", "CRITICAL"}

# Only block if same IP triggers X alerts
ALERT_THRESHOLD   = 3

# IPs that should NEVER be blocked
WHITELIST = {
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "192.168.1.1",    # Default gateway
    "8.8.8.8",        # Google DNS
    "8.8.4.4",        # Google DNS
    "1.1.1.1",        # Cloudflare DNS
}

# ─────────────────────────────────────────
# State
# ─────────────────────────────────────────
blocked_ips   = set()
alert_counts  = defaultdict(int)   # IP → alert count


def load_blocked_ips():
    """
    Loads previously blocked IPs from disk.
    So blocks persist across restarts.
    """
    global blocked_ips
    os.makedirs("alerts", exist_ok=True)

    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, "r") as f:
                data        = json.load(f)
                blocked_ips = set(data.get("blocked_ips", []))
                logger.info(f"✅ Loaded {len(blocked_ips)} previously blocked IPs")
        except Exception as e:
            logger.warning(f"Could not load blocked IPs: {e}")


def save_blocked_ips():
    """
    Saves blocked IPs to disk.
    """
    os.makedirs("alerts", exist_ok=True)
    try:
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump({
                "blocked_ips" : list(blocked_ips),
                "updated_at"  : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total"       : len(blocked_ips)
            }, f, indent=2)
    except Exception as e:
        logger.error(f"Could not save blocked IPs: {e}")


def is_valid_ip(ip: str) -> bool:
    """
    Checks if IP is valid and not in whitelist.
    """
    if not ip or ip == "Unknown":
        return False
    if ip in WHITELIST:
        return False
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return False   # Skip private IPs
    return True


def block_ip_windows(ip: str) -> bool:
    """
    Adds a Windows Firewall rule to block an IP.
    Requires Administrator privileges.
    """
    rule_name = f"ARGUS_BLOCK_{ip}"

    # Check if rule already exists
    check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
    result    = subprocess.run(
        check_cmd, shell=True,
        capture_output=True, text=True
    )

    if "No rules match" not in result.stdout and result.returncode == 0:
        logger.info(f"⚠️  IP already blocked: {ip}")
        return True

    # Add inbound block rule
    cmd_in  = (
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name}_IN" '
        f'dir=in action=block '
        f'remoteip={ip} '
        f'description="Blocked by ARGUS NIDS"'
    )

    # Add outbound block rule
    cmd_out = (
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name}_OUT" '
        f'dir=out action=block '
        f'remoteip={ip} '
        f'description="Blocked by ARGUS NIDS"'
    )

    try:
        result_in  = subprocess.run(
            cmd_in,  shell=True,
            capture_output=True, text=True
        )
        result_out = subprocess.run(
            cmd_out, shell=True,
            capture_output=True, text=True
        )

        if result_in.returncode == 0 and result_out.returncode == 0:
            logger.warning(f"🔒 BLOCKED IP: {ip} (inbound + outbound)")
            return True
        else:
            logger.error(f"Failed to block {ip}: {result_in.stderr}")
            logger.error("Make sure Argus is running as Administrator!")
            return False

    except Exception as e:
        logger.error(f"Exception blocking {ip}: {e}")
        return False


def unblock_ip_windows(ip: str) -> bool:
    """
    Removes the firewall block for an IP.
    """
    rule_name = f"ARGUS_BLOCK_{ip}"

    cmd_in  = f'netsh advfirewall firewall delete rule name="{rule_name}_IN"'
    cmd_out = f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"'

    try:
        subprocess.run(cmd_in,  shell=True, capture_output=True)
        subprocess.run(cmd_out, shell=True, capture_output=True)
        blocked_ips.discard(ip)
        save_blocked_ips()
        logger.info(f"🔓 UNBLOCKED IP: {ip}")
        return True
    except Exception as e:
        logger.error(f"Exception unblocking {ip}: {e}")
        return False


def log_block_event(ip: str, threat: dict):
    """
    Logs the block event to a file.
    """
    os.makedirs("alerts", exist_ok=True)
    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attack_type = threat.get("attack_type", "Unknown")
    severity    = threat.get("severity",    "HIGH")

    log_entry = (
        f"[{timestamp}] BLOCKED | IP: {ip} | "
        f"Attack: {attack_type} | Severity: {severity}\n"
    )

    with open(BLOCK_LOG_FILE, "a") as f:
        f.write(log_entry)


def process_threat(threat: dict) -> dict:
    """
    Main function called by the API for every detected threat.
    Decides whether to block the source IP.

    Returns updated threat dict with block status.
    """
    src_ip   = threat.get("src_ip",   "Unknown")
    severity = threat.get("severity", "HIGH")

    threat["ip_blocked"]     = False
    threat["block_reason"]   = ""
    threat["alert_count"]    = 0

    # Skip if not a valid external IP
    if not is_valid_ip(src_ip):
        threat["block_reason"] = "Whitelisted or private IP"
        return threat

    # Skip if severity not high enough
    if severity not in BLOCK_SEVERITIES:
        threat["block_reason"] = f"Severity {severity} below block threshold"
        return threat

    # Count alerts for this IP
    alert_counts[src_ip] += 1
    threat["alert_count"] = alert_counts[src_ip]

    # Already blocked
    if src_ip in blocked_ips:
        threat["ip_blocked"]   = True
        threat["block_reason"] = "Already blocked"
        return threat

    # Block if threshold reached
    if alert_counts[src_ip] >= ALERT_THRESHOLD:
        success = block_ip_windows(src_ip)

        if success:
            blocked_ips.add(src_ip)
            save_blocked_ips()
            log_block_event(src_ip, threat)
            threat["ip_blocked"]   = True
            threat["block_reason"] = (
                f"Blocked after {alert_counts[src_ip]} alerts"
            )
            logger.warning(
                f"🚨 AUTO-BLOCKED {src_ip} after "
                f"{alert_counts[src_ip]} alerts | "
                f"{threat.get('attack_type')}"
            )
        else:
            threat["block_reason"] = "Block failed — run as Administrator"
    else:
        remaining = ALERT_THRESHOLD - alert_counts[src_ip]
        threat["block_reason"] = (
            f"Alert {alert_counts[src_ip]}/{ALERT_THRESHOLD} "
            f"— will block after {remaining} more alerts"
        )

    return threat


def get_blocked_ips() -> list:
    """Returns list of all blocked IPs with details."""
    return list(blocked_ips)


def get_alert_counts() -> dict:
    """Returns alert count per IP."""
    return dict(alert_counts)


def clear_all_blocks():
    """
    Emergency function — removes ALL ARGUS firewall rules.
    Use if something goes wrong.
    """
    logger.warning("Clearing ALL ARGUS firewall blocks...")
    for ip in list(blocked_ips):
        unblock_ip_windows(ip)
    alert_counts.clear()
    logger.info("✅ All blocks cleared")


# ─────────────────────────────────────────
# Load on import
# ─────────────────────────────────────────
load_blocked_ips()


# ─────────────────────────────────────────
# Test directly
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "═" * 55)
    print("  ARGUS — IP Blocker Test")
    print("  (Run as Administrator for real blocking)")
    print("═" * 55)

    # Simulate 3 alerts from same IP
    test_threat = {
        "src_ip"      : "203.0.113.45",
        "dst_ip"      : "10.0.0.1",
        "attack_type" : "DDoS",
        "severity"    : "HIGH",
        "protocol"    : "TCP",
    }

    for i in range(1, 5):
        print(f"\n--- Alert #{i} from {test_threat['src_ip']} ---")
        result = process_threat(test_threat.copy())
        print(f"  Blocked      : {result['ip_blocked']}")
        print(f"  Alert Count  : {result['alert_count']}")
        print(f"  Reason       : {result['block_reason']}")

    print(f"\n✅ Currently blocked IPs: {get_blocked_ips()}")
    print(f"✅ Alert counts: {get_alert_counts()}")
    