# llm/reporter.py
# ─────────────────────────────────────────
# ARGUS — Incident Report Generator
# Creates professional security reports
# from detected threats and LLM explanations
# ─────────────────────────────────────────

import os
import json
import logging
from datetime import datetime
from llm.explainer import explain_threat, SEVERITY_EMOJI

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

REPORTS_DIR = "reports/"


def generate_markdown_report(threats: list, session_id: str = None) -> str:
    """
    Takes a list of detected threats and generates
    a full professional incident report in Markdown format.
    """
    if not session_id:
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    now       = datetime.now()
    date_str  = now.strftime("%B %d, %Y")
    time_str  = now.strftime("%H:%M:%S")

    # Count severity levels
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in threats:
        sev = t.get("severity", "HIGH")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Attack type summary
    attack_types = {}
    for t in threats:
        a = t.get("attack_type", "Unknown")
        attack_types[a] = attack_types.get(a, 0) + 1

    # ─────────────────────────────────────
    # Build the Markdown report
    # ─────────────────────────────────────
    report = f"""# 🛡️ ARGUS — Security Incident Report
---
**Report ID**     : ARGUS-{session_id}
**Generated At**  : {date_str} at {time_str}
**System**        : ARGUS AI-Powered Network Intrusion Detection
**Status**        : ⚠️ THREATS DETECTED

---

## 📊 Executive Summary

| Metric | Value |
|---|---|
| Total Threats Detected | {len(threats)} |
| Critical Severity | 🚨 {severity_counts['CRITICAL']} |
| High Severity | 🔴 {severity_counts['HIGH']} |
| Medium Severity | 🟡 {severity_counts['MEDIUM']} |
| Low Severity | 🟢 {severity_counts['LOW']} |
| Report Period | {date_str} |

### Attack Type Breakdown
| Attack Type | Count |
|---|---|
"""

    for attack, count in attack_types.items():
        report += f"| {attack} | {count} |\n"

    report += f"""
---

## 🔍 Overall Risk Assessment

"""
    # Overall risk level
    if severity_counts["CRITICAL"] > 0:
        report += "**Overall Risk Level: 🚨 CRITICAL**\n\n"
        report += "Immediate action required. Critical threats have been detected that could compromise system integrity.\n\n"
    elif severity_counts["HIGH"] > 0:
        report += "**Overall Risk Level: 🔴 HIGH**\n\n"
        report += "Urgent attention needed. High severity threats detected that require immediate investigation.\n\n"
    elif severity_counts["MEDIUM"] > 0:
        report += "**Overall Risk Level: 🟡 MEDIUM**\n\n"
        report += "Moderate risk detected. Threats should be investigated within 24 hours.\n\n"
    else:
        report += "**Overall Risk Level: 🟢 LOW**\n\n"
        report += "Low risk environment. Monitor for escalation.\n\n"

    report += "---\n\n## 📋 Detailed Threat Analysis\n\n"

    # ─────────────────────────────────────
    # Individual threat sections
    # ─────────────────────────────────────
    for i, threat in enumerate(threats, 1):
        attack_type  = threat.get("attack_type",     "Unknown")
        severity     = threat.get("severity",        "HIGH")
        emoji        = threat.get("emoji",           "🔴")
        src_ip       = threat.get("src_ip",          "Unknown")
        dst_ip       = threat.get("dst_ip",          "Unknown")
        protocol     = threat.get("protocol",        "Unknown")
        packet_count = threat.get("packet_count",    0)
        total_bytes  = threat.get("total_bytes",     0)
        pps          = threat.get("packets_per_sec", 0)
        timestamp    = threat.get("timestamp",       time_str)
        explanation  = threat.get("explanation",     "No explanation available.")

        report += f"""### Threat #{i} — {emoji} {attack_type} Attack

| Field | Value |
|---|---|
| Attack Type | {attack_type} |
| Severity | {emoji} {severity} |
| Source IP | `{src_ip}` |
| Target IP | `{dst_ip}` |
| Protocol | {protocol} |
| Packet Count | {packet_count} |
| Total Bytes | {total_bytes:,} bytes |
| Packets/Second | {pps} |
| Detected At | {timestamp} |

#### 🤖 AI Analysis
{explanation}

---

"""

    # ─────────────────────────────────────
    # Recommendations section
    # ─────────────────────────────────────
    report += """## 🔧 General Recommendations

### Immediate Actions
1. **Block suspicious IPs** — Add source IPs to firewall blocklist
2. **Enable rate limiting** — Limit connections per IP per second
3. **Monitor logs** — Check system and application logs for breach signs
4. **Alert your team** — Notify security team of critical/high severity threats

### Short-term Actions
1. **Patch systems** — Ensure all software is up to date
2. **Review firewall rules** — Tighten inbound/outbound rules
3. **Enable IDS/IPS** — Deploy intrusion prevention alongside detection
4. **Conduct vulnerability scan** — Identify exposed attack surfaces

### Long-term Actions
1. **Network segmentation** — Isolate critical systems
2. **Security awareness training** — Train staff on phishing and social engineering
3. **Incident response plan** — Document and rehearse response procedures
4. **Regular penetration testing** — Test defenses proactively

---

## 📝 Disclaimer

This report was automatically generated by **ARGUS AI-Powered NIDS**.
All analysis is AI-assisted and should be reviewed by a qualified
security professional before taking action.

---
*Report generated by ARGUS v1.0 — AI-Powered Network Intrusion Detection System*
*https://github.com/Suvendu-ai/Argus*
"""

    return report


def save_report(report_content: str, session_id: str = None) -> str:
    """
    Saves the report as a Markdown file.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    if not session_id:
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename    = f"ARGUS_Report_{session_id}.md"
    filepath    = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_content)

    logger.info(f"✅ Report saved → {filepath}")
    return filepath


def save_threats_json(threats: list, session_id: str = None) -> str:
    """
    Also saves raw threat data as JSON for the dashboard to read.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    if not session_id:
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = f"ARGUS_Threats_{session_id}.json"
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(threats, f, indent=2)

    logger.info(f"✅ Threat data saved → {filepath}")
    return filepath


def generate_report(threats: list) -> dict:
    """
    Master function — generates both Markdown report
    and JSON threat data in one call.
    """
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    logger.info("=" * 50)
    logger.info(f"  Generating Incident Report...")
    logger.info(f"  Threats to report: {len(threats)}")
    logger.info("=" * 50)

    # Generate markdown
    report_content = generate_markdown_report(threats, session_id)

    # Save files
    md_path   = save_report(report_content, session_id)
    json_path = save_threats_json(
        [t.get("raw_data", t) for t in threats],
        session_id
    )

    return {
        "session_id"   : session_id,
        "report_path"  : md_path,
        "json_path"    : json_path,
        "threat_count" : len(threats),
        "content"      : report_content
    }


# ─────────────────────────────────────────
# Run directly to test
# ─────────────────────────────────────────
if __name__ == "__main__":

    logger.info("Testing ARGUS Report Generator...")
    logger.info("Simulating 3 detected threats with LLM explanations...")

    # Simulate detected threats
    raw_threats = [
        {
            "attack_type"     : "DoS",
            "src_ip"          : "192.168.1.100",
            "dst_ip"          : "10.203.189.103",
            "protocol"        : "TCP",
            "packet_count"    : 850,
            "total_bytes"     : 425000,
            "packets_per_sec" : 48.5
        },
        {
            "attack_type"     : "Probe",
            "src_ip"          : "203.0.113.45",
            "dst_ip"          : "10.203.189.103",
            "protocol"        : "TCP",
            "packet_count"    : 120,
            "total_bytes"     : 6000,
            "packets_per_sec" : 22.3
        }
    ]

    # Get LLM explanation for each threat
    explained_threats = []
    for threat in raw_threats:
        logger.info(f"Getting explanation for {threat['attack_type']} attack...")
        result = explain_threat(threat)
        explained_threats.append(result)

    # Generate full report
    report = generate_report(explained_threats)

    logger.info("=" * 50)
    logger.info(f"✅ Report generated successfully!")
    logger.info(f"📄 Markdown : {report['report_path']}")
    logger.info(f"📊 JSON     : {report['json_path']}")
    logger.info("=" * 50)

    # Print first 50 lines preview
    print("\n📋 Report Preview (first 50 lines):")
    print("─" * 60)
    lines = report["content"].split("\n")
    for line in lines[:50]:
        print(line)
    print("─" * 60)
    print(f"\n✅ Full report saved to: {report['report_path']}")