# llm/explainer.py
# ─────────────────────────────────────────
# ARGUS — LLM Threat Explainer
# Uses local Ollama/Mistral to explain
# detected attacks in plain English
# ─────────────────────────────────────────

import requests
import json
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# Ollama runs locally on this address
OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "mistral"


# ─────────────────────────────────────────
# Severity levels for each attack type
# ─────────────────────────────────────────
SEVERITY_MAP = {
    "DoS"     : "HIGH",
    "Probe"   : "MEDIUM",
    "R2L"     : "HIGH",
    "U2R"     : "CRITICAL",
    "Unknown" : "HIGH",
    "NORMAL"  : "LOW",
}

SEVERITY_EMOJI = {
    "LOW"      : "🟢",
    "MEDIUM"   : "🟡",
    "HIGH"     : "🔴",
    "CRITICAL" : "🚨",
}


def build_prompt(threat_data: dict) -> str:
    """
    Builds a clear prompt for the LLM based on threat data.
    The better the prompt, the better the explanation.
    """
    attack_type  = threat_data.get("attack_type",   "Unknown")
    src_ip       = threat_data.get("src_ip",        "Unknown")
    dst_ip       = threat_data.get("dst_ip",        "Unknown")
    protocol     = threat_data.get("protocol",      "Unknown")
    packet_count = threat_data.get("packet_count",  0)
    total_bytes  = threat_data.get("total_bytes",   0)
    pps          = threat_data.get("packets_per_sec", 0)
    severity     = threat_data.get("severity",      "HIGH")
    timestamp    = threat_data.get("timestamp",     datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    prompt = f"""You are ARGUS, an expert AI cybersecurity analyst.
A network intrusion detection system has detected a potential threat.
Analyze it and respond in exactly this format:

THREAT SUMMARY:
[2-3 sentences explaining what this attack is in simple English]

WHAT IS HAPPENING:
[Explain in plain English what the attacker is trying to do]

WHY IT IS DANGEROUS:
[Explain the potential impact on the victim's system]

IMMEDIATE ACTIONS:
1. [First action to take]
2. [Second action to take]
3. [Third action to take]

TECHNICAL DETAILS:
[One paragraph with technical context for security professionals]

---
DETECTED THREAT DATA:
- Attack Type    : {attack_type}
- Severity       : {severity}
- Source IP      : {src_ip}
- Target IP      : {dst_ip}
- Protocol       : {protocol}
- Packet Count   : {packet_count}
- Total Bytes    : {total_bytes}
- Packets/Second : {pps}
- Detected At    : {timestamp}
---

Keep your response clear, concise and actionable.
Use simple English for the summary sections.
"""
    return prompt


def query_ollama(prompt: str) -> str:
    """
    Sends the prompt to local Ollama and gets a response.
    Ollama must be running: `ollama run mistral`
    """
    try:
        payload = {
            "model"  : OLLAMA_MODEL,
            "prompt" : prompt,
            "stream" : False        # Get full response at once
        }

        logger.info(f"Querying Ollama ({OLLAMA_MODEL})...")

        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120             # Wait up to 2 minutes
        )

        if response.status_code == 200:
            result = response.json()
            return result.get("response", "No response from model.")
        else:
            logger.error(f"Ollama error: {response.status_code}")
            return f"Error: Ollama returned status {response.status_code}"

    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to Ollama!")
        logger.error("Make sure Ollama is running: ollama serve")
        return "ERROR: Ollama is not running. Start it with: ollama serve"

    except requests.exceptions.Timeout:
        logger.error("Ollama timed out!")
        return "ERROR: Ollama response timed out."

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return f"ERROR: {str(e)}"


def explain_threat(threat_data: dict) -> dict:
    """
    Main function — takes threat data, returns full explanation.

    Input example:
    {
        "attack_type"    : "DoS",
        "src_ip"         : "192.168.1.100",
        "dst_ip"         : "10.0.0.1",
        "protocol"       : "TCP",
        "packet_count"   : 500,
        "total_bytes"    : 250000,
        "packets_per_sec": 48.5
    }

    Returns:
    {
        "attack_type" : "DoS",
        "severity"    : "HIGH",
        "explanation" : "...",
        "timestamp"   : "...",
        "raw_data"    : {...}
    }
    """
    # Add severity to threat data
    attack_type = threat_data.get("attack_type", "Unknown")
    severity    = SEVERITY_MAP.get(attack_type, "HIGH")
    emoji       = SEVERITY_EMOJI.get(severity, "🔴")

    threat_data["severity"]  = severity
    threat_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logger.info("─" * 50)
    logger.info(f"{emoji} THREAT DETECTED: {attack_type} | Severity: {severity}")
    logger.info(f"   From : {threat_data.get('src_ip', 'Unknown')}")
    logger.info(f"   To   : {threat_data.get('dst_ip', 'Unknown')}")
    logger.info("─" * 50)

    # Build prompt
    prompt = build_prompt(threat_data)

    # Get explanation from LLM
    explanation = query_ollama(prompt)

    # Build result
    result = {
        "attack_type" : attack_type,
        "severity"    : severity,
        "emoji"       : emoji,
        "explanation" : explanation,
        "timestamp"   : threat_data["timestamp"],
        "raw_data"    : threat_data
    }

    return result


def print_explanation(result: dict):
    """
    Prints the explanation in a nicely formatted way.
    """
    emoji    = result.get("emoji",       "🔴")
    attack   = result.get("attack_type", "Unknown")
    severity = result.get("severity",    "HIGH")
    time     = result.get("timestamp",   "")

    print("\n" + "═" * 60)
    print(f"  {emoji} ARGUS THREAT REPORT")
    print(f"  Attack   : {attack}")
    print(f"  Severity : {severity}")
    print(f"  Time     : {time}")
    print("═" * 60)
    print(result.get("explanation", "No explanation available."))
    print("═" * 60 + "\n")


# ─────────────────────────────────────────
# Run directly to test
# ─────────────────────────────────────────
if __name__ == "__main__":

    # Simulate 3 different detected threats
    test_threats = [
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
        },
        {
            "attack_type"     : "U2R",
            "src_ip"          : "10.0.0.55",
            "dst_ip"          : "10.203.189.103",
            "protocol"        : "TCP",
            "packet_count"    : 15,
            "total_bytes"     : 3200,
            "packets_per_sec" : 2.1
        }
    ]

    # Test with first threat (DoS)
    logger.info("Testing ARGUS LLM Explainer with a DoS attack...")
    result = explain_threat(test_threats[0])
    print_explanation(result)