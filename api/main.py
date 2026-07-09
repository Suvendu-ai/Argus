# api/main.py
# ─────────────────────────────────────────
# ARGUS — FastAPI Backend
# Connects capture → classifier → LLM
# Serves data to the dashboard via WebSocket
# ─────────────────────────────────────────

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import threading
import logging
import json
from datetime import datetime
from collections import deque

from core.extractor import FeatureExtractor
from core.classifier import ArgusClassifier
from llm.explainer import explain_threat
from llm.reporter import generate_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────
app = FastAPI(
    title="ARGUS API",
    description="AI-Powered Network Intrusion Detection System",
    version="1.0.0"
)

# Allow React dashboard to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────
# Global State
# ─────────────────────────────────────────
classifier   = ArgusClassifier()
extractor    = FeatureExtractor(window_seconds=5)

# Store last 100 alerts and flows in memory
recent_alerts = deque(maxlen=100)
recent_flows  = deque(maxlen=100)

# Stats counter
stats = {
    "total_flows"    : 0,
    "total_threats"  : 0,
    "total_normal"   : 0,
    "dos_count"      : 0,
    "probe_count"    : 0,
    "r2l_count"      : 0,
    "u2r_count"      : 0,
    "unknown_count"  : 0,
    "started_at"     : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

# Connected WebSocket clients (dashboard)
connected_clients = []

# Is capture running?
capture_running = False


# ─────────────────────────────────────────
# WebSocket Manager
# ─────────────────────────────────────────
async def broadcast(message: dict):
    """
    Sends a message to ALL connected dashboard clients.
    """
    if not connected_clients:
        return

    data = json.dumps(message)
    disconnected = []

    for client in connected_clients:
        try:
            await client.send_text(data)
        except Exception:
            disconnected.append(client)

    # Remove disconnected clients
    for client in disconnected:
        connected_clients.remove(client)


# ─────────────────────────────────────────
# Core Processing Pipeline
# ─────────────────────────────────────────
def process_flow(flow: dict):
    """
    Called for every extracted flow.
    Runs classification and sends results to dashboard.
    """
    global stats

    stats["total_flows"] += 1

    # Classify the flow
    result = classifier.classify_flow(flow)
    if not result:
        return

    # Update stats
    if result["is_threat"]:
        stats["total_threats"] += 1
        attack = result["attack_type"]

        if attack == "DoS"     : stats["dos_count"]     += 1
        elif attack == "Probe" : stats["probe_count"]   += 1
        elif attack == "R2L"   : stats["r2l_count"]     += 1
        elif attack == "U2R"   : stats["u2r_count"]     += 1
        else                   : stats["unknown_count"] += 1

        # Add to alerts
        alert = {
            **result,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "id"       : len(recent_alerts) + 1
        }
        recent_alerts.appendleft(alert)

        # Send alert to dashboard via WebSocket
        asyncio.run(broadcast({
            "type"  : "alert",
            "data"  : alert,
            "stats" : dict(stats)
        }))

        logger.warning(
            f"🚨 ALERT #{alert['id']} | "
            f"{result['attack_type']} | "
            f"{result['src_ip']} → {result['dst_ip']}"
        )

    else:
        stats["total_normal"] += 1

    # Always send flow to dashboard
    flow_data = {
        **result,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    recent_flows.appendleft(flow_data)

    asyncio.run(broadcast({
        "type"  : "flow",
        "data"  : flow_data,
        "stats" : dict(stats)
    }))


def capture_loop():
    """
    Runs in a background thread.
    Continuously captures packets and processes flows.
    """
    global capture_running
    capture_running = True

    logger.info("🔍 Starting live capture loop...")

    def on_flow_ready(flow):
        process_flow(flow)

    # Override extractor flush to call our processor
    original_flush = extractor.flush_flows

    def custom_flush():
        for flow_key, packets in extractor.flows.items():
            if len(packets) < 2:
                continue
            features = extractor.compute_flow_features(flow_key, packets)
            on_flow_ready(features)
        extractor.flows.clear()

    extractor.flush_flows = custom_flush

    # Start infinite capture
    from scapy.all import sniff
    sniff(
        iface=None,
        prn=extractor.process_packet,
        store=False
    )


# ─────────────────────────────────────────
# API Routes
# ─────────────────────────────────────────

@app.on_event("startup")
async def startup():
    """
    Runs when the API starts.
    Loads ML models automatically.
    """
    logger.info("=" * 50)
    logger.info("  ARGUS API Starting...")
    logger.info("=" * 50)

    if not classifier.load_models():
        logger.error("Failed to load models!")
        return

    logger.info("✅ ARGUS API Ready!")
    logger.info("   Dashboard : http://localhost:8000")
    logger.info("   API Docs  : http://localhost:8000/docs")


@app.get("/")
async def root():
    return {
        "name"    : "ARGUS",
        "version" : "1.0.0",
        "status"  : "running",
        "message" : "AI-Powered Network Intrusion Detection System"
    }


@app.get("/stats")
async def get_stats():
    """Returns live statistics."""
    return JSONResponse(content=dict(stats))


@app.get("/alerts")
async def get_alerts(limit: int = 20):
    """Returns recent alerts."""
    alerts = list(recent_alerts)[:limit]
    return JSONResponse(content={"alerts": alerts, "total": len(alerts)})


@app.get("/flows")
async def get_flows(limit: int = 20):
    """Returns recent network flows."""
    flows = list(recent_flows)[:limit]
    return JSONResponse(content={"flows": flows, "total": len(flows)})


@app.post("/capture/start")
async def start_capture():
    """Starts live packet capture in background."""
    global capture_running

    if capture_running:
        return JSONResponse(content={"message": "Capture already running"})

    thread = threading.Thread(target=capture_loop, daemon=True)
    thread.start()

    return JSONResponse(content={
        "message" : "✅ Capture started",
        "status"  : "running"
    })


@app.post("/capture/stop")
async def stop_capture():
    """Stops live packet capture."""
    global capture_running
    capture_running = False
    return JSONResponse(content={"message": "Capture stopped"})


@app.post("/report/generate")
async def generate_incident_report():
    """Generates a full incident report from recent alerts."""
    if not recent_alerts:
        return JSONResponse(
            content={"message": "No alerts to report"},
            status_code=400
        )

    # Get LLM explanations for recent threats
    threats = list(recent_alerts)[:10]
    explained = []

    for threat in threats:
        result = explain_threat(threat)
        explained.append(result)

    report = generate_report(explained)

    return JSONResponse(content={
        "message"     : "✅ Report generated",
        "report_path" : report["report_path"],
        "threats"     : report["threat_count"]
    })


@app.post("/explain")
async def explain_single_threat(threat: dict):
    """Gets LLM explanation for a single threat."""
    result = explain_threat(threat)
    return JSONResponse(content=result)


# ─────────────────────────────────────────
# WebSocket — Live Dashboard Feed
# ─────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket connection for the React dashboard.
    Dashboard connects here to receive live updates.
    """
    await websocket.accept()
    connected_clients.append(websocket)
    logger.info(f"📡 Dashboard connected | {len(connected_clients)} client(s)")

    try:
        # Send current state immediately on connect
        await websocket.send_text(json.dumps({
            "type"   : "init",
            "stats"  : dict(stats),
            "alerts" : list(recent_alerts)[:20],
            "flows"  : list(recent_flows)[:20]
        }))

        # Keep connection alive
        while True:
            await asyncio.sleep(1)
            await websocket.send_text(json.dumps({
                "type"  : "heartbeat",
                "stats" : dict(stats),
                "time"  : datetime.now().strftime("%H:%M:%S")
            }))

    except WebSocketDisconnect:
        connected_clients.remove(websocket)
        logger.info(f"📡 Dashboard disconnected | {len(connected_clients)} client(s)")


# ─────────────────────────────────────────
# Run the server
# ─────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )