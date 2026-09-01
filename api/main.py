# api/main.py — FIXED VERSION
from core.geoip import enrich_threat
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
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
from core.ip_blocker import process_threat as check_and_block

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────
# Global State
# ─────────────────────────────────────────
classifier      = ArgusClassifier()
extractor       = FeatureExtractor(window_seconds=5)
recent_alerts   = deque(maxlen=100)
recent_flows    = deque(maxlen=100)
connected_clients = []
capture_running = False
main_loop       = None   # ← stores the main event loop

stats = {
    "total_flows"   : 0,
    "total_threats" : 0,
    "total_normal"  : 0,
    "dos_count"     : 0,
    "probe_count"   : 0,
    "r2l_count"     : 0,
    "u2r_count"     : 0,
    "unknown_count" : 0,
    "started_at"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}


# ─────────────────────────────────────────
# Lifespan (replaces deprecated on_event)
# ─────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_event_loop()   # ← save loop on startup

    logger.info("=" * 50)
    logger.info("  ARGUS API Starting...")
    logger.info("=" * 50)

    if not classifier.load_models():
        logger.error("Failed to load models!")
    else:
        logger.info("✅ ARGUS API Ready!")
        logger.info("   Dashboard : http://localhost:8000")
        logger.info("   API Docs  : http://localhost:8000/docs")

    yield  # App runs here


# ─────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────
app = FastAPI(
    title="ARGUS API",
    description="AI-Powered Network Intrusion Detection System",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────
# WebSocket Broadcast (thread-safe)
# ─────────────────────────────────────────
async def _broadcast(message: dict):
    """Async broadcast to all connected clients."""
    if not connected_clients:
        return
    data         = json.dumps(message, default=str)
    disconnected = []
    for client in connected_clients:
        try:
            await client.send_text(data)
        except Exception:
            disconnected.append(client)
    for c in disconnected:
        connected_clients.remove(c)


def broadcast_from_thread(message: dict):
    """
    Safely sends a message from a background thread
    to all connected WebSocket clients.
    """
    if main_loop and connected_clients:
        asyncio.run_coroutine_threadsafe(
            _broadcast(message), main_loop
        )


# ─────────────────────────────────────────
# Core Processing Pipeline
# ─────────────────────────────────────────
def process_flow(flow: dict):
    global stats
    stats["total_flows"] += 1

    result = classifier.classify_flow(flow)
    if not result:
        return

    result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Add Geo-IP location data
    result = enrich_threat(result)
    if result["is_threat"]:
        stats["total_threats"] += 1
        attack = result["attack_type"]
        if   attack == "DoS"   : stats["dos_count"]     += 1
        elif attack == "Probe" : stats["probe_count"]   += 1
        elif attack == "R2L"   : stats["r2l_count"]     += 1
        elif attack == "U2R"   : stats["u2r_count"]     += 1
        else                   : stats["unknown_count"] += 1

        alert = {**result, "id": len(recent_alerts) + 1}
        recent_alerts.appendleft(alert)
        # Auto block if threshold reached
        result = check_and_block(result)

        broadcast_from_thread({
            "type"  : "alert",
            "data"  : alert,
            "stats" : dict(stats)
        })
        logger.warning(
            f"🚨 ALERT | {result['attack_type']} | "
            f"{result['src_ip']} → {result['dst_ip']}"
        )
    else:
        stats["total_normal"] += 1

    recent_flows.appendleft(result)
    broadcast_from_thread({
        "type"  : "flow",
        "data"  : result,
        "stats" : dict(stats)
    })


def capture_loop():
    global capture_running
    capture_running = True
    logger.info("🔍 Capture loop started...")

    original_flush = extractor.flush_flows

    def custom_flush():
        for flow_key, packets in list(extractor.flows.items()):
            if len(packets) >= 2:
                features = extractor.compute_flow_features(flow_key, packets)
                process_flow(features)
        extractor.flows.clear()

    extractor.flush_flows = custom_flush

    from scapy.all import sniff
    sniff(iface=None, prn=extractor.process_packet, store=False)


# ─────────────────────────────────────────
# REST Endpoints
# ─────────────────────────────────────────
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
    return JSONResponse(content=dict(stats))


@app.get("/alerts")
async def get_alerts(limit: int = 20):
    return JSONResponse(content={
        "alerts": list(recent_alerts)[:limit],
        "total" : len(recent_alerts)
    })


@app.get("/flows")
async def get_flows(limit: int = 20):
    return JSONResponse(content={
        "flows": list(recent_flows)[:limit],
        "total": len(recent_flows)
    })


@app.post("/capture/start")
async def start_capture():
    global capture_running
    if capture_running:
        return JSONResponse(content={"message": "Already running"})
    thread = threading.Thread(target=capture_loop, daemon=True)
    thread.start()
    return JSONResponse(content={"message": "✅ Capture started", "status": "running"})


@app.post("/capture/stop")
async def stop_capture():
    global capture_running
    capture_running = False
    return JSONResponse(content={"message": "Capture stopped"})


@app.post("/report/generate")
async def generate_incident_report():
    if not recent_alerts:
        return JSONResponse(content={"message": "No alerts yet"}, status_code=400)
    threats   = [explain_threat(t) for t in list(recent_alerts)[:10]]
    report    = generate_report(threats)
    return JSONResponse(content={
        "message"     : "✅ Report generated",
        "report_path" : report["report_path"],
        "threats"     : report["threat_count"]
    })


@app.post("/explain")
async def explain_single(threat: dict):
    return JSONResponse(content=explain_threat(threat))

@app.get("/blocked-ips")
async def get_blocked():
    """Returns all currently blocked IPs."""
    from core.ip_blocker import get_blocked_ips, get_alert_counts
    return JSONResponse(content={
        "blocked_ips"  : get_blocked_ips(),
        "alert_counts" : get_alert_counts(),
        "total_blocked": len(get_blocked_ips())
    })


@app.post("/unblock/{ip}")
async def unblock_ip(ip: str):
    """Manually unblocks an IP."""
    from core.ip_blocker import unblock_ip_windows
    success = unblock_ip_windows(ip)
    return JSONResponse(content={
        "message": f"✅ {ip} unblocked" if success else f"❌ Failed to unblock {ip}",
        "success": success
    })


@app.post("/clear-blocks")
async def clear_blocks():
    """Emergency — removes all ARGUS firewall rules."""
    from core.ip_blocker import clear_all_blocks
    clear_all_blocks()
    return JSONResponse(content={"message": "✅ All blocks cleared"})

# ─────────────────────────────────────────
# WebSocket
# ─────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    logger.info(f"📡 Dashboard connected ({len(connected_clients)} client(s))")

    try:
        # Send current state immediately
        await websocket.send_text(json.dumps({
            "type"   : "init",
            "stats"  : dict(stats),
            "alerts" : list(recent_alerts)[:20],
            "flows"  : list(recent_flows)[:20]
        }, default=str))

        # Keep alive with heartbeat
        while True:
            await asyncio.sleep(1)
            await websocket.send_text(json.dumps({
                "type"  : "heartbeat",
                "stats" : dict(stats),
                "time"  : datetime.now().strftime("%H:%M:%S")
            }))

    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
        logger.info(f"📡 Dashboard disconnected ({len(connected_clients)} client(s))")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if websocket in connected_clients:
            connected_clients.remove(websocket)


# ─────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=False)