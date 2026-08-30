"""
X19 Web UI — Next-Gen Autonomous Cognitive Pentesting Dashboard.
Features: Live Interactive Attack Graph, Swarm Agent Monitor, Real-time SSE Stream,
PoC Findings Triage, and Self-Adapting Diagnostics.

Usage:
  python webui.py            # http://0.0.0.0:5050
"""

import json
import os
import re
import subprocess
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

import sys
import flask
from flask import Flask, jsonify, request, render_template, Response

from windows_bootstrap import apply_windows_utf8_bootstrap
apply_windows_utf8_bootstrap()

from config import CONFIG, CONFIG_DIR, CONFIG_FILE, load_config, save_config, set_data
from constants import PROVIDERS, PROVIDER_PRIORITY
from providers import make_ai
from brain.coordinator import SwarmCoordinator
from learning.self_adaptation import SelfAdaptationEngine
from reporting.report_generator import SecurityReportGenerator

# ---------------------------------------------------------------------------
# Restore saved config into environment
# ---------------------------------------------------------------------------
_cfg = load_config()
if _cfg:
    set_data(_cfg, save=False)

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder=Path(__file__).resolve().parent / "webui_templates",
    static_folder=Path(__file__).resolve().parent / "webui_templates",
)

LOG_FILE = Path(CONFIG.LOG_FILE).expanduser()
DB_PATH = Path(CONFIG.DB_SQLITE_PATH).expanduser()

# Global Swarm Coordinator & Self-Adaptation Engine
global_coordinator = SwarmCoordinator()
self_adaptation_engine = SelfAdaptationEngine()


# ---------------------------------------------------------------------------
# Report Export Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/report/markdown")
def api_report_markdown():
    summary = global_coordinator.get_summary()
    generator = SecurityReportGenerator(
        target=global_coordinator.target or "127.0.0.1",
        findings=global_coordinator.verified_findings
    )
    md_content = generator.generate_markdown()
    return Response(
        md_content,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=x19_report_{global_coordinator.target or 'local'}.md"}
    )


@app.route("/api/report/html")
def api_report_html():
    generator = SecurityReportGenerator(
        target=global_coordinator.target or "127.0.0.1",
        findings=global_coordinator.verified_findings
    )
    html_content = generator.generate_html()
    return Response(
        html_content,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename=x19_report_{global_coordinator.target or 'local'}.html"}
    )


@app.route("/api/report/json")
def api_report_json():
    generator = SecurityReportGenerator(
        target=global_coordinator.target or "127.0.0.1",
        findings=global_coordinator.verified_findings
    )
    return Response(
        generator.generate_json(),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=x19_report_{global_coordinator.target or 'local'}.json"}
    )


# ---------------------------------------------------------------------------
# Existing Legacy & Global Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "swarm_running": global_coordinator.is_running,
        "active_target": global_coordinator.target
    })


@app.route("/api/stats")
def api_stats():
    return jsonify(global_coordinator.get_summary()["stats"])


@app.route("/api/providers")
def api_providers():
    return jsonify({
        "providers": PROVIDERS,
        "priority": PROVIDER_PRIORITY,
        "current_provider": getattr(CONFIG, "AI_PROVIDER", "openrouter"),
        "current_model": getattr(CONFIG, "AI_MODEL", "meta-llama/llama-3.3-70b-instruct")
    })


@app.route("/api/config", methods=["GET"])
def api_get_config():
    cfg = load_config()
    return jsonify(cfg)


@app.route("/api/config", methods=["POST"])
def api_save_config():
    data = request.get_json() or {}
    save_config(data)
    set_data(data, save=False)
    return jsonify({"status": "saved"})


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json() or {}
    message = data.get("message", "").strip()
    system_prompt = data.get("system", "You are X19 General AI Assistant — an expert software engineer and security analyst helping the user debug code, analyze command outputs, and craft payloads.").strip()
    provider = data.get("provider", "").strip()

    if not message:
        return jsonify({"error": "Message is required"}), 400

    try:
        ai = make_ai(provider if provider in PROVIDERS else "")
        response_text = ai.chat(system_prompt, message)
        return jsonify({
            "response": response_text,
            "provider": ai.name(),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Next-Gen Swarm & Cognitive Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/swarm/start", methods=["POST"])
def api_swarm_start():
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400

    global_coordinator.set_target(target)
    global_coordinator.start_mission_pipeline(target)
    return jsonify({
        "status": "started",
        "target": target,
        "timestamp": time.time()
    })


@app.route("/api/swarm/status", methods=["GET"])
def api_swarm_status():
    return jsonify(global_coordinator.get_summary())


@app.route("/api/swarm/stop", methods=["POST"])
def api_swarm_stop():
    global_coordinator.stop_mission()
    return jsonify({"status": "stopped"})


@app.route("/api/swarm/graph", methods=["GET"])
def api_swarm_graph():
    return jsonify(global_coordinator.get_attack_graph_d3())


@app.route("/api/swarm/stream")
def api_swarm_stream():
    def event_stream():
        q: List[Dict[str, Any]] = []
        lock = threading.Lock()

        def listener(event):
            with lock:
                q.append(event)

        global_coordinator.subscribe_events(listener)

        # Initial heartbeat
        yield f"data: {json.dumps({'type': 'init', 'data': global_coordinator.get_summary()})}\n\n"

        while True:
            events_to_send = []
            with lock:
                if q:
                    events_to_send = list(q)
                    q.clear()

            for evt in events_to_send:
                yield f"data: {json.dumps(evt)}\n\n"

            time.sleep(0.5)

    return Response(event_stream(), mimetype="text/event-stream")


@app.route("/api/self-diagnostics", methods=["GET"])
def api_self_diagnostics():
    res = self_adaptation_engine.run_self_diagnostics()
    lessons = self_adaptation_engine.get_lessons_for_target("all")
    res["lessons_learned"] = lessons
    return jsonify(res)


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="X19 Web UI Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind")
    parser.add_argument("--port", type=int, default=5050, help="Port to listen on")
    args = parser.parse_args()

    print(f"[*] Starting X19 Next-Gen Web UI at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
