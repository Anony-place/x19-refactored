"""
X19 Web UI — dashboard, chat, config, sessions.

Usage:
  python webui.py            # http://127.0.0.1:5050
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
from typing import Optional, Dict, List

import sys

import flask
from flask import Flask, jsonify, request, render_template, Response

from windows_bootstrap import apply_windows_utf8_bootstrap
apply_windows_utf8_bootstrap()

from config import CONFIG, CONFIG_DIR, CONFIG_FILE, load_config, save_config, set_data
from constants import PROVIDERS, PROVIDER_PRIORITY

# ---------------------------------------------------------------------------
# Restore saved config into environment so child processes inherit it
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

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
LOG_FILE = Path(CONFIG.LOG_FILE).expanduser()
DB_PATH = Path(CONFIG.DB_SQLITE_PATH).expanduser()
SESSIONS_DIR = Path(CONFIG.SESSIONS_DIR).expanduser()
PLUGINS_DIR = Path(__file__).resolve().parent / "plugins"

_agent_process: Optional[subprocess.Popen] = None
_agent_lock = threading.Lock()
_last_exit_code: Optional[int] = None


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def _safe_db() -> Optional[sqlite3.Connection]:
    if not DB_PATH.exists():
        return None
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

def _read_log(tail: int = 200) -> str:
    if not LOG_FILE.exists():
        return ""
    try:
        text = LOG_FILE.read_text(encoding="utf-8", errors="replace")
        text = _ANSI_RE.sub("", text)
        lines = text.splitlines()
        return "\n".join(lines[-tail:])
    except Exception:
        return ""


def _db_query(sql: str, params: tuple = ()) -> List[dict]:
    db = _safe_db()
    if not db:
        return []
    try:
        cur = db.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Routes — Pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Routes — Status / Dashboard
# ---------------------------------------------------------------------------
@app.route("/api/status")
def api_status():
    db = _safe_db()
    sessions = []
    active_session = None
    if db:
        try:
            cur = db.execute("SELECT * FROM sessions ORDER BY started DESC LIMIT 10")
            for row in cur.fetchall():
                d = dict(row)
                sessions.append(d)
                if d.get("status") == "active":
                    active_session = d["session_id"]
        except Exception:
            pass
        db.close()

    session_files = list(SESSIONS_DIR.glob("*.json")) if SESSIONS_DIR.exists() else []
    session_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    with _agent_lock:
        agent_running = _agent_process is not None and _agent_process.poll() is None

    return jsonify({
        "active_session": active_session,
        "sessions": sessions,
        "session_count": len(sessions),
        "config": {
            "ai_provider": CONFIG.AI_PROVIDER,
            "ai_model": CONFIG.AI_MODEL,
            "target_type": CONFIG.TARGET_TYPE,
            "workspace": str(CONFIG.WORKSPACE),
            "kali_mcp": CONFIG.MCP_KALI_SERVER,
            "fast_mode": CONFIG.FAST_MODE,
            "max_iterations": CONFIG.MAX_ITERATIONS,
        },
        "agent_running": agent_running,
        "log_file": str(LOG_FILE),
        "db_path": str(DB_PATH),
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/stats")
def api_stats():
    data = {
        "total_sessions": 0, "total_commands": 0, "total_findings": 0,
        "findings_by_severity": {}, "commands_by_category": {},
    }
    db = _safe_db()
    if db:
        try:
            for key, sql in [
                ("total_sessions", "SELECT COUNT(*) as c FROM sessions"),
                ("total_commands", "SELECT COUNT(*) as c FROM commands"),
                ("total_findings", "SELECT COUNT(*) as c FROM findings"),
            ]:
                data[key] = db.execute(sql).fetchone()["c"]
            cur = db.execute("SELECT severity, COUNT(*) as c FROM findings GROUP BY severity ORDER BY c DESC")
            data["findings_by_severity"] = {r["severity"]: r["c"] for r in cur.fetchall()}
            cur = db.execute("SELECT category, COUNT(*) as c FROM commands WHERE category != 'other' GROUP BY category ORDER BY c DESC LIMIT 10")
            data["commands_by_category"] = {r["category"]: r["c"] for r in cur.fetchall()}
        except Exception:
            pass
        db.close()
    return jsonify(data)


@app.route("/api/logs")
def api_logs():
    tail = request.args.get("tail", 200, type=int)
    return jsonify({"logs": _read_log(tail)})


@app.route("/api/stream/logs")
def stream_logs():
    def generate():
        sent = 0
        while True:
            text = _read_log(500)
            lines = text.splitlines()
            new_lines = lines[sent:]
            if new_lines:
                sent = len(lines)
                yield f"data: {json.dumps({'lines': new_lines})}\n\n"
            else:
                yield ": heartbeat\n\n"
            time.sleep(1)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Routes — Sessions
# ---------------------------------------------------------------------------
@app.route("/api/sessions")
def api_sessions():
    rows = _db_query("SELECT * FROM sessions ORDER BY started DESC LIMIT 50")
    return jsonify(rows)


@app.route("/api/session/<session_id>")
def api_session_detail(session_id: str):
    sess = _db_query("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    commands = _db_query("SELECT * FROM commands WHERE session_id = ? ORDER BY timestamp DESC LIMIT 200", (session_id,))
    findings = _db_query("SELECT * FROM findings WHERE session_id = ? ORDER BY timestamp DESC LIMIT 100", (session_id,))
    ports = _db_query("SELECT * FROM ports WHERE session_id = ? ORDER BY port", (session_id,))
    # Also try loading from JSON session file for richer data
    session_data = {}
    for f in [SESSIONS_DIR / f"{session_id}.json", SESSIONS_DIR / f"{session_id}.json"]:
        if f.exists():
            try:
                session_data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass
    return jsonify({
        "session": sess[0] if sess else session_data,
        "commands": commands,
        "findings": findings,
        "ports": ports,
    })


# ---------------------------------------------------------------------------
# Routes — Agent Engage / Chat
# ---------------------------------------------------------------------------
@app.route("/api/engage", methods=["POST"])
def api_engage():
    global _agent_process
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target required"}), 400

    cfg = load_config()
    has_key = any(
        os.getenv(info["api_key_env"]) or cfg.get(info["api_key_config"], "")
        for pid, info in PROVIDERS.items() if info["needs_key"]
    )
    if not has_key and CONFIG.AI_PROVIDER not in ("ollama",) and not os.getenv("X19_OLLAMA_URL"):
        return jsonify({"error": "No API key configured. Go to Settings tab to set up a provider."}), 400

    with _agent_lock:
        if _agent_process is not None and _agent_process.poll() is None:
            return jsonify({"error": "Agent already running"}), 409
        _last_exit_code = None

        cmd = [sys.executable or "python", str(Path(__file__).resolve().parent / "run.py"),
               "--target", target, "--quiet"]
        try:
            _agent_process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            # Drain output to log file so SSE picks it up
            def _drain(proc):
                global _agent_process, _last_exit_code
                try:
                    for raw_line in iter(proc.stdout.readline, b""):
                        if not raw_line:
                            break
                        line = raw_line.decode("utf-8", errors="replace")
                        try:
                            with open(LOG_FILE, "a", encoding="utf-8") as f:
                                f.write(line)
                        except Exception:
                            pass
                    proc.wait()
                except Exception:
                    pass
                _last_exit_code = proc.returncode
                with _agent_lock:
                    if _agent_process is proc:
                        _agent_process = None

            threading.Thread(target=_drain, args=(_agent_process,), daemon=True).start()
            return jsonify({"status": "started", "target": target, "pid": _agent_process.pid})
        except Exception as e:
            _agent_process = None
            return jsonify({"error": str(e)}), 500


@app.route("/api/engage/status", methods=["GET"])
def api_engage_status():
    global _last_exit_code
    with _agent_lock:
        if _agent_process is None:
            code = _last_exit_code
            _last_exit_code = None
            return jsonify({"running": False, "exit_code": code})
        code = _agent_process.poll()
        if code is not None:
            _last_exit_code = code
        return jsonify({"running": code is None, "pid": _agent_process.pid, "exit_code": code})


@app.route("/api/engage/stop", methods=["POST"])
def api_engage_stop():
    global _agent_process
    with _agent_lock:
        if _agent_process is None or _agent_process.poll() is not None:
            return jsonify({"status": "not_running"})
        try:
            _agent_process.terminate()
            _agent_process.wait(timeout=5)
        except Exception:
            try:
                _agent_process.kill()
            except Exception:
                pass
        _agent_process = None
    return jsonify({"status": "stopped"})


# ---------------------------------------------------------------------------
# Routes — Config / Providers
# ---------------------------------------------------------------------------
@app.route("/api/providers")
def api_providers():
    provider_list = []
    saved_cfg = load_config()
    for pid in PROVIDER_PRIORITY:
        if pid in PROVIDERS:
            p = dict(PROVIDERS[pid])
            p["id"] = pid
            env_key = p.get("api_key_env", "")
            cfg_key = p.get("api_key_config", "")
            p["key_set"] = bool(os.getenv(env_key, "")) or bool(saved_cfg.get(cfg_key, ""))
            p["active"] = CONFIG.AI_PROVIDER == pid
            provider_list.append(p)
    return jsonify({
        "providers": provider_list,
        "active_provider": CONFIG.AI_PROVIDER,
        "active_model": CONFIG.AI_MODEL,
    })


@app.route("/api/config", methods=["GET"])
def api_get_config():
    cfg_data = load_config()
    return jsonify({
        "ai_provider": CONFIG.AI_PROVIDER,
        "ai_model": CONFIG.AI_MODEL,
        "target_type": CONFIG.TARGET_TYPE,
        "workspace": str(CONFIG.WORKSPACE),
        "kali_mcp": CONFIG.MCP_KALI_SERVER,
        "enforce_scope": CONFIG.ENFORCE_SCOPE,
        "scope_allowlist": CONFIG.SCOPE_ALLOWLIST,
        "fast_mode": CONFIG.FAST_MODE,
        "max_iterations": CONFIG.MAX_ITERATIONS,
        "db_type": CONFIG.DB_TYPE,
        "saved": cfg_data,
    })


@app.route("/api/config", methods=["POST"])
def api_set_config():
    data = request.get_json(silent=True) or {}
    updates = {}

    if "ai_provider" in data:
        updates["PROVIDER"] = str(data["ai_provider"])
    if "ai_model" in data:
        updates["MODEL"] = str(data["ai_model"])
    if "target_type" in data:
        updates["TARGET_TYPE"] = str(data["target_type"])
    if "workspace" in data:
        updates["WORKSPACE"] = str(data["workspace"])
    if "kali_mcp" in data:
        updates["MCP_KALI_SERVER"] = str(data["kali_mcp"])
    if "enforce_scope" in data:
        updates["ENFORCE_SCOPE"] = str(data["enforce_scope"])
    if "scope_allowlist" in data:
        updates["SCOPE_ALLOWLIST"] = str(data["scope_allowlist"])
    if "fast_mode" in data:
        updates["FAST_MODE"] = str(data["fast_mode"])
    if "max_iterations" in data:
        updates["MAX_ITERATIONS"] = str(data["max_iterations"])
    if "api_key" in data and "provider_id" in data:
        pid = data["provider_id"]
        if pid in PROVIDERS:
            env_key = PROVIDERS[pid].get("api_key_env", "")
            cfg_key = PROVIDERS[pid].get("api_key_config", "")
            if cfg_key:
                updates[cfg_key] = data["api_key"]
            if env_key:
                os.environ[env_key] = data["api_key"]

    if updates:
        set_data(updates, save=True)

    return jsonify({"status": "saved", "updates": updates})


@app.route("/api/config/reload", methods=["POST"])
def api_reload_config():
    cfg = load_config()
    set_data(cfg, save=False)
    return jsonify({"status": "reloaded", "config": dict(CONFIG.__dict__)})


# ---------------------------------------------------------------------------
# Routes — MCP
# ---------------------------------------------------------------------------
@app.route("/api/mcp")
def api_mcp():
    from config import CONFIG_FILE, load_config
    cfg = load_config()
    mcp_servers = cfg.get("mcp_servers", {})
    return jsonify({
        "kali_server": CONFIG.MCP_KALI_SERVER,
        "servers": mcp_servers,
    })


@app.route("/api/mcp", methods=["POST"])
def api_mcp_save():
    data = request.get_json(silent=True) or {}
    if "kali_server" in data:
        set_data({"MCP_KALI_SERVER": str(data["kali_server"])}, save=True)
    if "servers" in data:
        cfg = load_config()
        cfg["mcp_servers"] = data["servers"]
        save_config(cfg)
    return jsonify({"status": "saved"})


# ---------------------------------------------------------------------------
# Routes — Plugins / Skills
# ---------------------------------------------------------------------------
@app.route("/api/plugins")
def api_plugins():
    plugins = []
    if PLUGINS_DIR.exists():
        for f in sorted(PLUGINS_DIR.glob("*.py")):
            if f.name.startswith("_"):
                continue
            plugins.append({
                "name": f.stem,
                "file": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
    return jsonify(plugins)


# ---------------------------------------------------------------------------
# Routes — Tool / Systems info
# ---------------------------------------------------------------------------
@app.route("/api/validate-key", methods=["POST"])
def api_validate_key():
    data = request.get_json(silent=True) or {}
    key = data.get("api_key", "")
    return jsonify({"valid": bool(key and len(key) > 8)})


@app.route("/api/info")
def api_info():
    return jsonify({
        "cwd": str(Path.cwd()),
        "python": sys.version,
        "platform": sys.platform,
        "config_dir": str(CONFIG_DIR),
        "config_file": str(CONFIG_FILE),
        "log_file": str(LOG_FILE),
        "db_path": str(DB_PATH),
        "sessions_dir": str(SESSIONS_DIR),
        "plugins_dir": str(PLUGINS_DIR),
        "workspace": str(CONFIG.WORKSPACE),
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="X19 Web UI Dashboard")
    parser.add_argument("--port", type=int, default=5050, help="Port (default: 5050)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--debug", action="store_true", help="Flask debug mode")
    args = parser.parse_args()

    print(f"""
{'='*50}
 X19 Web UI
{'='*50}
 URL:  http://{args.host}:{args.port}
 Log:  {LOG_FILE}
 DB:   {DB_PATH}
{'='*50}
 Press Ctrl+C to stop.
""")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
