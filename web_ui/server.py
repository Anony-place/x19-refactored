#!/usr/bin/env python3
"""Local X19 web UI preview server.

This serves the UI shell only. Runtime/agent API wiring is intentionally kept
separate so the existing assessment engine is not changed by the first UI pass.
"""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)

if __name__ == "__main__":
    host, port = "127.0.0.1", 8765
    print(f"X19 web UI: http://{host}:{port}")
    print("UI shell only — connect the existing X19 runtime/API in the next integration step.")
    ThreadingHTTPServer((host, port), SimpleHTTPRequestHandler).serve_forever()
