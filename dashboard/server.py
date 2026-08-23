#!/usr/bin/env python3
"""
LinuxGuard dashboard server.

Serves the static dashboard (index.html), exposes /metrics.json by
reading the JSON file the C watchdog daemon writes, /audit.json by
tailing the daemon's audit log, and a /kill endpoint the dashboard's
kill-switch button uses to send a signal to a flagged process.
No external dependencies - just Python's standard library.

Usage:
    python3 server.py [port] [metrics_path] [audit_log_path]
    defaults: port=8080,
              metrics_path=/tmp/linuxguard_metrics.json,
              audit_log_path=/tmp/linuxguard_audit.log
"""

import http.server
import socketserver
import json
import os
import signal
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
METRICS_PATH = sys.argv[2] if len(sys.argv) > 2 else "/tmp/linuxguard_metrics.json"
AUDIT_PATH = sys.argv[3] if len(sys.argv) > 3 else "/tmp/linuxguard_audit.log"
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))

AUDIT_TAIL_LINES = 200  # how many recent audit entries to serve

ALLOWED_SIGNALS = {
    "SIGTERM": signal.SIGTERM,
    "SIGKILL": signal.SIGKILL,
    "SIGINT": signal.SIGINT,
}


def append_audit(event_type, pid, name, detail):
    """Best-effort write so the kill action itself shows up in the log."""
    try:
        with open(AUDIT_PATH, "a") as f:
            f.write(json.dumps({
                "ts": int(time.time()),
                "type": event_type,
                "pid": pid,
                "name": name,
                "detail": detail,
            }) + "\n")
    except OSError:
        pass


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DASHBOARD_DIR, **kwargs)

    def do_GET(self):
        if self.path.startswith("/metrics.json"):
            self.serve_metrics()
        elif self.path.startswith("/audit.json"):
            self.serve_audit()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith("/kill"):
            self.handle_kill()
        else:
            self.send_response(404)
            self.end_headers()

    def serve_metrics(self):
        try:
            with open(METRICS_PATH, "rb") as f:
                body = f.read()
            self._send_json_bytes(200, body)
        except FileNotFoundError:
            self._send_json(503, {"error": "watchdog daemon not running yet"})

    def serve_audit(self):
        try:
            with open(AUDIT_PATH, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            self._send_json(200, {"events": []})
            return

        events = []
        for line in lines[-AUDIT_TAIL_LINES:]:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        events.reverse()  # most recent first
        self._send_json(200, {"events": events})

    def handle_kill(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            pid = int(payload["pid"])
            sig_name = payload.get("signal", "SIGTERM")
            name = payload.get("name", "")
        except (ValueError, KeyError, json.JSONDecodeError):
            self._send_json(400, {"ok": False, "error": "bad request body"})
            return

        if sig_name not in ALLOWED_SIGNALS:
            self._send_json(400, {"ok": False, "error": f"signal not allowed: {sig_name}"})
            return

        # Guard rails: never let the dashboard kill init, the kernel, or itself.
        if pid <= 1 or pid == os.getpid():
            self._send_json(400, {"ok": False, "error": "refusing to signal that pid"})
            return

        try:
            os.kill(pid, ALLOWED_SIGNALS[sig_name])
            append_audit("kill_action", pid, name, f"sent {sig_name} via dashboard")
            self._send_json(200, {"ok": True, "pid": pid, "signal": sig_name})
        except ProcessLookupError:
            self._send_json(404, {"ok": False, "error": "no such process"})
        except PermissionError:
            self._send_json(403, {"ok": False, "error": "permission denied (try running the server with sufficient privileges)"})

    def _send_json(self, status, obj):
        self._send_json_bytes(status, json.dumps(obj).encode())

    def _send_json_bytes(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # keep console quiet; comment out to debug


if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"LinuxGuard dashboard: http://localhost:{PORT}")
        print(f"Reading metrics from: {METRICS_PATH}")
        print(f"Reading audit log from: {AUDIT_PATH}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")
