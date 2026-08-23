#!/usr/bin/env python3
"""
LinuxGuard dashboard server.

Serves the static dashboard (index.html) and exposes /metrics.json by
reading the JSON file the C watchdog daemon writes. No external
dependencies - just Python's standard library, so it runs anywhere.

Usage:
    python3 server.py [port] [metrics_path]
    defaults: port=8080, metrics_path=/tmp/linuxguard_metrics.json
"""

import http.server
import socketserver
import os
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
METRICS_PATH = sys.argv[2] if len(sys.argv) > 2 else "/tmp/linuxguard_metrics.json"
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DASHBOARD_DIR, **kwargs)

    def do_GET(self):
        if self.path.startswith("/metrics.json"):
            self.serve_metrics()
        else:
            super().do_GET()

    def serve_metrics(self):
        try:
            with open(METRICS_PATH, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "watchdog daemon not running yet"}')

    def log_message(self, format, *args):
        pass  # keep console quiet; comment out to debug


if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"LinuxGuard dashboard: http://localhost:{PORT}")
        print(f"Reading metrics from: {METRICS_PATH}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")
