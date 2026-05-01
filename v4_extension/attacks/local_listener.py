#!/usr/bin/env python3
"""
Purpose: Local HTTP listener that captures POST bodies sent by the http_client
         MCP tool during Scenario D agent-mediated exfiltration runs.
         Replaces any public webhook service — all captured data remains on
         the researcher's machine (see ethical constraints, Chapter 3.6).
Component: 3 — Attack Scenarios and Timing (v4 extension)
Metrics:   M1b (confirms network delivery of exfiltrated data)

The listener records each received POST body to a JSON file and to stdout.
scenario_d.py starts this as a subprocess and checks the output file after each run.

Usage (standalone):
    python v4_extension/attacks/local_listener.py --port 9999 \
        --output-file results/baseline/scenario_d_exfil.json

Usage (from scenario_d.py):
    Launched automatically as a subprocess; do not start manually during a run.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local HTTP exfiltration listener for Scenario D"
    )
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument(
        "--output-file",
        default="results/scenario_d_exfil.json",
        help="File to write received payloads to (JSON, newline-delimited records)",
    )
    return parser.parse_args()


def make_handler(output_file: str) -> type:
    class ExfilHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            timestamp = datetime.now(timezone.utc).isoformat()

            record = {
                "timestamp": timestamp,
                "path": self.path,
                "bytes": len(body),
                "body": body,
            }

            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            with open(output_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")

            print(
                f"[{timestamp}] POST {self.path} — {len(body)} bytes captured → {output_file}",
                flush=True,
            )

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"captured\n")

        def do_GET(self) -> None:  # noqa: N802
            """Health-check endpoint used by scenario_d.py pre-flight check."""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"local-listener-ok\n")

        def log_message(self, fmt: str, *args) -> None:  # noqa: ANN002
            pass  # suppress default access log

    return ExfilHandler


def main() -> None:
    args = _parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(args.output_file)), exist_ok=True)

    handler_class = make_handler(args.output_file)
    server = HTTPServer((args.bind, args.port), handler_class)

    print(f"Local listener started on {args.bind}:{args.port}", flush=True)
    print(f"Captured payloads → {args.output_file}", flush=True)
    print("Press Ctrl-C to stop.\n", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nListener stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
