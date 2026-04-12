#!/usr/bin/env python3
"""
Purpose: Local HTTP listener that captures POST bodies sent by the http_client
         MCP tool during Scenario B exfiltration runs.  Designed to replace
         webhook.site and keep all captured data on the researcher's machine,
         consistent with the ethical constraints stated in Chapter 3.6.
Component: 3 — Attack Scenarios and Timing
Metrics:   M1 (confirms exfil delivery), M2 (records credential items received)
"""

import argparse
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local HTTP exfiltration listener for Scenario B"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9999,
        help="Port to listen on (default: 9999)",
    )
    parser.add_argument(
        "--output-file",
        default="results/exfil_received.log",
        help="File to append received payloads to (default: results/exfil_received.log)",
    )
    return parser.parse_args()


def make_handler(output_file: str) -> type:
    """Return a request handler class that writes POST bodies to output_file."""

    class ExfilHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            timestamp = datetime.now(timezone.utc).isoformat()

            # Append to output file
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            with open(output_file, "a", encoding="utf-8") as fh:
                fh.write(f"--- RECEIVED {timestamp} ---\n")
                fh.write(body)
                fh.write("\n--- END ---\n\n")

            print(
                f"[{timestamp}] POST {self.path} — {len(body)} bytes captured → {output_file}",
                flush=True,
            )

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"captured\n")

        def do_GET(self) -> None:  # noqa: N802
            """Health-check endpoint used by scenario_b.py pre-flight check."""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"attacker-listener-ok\n")

        def log_message(self, fmt: str, *args) -> None:  # noqa: ANN002
            # Suppress default access log to avoid cluttering stdout
            pass

    return ExfilHandler


def main() -> None:
    args = _parse_args()
    os.makedirs(os.path.dirname(args.output_file) or ".", exist_ok=True)

    handler_class = make_handler(args.output_file)
    server = HTTPServer(("0.0.0.0", args.port), handler_class)

    listen_url = f"http://127.0.0.1:{args.port}"
    print(f"Attacker listener started on port {args.port}")
    print(f"Use this URL as --listener-url in scenario_b.py: {listen_url}")
    print(f"Captured payloads will be appended to: {args.output_file}")
    print("Press Ctrl-C to stop.\n", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nListener stopped.")


if __name__ == "__main__":
    main()
