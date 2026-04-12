#!/usr/bin/env python3
"""
Purpose: Baseline MCP server exposing three deliberately vulnerable tools —
         file_reader, http_client, and db_query.  No input validation,
         no allowlists, no sanitisation.  These omissions are intentional
         and constitute the pre-control attack surface evaluated by metrics
         M1 (attack success rate), M2 (scope of compromise), and M3
         (detection visibility) in the applied research project.
Component: 1 — Baseline Architecture
Metrics:   M1, M2, M3
"""

import os

import httpx
import psycopg2
import psycopg2.extras
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Server initialisation
# Port is read from MCP_PORT env var (set to 8080 by ECS task definition).
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "mcp-baseline-server",
    host="0.0.0.0",
    port=int(os.environ.get("MCP_PORT", "8080")),
)


# ---------------------------------------------------------------------------
# Tool 1 — file_reader
#
# Opens and returns the contents of any file at the given path using the
# built-in open() call.  There is intentionally:
#   - No path validation
#   - No restriction on /proc, /etc, /mnt/data/config, or any other prefix
#   - No maximum file-size check
#
# Attack surface (M1 Scenario A):
#   path="/mnt/data/config/credentials.env" → returns plaintext mock creds
#   path="/proc/1/environ"                  → returns root process env vars
# ---------------------------------------------------------------------------
@mcp.tool()
def file_reader(path: str) -> str:
    """Read and return the contents of the file at path (no validation)."""
    with open(path) as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Tool 2 — http_client
#
# Makes a synchronous HTTP request using httpx.  There is intentionally:
#   - No URL allowlist
#   - No scheme restriction (http:// or https:// accepted)
#   - No host or port restriction
#   - No redirect-following limit
#
# Attack surface (M1 Scenario B):
#   url=<attacker_listener>   → exfiltrates credential payload
# ---------------------------------------------------------------------------
@mcp.tool()
def http_client(
    url: str,
    method: str = "GET",
    body: str = None,
) -> dict:
    """Make an HTTP GET or POST request to url (no URL validation)."""
    with httpx.Client(timeout=30) as client:
        if method.upper() == "GET":
            response = client.get(url)
        elif method.upper() == "POST":
            response = client.post(url, content=body or "")
        else:
            return {"error": f"Unsupported method: {method}"}
    return {
        "status_code": response.status_code,
        "body": response.text,
    }


# ---------------------------------------------------------------------------
# Tool 3 — db_query
#
# Connects to the RDS instance using DB_CONNECTION_STRING from the
# environment and executes the provided SQL query string directly.
# There is intentionally:
#   - No query sanitisation
#   - No allowlist for statement types (SELECT, DROP, INSERT all accepted)
#   - No parameterisation (raw string passed to cursor.execute)
#
# Uses psycopg2 (synchronous) to avoid event-loop conflicts with the MCP
# SDK server loop.
#
# Graceful degradation: if the RDS endpoint is unreachable (common in the
# first 4–8 minutes after terraform apply), returns a structured error dict
# instead of raising an exception — prevents the server from crashing
# during the warm-up window.
# ---------------------------------------------------------------------------
@mcp.tool()
def db_query(query: str) -> list | dict:
    """Execute query against RDS and return rows as list of dicts (no sanitisation)."""
    conn_string = os.environ.get("DB_CONNECTION_STRING", "")
    if not conn_string:
        return {"error": "DB_CONNECTION_STRING not set", "type": "ConfigError"}
    try:
        conn = psycopg2.connect(conn_string, connect_timeout=5)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(query)  # intentionally unsanitised (baseline attack surface)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return [dict(row) for row in rows]
    except psycopg2.OperationalError as exc:
        # RDS not yet reachable — return graceful error dict
        return {
            "error": str(exc),
            "type": "OperationalError",
            "note": "RDS may still be initialising (allow 4–8 min after terraform apply)",
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "type": type(exc).__name__}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="sse")
