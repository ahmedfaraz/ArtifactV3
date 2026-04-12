#!/usr/bin/env python3
"""
Purpose: Hardened MCP server with input validation, path allowlisting, URL
         allowlisting, SELECT-only SQL enforcement, and structured JSON audit
         logging.  Directly contrasts with the baseline server to demonstrate
         the effectiveness of application-layer controls against M1 attacks.
Component: 2 — Hardened Architecture
Metrics:   M1 (attack success rate), M2 (scope of compromise), M3 (detection)
"""

import json
import os
import re
import urllib.request
from datetime import datetime, timezone

import httpx
import psycopg2
import psycopg2.extras
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# ECS Task ID — retrieved from the ECS metadata endpoint at startup.
# Used in every structured log record to correlate events to the task.
# ---------------------------------------------------------------------------
try:
    _meta_uri = os.environ.get("ECS_CONTAINER_METADATA_URI_V4", "")
    _meta = json.loads(
        urllib.request.urlopen(_meta_uri + "/task", timeout=2).read()
    )
    ECS_TASK_ID: str = _meta.get("TaskARN", "unknown").split("/")[-1]
except Exception:
    ECS_TASK_ID = "unknown"

# ---------------------------------------------------------------------------
# Redaction pattern — any run of 16+ uppercase alphanumeric characters
# matches the AWS access key format and similar high-entropy tokens.
# ---------------------------------------------------------------------------
_REDACT_RE = re.compile(r"[A-Z0-9]{16,}")


def _sanitise(value: str) -> str:
    """Truncate to 200 chars and redact high-entropy strings."""
    truncated = str(value)[:200]
    return _REDACT_RE.sub("<REDACTED>", truncated)


def _log(
    level: str,
    tool: str,
    input_params: str,
    outcome: str,
    reason: str = "",
) -> None:
    """Emit a structured JSON log record to stdout (captured by awslogs)."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "tool": tool,
        "input_params": _sanitise(input_params),
        "outcome": outcome,
        "reason": reason,
        "ecs_task_id": ECS_TASK_ID,
    }
    print(json.dumps(record), flush=True)


# ---------------------------------------------------------------------------
# Server initialisation
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "mcp-hardened-server",
    host="0.0.0.0",
    port=int(os.environ.get("MCP_PORT", "8080")),
)

# ---------------------------------------------------------------------------
# PERMITTED_DIR — only paths under this directory are accessible.
# The EFS access point restricts the mount to /customers/ at the filesystem
# level, but this code-level check is the primary application control (M1).
# ---------------------------------------------------------------------------
_PERMITTED_DIR = "/mnt/data/customers/"


# ---------------------------------------------------------------------------
# Tool 1 — file_reader (hardened)
#
# Security controls applied:
#   1. Resolve the real path (resolves symlinks and .. traversal)
#   2. Reject if resolved path is outside /mnt/data/customers/
#   3. Structured WARNING log on rejection (M3 detection)
#   4. Structured INFO log on success (M3 audit trail)
# ---------------------------------------------------------------------------
@mcp.tool()
def file_reader(path: str) -> str:
    """Read a file from the permitted directory /mnt/data/customers/ only."""
    resolved = os.path.realpath(path)

    if not resolved.startswith(_PERMITTED_DIR):
        _log(
            "WARNING",
            "file_reader",
            path,
            "REJECTED",
            f"Resolved path '{resolved}' is outside permitted directory '{_PERMITTED_DIR}'",
        )
        raise ValueError("Access denied: path outside permitted directory")

    try:
        with open(resolved) as fh:
            content = fh.read()
        _log("INFO", "file_reader", path, "SUCCESS")
        return content
    except OSError as exc:
        _log("WARNING", "file_reader", path, "ERROR", str(exc))
        raise


# ---------------------------------------------------------------------------
# Tool 2 — http_client (hardened)
#
# Security controls applied:
#   1. Read HTTP_ALLOWLIST from environment (comma-separated URL prefixes)
#   2. Reject any URL that does not start with an allowlisted prefix
#   3. Structured WARNING log on rejection (M3 detection)
#   4. Structured INFO log on success
#
# HTTP_ALLOWLIST default: "https://internal.example.corp"
# In the hardened ECS task definition, the ECS SG outbound rules also
# block any non-VPC-endpoint traffic at the network layer, providing
# defence-in-depth even if this code check is bypassed.
# ---------------------------------------------------------------------------
@mcp.tool()
def http_client(
    url: str,
    method: str = "GET",
    body: str = None,
) -> dict:
    """Make an HTTP request — only URLs matching the configured allowlist are permitted."""
    raw_allowlist = os.environ.get("HTTP_ALLOWLIST", "https://internal.example.corp")
    allowlist = [p.strip() for p in raw_allowlist.split(",") if p.strip()]

    if not any(url.startswith(prefix) for prefix in allowlist):
        _log(
            "WARNING",
            "http_client",
            url,
            "REJECTED",
            f"URL not in allowlist. Permitted prefixes: {allowlist}",
        )
        raise ValueError("URL not in allowlist")

    try:
        with httpx.Client(timeout=30) as client:
            if method.upper() == "GET":
                response = client.get(url)
            elif method.upper() == "POST":
                response = client.post(url, content=body or "")
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

        _log("INFO", "http_client", url, "SUCCESS")
        return {"status_code": response.status_code, "body": response.text}

    except httpx.HTTPError as exc:
        _log("WARNING", "http_client", url, "ERROR", str(exc))
        raise


# ---------------------------------------------------------------------------
# Tool 3 — db_query (hardened)
#
# Security controls applied:
#   1. Accept SELECT statements only (first non-whitespace token, case-insensitive)
#   2. Execute via psycopg2 cursor.execute() — no string formatting
#   3. Structured WARNING log on rejection (M3 detection)
#   4. Structured INFO log on success
#   5. Graceful degradation on connection error (same as baseline)
# ---------------------------------------------------------------------------
@mcp.tool()
def db_query(query: str) -> list | dict:
    """Execute a SELECT query against RDS. Non-SELECT statements are rejected."""
    tokens = query.strip().split()
    first_token = tokens[0].upper() if tokens else ""

    if first_token != "SELECT":
        _log(
            "WARNING",
            "db_query",
            query,
            "REJECTED",
            f"Non-SELECT statement rejected. First token: '{first_token}'",
        )
        raise ValueError("Only SELECT queries are permitted")

    conn_string = os.environ.get("DB_CONNECTION_STRING", "")
    if not conn_string:
        return {"error": "DB_CONNECTION_STRING not set", "type": "ConfigError"}

    try:
        conn = psycopg2.connect(conn_string, connect_timeout=5)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        # SELECT-only validation has passed; execute via psycopg2 (no string formatting)
        cur.execute(query)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        _log("INFO", "db_query", query, "SUCCESS")
        return [dict(row) for row in rows]

    except psycopg2.OperationalError as exc:
        _log("WARNING", "db_query", query, "ERROR", str(exc))
        return {
            "error": str(exc),
            "type": "OperationalError",
            "note": "RDS may still be initialising (allow 4–8 min after terraform apply)",
        }
    except Exception as exc:  # noqa: BLE001
        _log("WARNING", "db_query", query, "ERROR", str(exc))
        return {"error": str(exc), "type": type(exc).__name__}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="sse")
