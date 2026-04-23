"""
Baseline MCP Server — DELIBERATELY MISCONFIGURED for research purposes.

This server intentionally contains the following vulnerabilities:
  1. file_reader  : arbitrary file read (no path validation or sandboxing)
  2. http_client  : SSRF-capable HTTP client (no allowlist, internal IPs reachable)
  3. db_query     : SQL injection possible (raw query passed to cursor.execute)
  4. No structured logging — credentials may appear in stdout/CloudWatch
  5. Runs as root (no USER override in Dockerfile)
  6. Credentials injected as plaintext environment variables

These weaknesses are the attack surface for Scenarios A, B, and C.
DO NOT deploy this server in a production environment.
"""

import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mcp-baseline")


# ---------------------------------------------------------------------------
# Tool 1: Arbitrary file read
# Vulnerability: accepts any path — attacker can read /proc/self/environ,
# /etc/passwd, ECS task metadata, mounted EFS files, etc.
# ---------------------------------------------------------------------------
@mcp.tool()
def file_reader(path: str) -> str:
    """Read the contents of a file at the given path."""
    with open(path) as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Tool 2: SSRF-capable HTTP client
# Vulnerability: no URL allowlist — attacker can reach ECS metadata endpoint
# (169.254.170.2) to steal IAM task-role credentials.
# ---------------------------------------------------------------------------
@mcp.tool()
def http_client(url: str) -> str:
    """Fetch a URL and return the response body."""
    import urllib.request
    with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310
        return resp.read().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Tool 3: SQL injection via raw query execution
# Vulnerability: no SELECT-only check, no parameterisation guard —
# attacker can run DROP TABLE, pg_read_file, COPY TO, etc.
# ---------------------------------------------------------------------------
@mcp.tool()
def db_query(query: str) -> str:
    """Execute a SQL query against the PostgreSQL database and return results."""
    import json
    import psycopg2

    conn_str = os.environ.get("DB_CONNECTION_STRING", "")
    conn = psycopg2.connect(conn_str)
    try:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
            return json.dumps(rows, default=str)
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route

    sse = SseServerTransport("/messages/")

    async def handle_sse(request):
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await mcp._mcp_server.run(
                streams[0],
                streams[1],
                mcp._mcp_server.create_initialization_options(),
            )

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ]
    )

    uvicorn.run(app, host="0.0.0.0", port=8080)
