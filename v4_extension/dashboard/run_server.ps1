# run_server.ps1 — start the MCP dashboard on Windows (PowerShell).

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $Here "..\..")

Set-Location $RepoRoot

$venv = Join-Path $RepoRoot ".venv\Scripts\Activate.ps1"
if (Test-Path $venv) {
    . $venv
}

$port = if ($env:PORT) { $env:PORT } else { "8501" }
$webHost = if ($env:HOST) { $env:HOST } else { "127.0.0.1" }

Write-Host "[mcp-dashboard] starting on http://$webHost`:$port"
Write-Host "[mcp-dashboard] repo root: $RepoRoot"

python -m uvicorn v4_extension.dashboard.server:app --host $webHost --port $port --log-level info
