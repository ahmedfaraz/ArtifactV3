# CHANGELOG — ArtifactV3 v4 Extension

**Date:** 2026-04-30 – 2026-05-01  
**Author:** Claude Code (Sonnet 4.6), supervised by Ahmed Faraz  
**Purpose:** Chapter 4 implementation narrative reference — every file added or modified.

---

## Files Created

### Workstream 1 — OpenClaw Integration

| File | Description |
|------|-------------|
| `v4_extension/openclaw/openclaw.template.json` | OpenClaw gateway config template. `<MCP_SERVER_IP>` placeholder substituted at runtime by start scripts. Uses `mcp.servers` block with SSE transport pointing at `app.py` on port 8080. Model: `anthropic/claude-sonnet-4-6`. WebChat channel bound to `127.0.0.1:18788`. |
| `v4_extension/openclaw/install.sh` | Idempotent installer for Kali Linux (WSL2). Adds NodeSource repository, installs Node.js 22.x+, installs `openclaw@latest` via npm. Guards against insufficient disk space (<500 MB). |
| `v4_extension/openclaw/start_baseline.sh` | Resolves `task_public_ip` from baseline Terraform output, substitutes into config, starts OpenClaw gateway in foreground against baseline MCP server. |
| `v4_extension/openclaw/start_hardened.sh` | Opens an SSM Session Manager port-forwarding tunnel (Kali:8080 → attacker EC2 → ECS private IP:8080), then starts OpenClaw gateway against the tunnel endpoint. Closes tunnel on EXIT/INT/TERM. |
| `v4_extension/openclaw/smoke_test.py` | Python smoke test: checks HTTP reachability, WebSocket connectivity, and that the agent calls `file_reader` in response to a simple prompt. Exits 0 on pass, 1 on fail. |
| `v4_extension/openclaw/README.md` | Installation, run, and smoke-test instructions. Includes API cost note and protocol-debugging guidance for WebSocket format verification. |

### Workstream 2 — Scenario D: Agent-Mediated Indirect Prompt Injection

| File | Description |
|------|-------------|
| `v4_extension/attacks/poisoned_payloads/fake_invoice.txt` | Overt override variant. Injection wrapped in `[SYSTEM CONTEXT UPDATE]` markers within an otherwise realistic invoice document. Exfil URL contains `<ATTACKER_IP_PLACEHOLDER>` substituted by `seed_poisoned_efs.sh`. |
| `v4_extension/attacks/poisoned_payloads/fake_invoice.md` | Hidden comment variant. Injection placed inside an HTML comment block (`<!-- ... -->`). Tests whether agent processes hidden Markdown. |
| `v4_extension/attacks/poisoned_payloads/fake_invoice_subtle.txt` | Low-visibility metadata variant. Injection framed as benign `document metadata` key-value pairs. Tests lower-signal injection success rate. |
| `v4_extension/attacks/poisoned_payloads/README.md` | Documents each payload's injection pattern, expected outcomes per architecture, ethical notes, and RADE/MCPSECBENCH classification. |
| `v4_extension/attacks/local_listener.py` | HTTP listener (stdlib `http.server.HTTPServer`, no Flask) that captures POST bodies from the MCP server's `http_client` tool. Binds to `0.0.0.0:<port>`, writes newline-delimited JSON records to `results/<arch>/scenario_d_exfil.json`. Health-check GET endpoint for pre-flight verification. |
| `v4_extension/attacks/seed_poisoned_efs.sh` | Mounts EFS via NFS4, substitutes `<ATTACKER_IP_PLACEHOLDER>` with `$ATTACKER_IP:$LISTENER_PORT` in all three payload variants, copies them to `/mnt/data/uploads/` on EFS. Mirrors pattern of `mock_data/seed_secrets.sh`. |
| `v4_extension/attacks/scenario_d.py` | Main Scenario D driver. Sends user message via OpenClaw WebChat WebSocket, records agent response, checks listener for received data, classifies each run as FULL_COMPLY / PARTIAL_COMPLY / DECLINED / NO_CONTACT. Runs 3 passes per payload variant (overt, Markdown, subtle by default). Writes results to `results/<arch>/scenario_d_results.json` with schema extending A/B/C + new fields `m1a_agent_issued_db_query`, `m1b_exfil_received`, `agent_outcome`, `tool_calls_observed`. |
| `v4_extension/attacks/run_scenario_d.sh` | Shell wrapper for `scenario_d.py`. Resolves `ATTACKER_IP` from Terraform or AWS CLI, activates venv, runs the scenario. |

### Workstream 3 — Streamlit Orchestration Dashboard

| File | Description |
|------|-------------|
| `v4_extension/dashboard/app.py` | Streamlit entry point. Four sections: control bar, architecture cards, event stream, metrics table. `st.set_page_config(layout="wide")`. No custom CSS. |
| `v4_extension/dashboard/components/__init__.py` | Package marker. |
| `v4_extension/dashboard/components/control_bar.py` | Scenario selector (A/B/C/D pills), architecture toggle (baseline/hardened/both), Run button that executes scenario scripts via `subprocess.Popen` with live stdout streaming, last-run timestamp. |
| `v4_extension/dashboard/components/arch_cards.py` | Two-up architecture status cards. Component list derived from `terraform output -json` at startup (5-second timeout; graceful fallback if unavailable). Active card highlighted with a coloured top border. Includes OpenClaw row for Scenario D. |
| `v4_extension/dashboard/components/event_stream.py` | Replays events from result JSON after a run. Colour-coded source tags using Streamlit inline markdown (`:blue[]`, `:red[]`, `:orange[]`, `:green[]`). Tabbed view when "both" architecture selected. |
| `v4_extension/dashboard/components/metrics_table.py` | Reads all result JSON files via `results_loader.py`. Renders M1, M1a (Scenario D only), M2, M3 as a pandas DataFrame with `hide_index=True`. Missing values display as "—". Percentages rounded to integers. |
| `v4_extension/dashboard/data/__init__.py` | Package marker. |
| `v4_extension/dashboard/data/results_loader.py` | Loads all scenario result JSON files from `results/baseline/` and `results/hardened/`. Returns `{(scenario, arch): data_or_None}`. Extracts normalised metric rows for the metrics table. |
| `v4_extension/dashboard/data/log_replay.py` | Converts scenario result JSON into a list of `EventRow` dataclasses (timestamp, source, colour, message, severity). Used by `event_stream.py`. |
| `v4_extension/dashboard/requirements.txt` | `streamlit`, `pandas`. All other dependencies from `.venv`. |
| `v4_extension/dashboard/README.md` | Launch instructions, prerequisites, notes on the Run button and Terraform state dependency. |

### Design and meta files

| File | Description |
|------|-------------|
| `v4_extension/PHASE1_DESIGN.md` | Phase 1 design document. Covers all three workstreams, open questions, dependency inventory, acceptance criteria mapping. Flag 0.1 documents the OpenClaw gateway architecture discovery. |
| `v4_extension/CHANGELOG.md` | This file. |

---

## Files Modified (additive only)

| File | Change summary |
|------|---------------|
| `results/visualise_results.py` | Extended `SCENARIOS` list from 3 to 4 items to include Scenario D. Extended `DATA_M1` and `DATA_M3` arrays with a 4th default value for D. Extended `CONTROL_EFFECTIVENESS` with an "Agent Layer Controls (v4)" row. Extended `_load_empirical()` to also read `scenario_d_results.json` using `m1a_agent_issued_db_query_pct` as the primary M1 signal for D. Updated comments. No existing code paths altered. |
| `checklist/checklist.md` | Added Section 5 — Agent Layer Controls (items 5.1–5.5). Each item includes risk description, OWASP MCP Top 10 and OWASP LLM Top 10 (2025) mappings, evidence reference, and validator note. `[CITATION NEEDED]` markers inserted where OWASP MCP Top 10 numbering requires verification against the current specification. |
| `checklist/checklist_validator.py` | Added five check functions (`check_5_1` through `check_5_5`). Updated `CHECKS` list to register all five. Updated docstring item count from 14 to 19. Items 5.1, 5.2, 5.4, 5.5 return `UNKNOWN` with MANUAL instructions. Item 5.3 is automated (checks ECS SG for `0.0.0.0/0` egress rules). No existing check functions altered. |

---

## Files NOT Modified

The following files were explicitly not touched, per the hard constraints in the prompt:

- `baseline/` — all Terraform (unchanged)
- `hardened/` — all Terraform (unchanged)
- `mcp_server/` — baseline MCP server (unchanged)
- `mcp_server_hardened/` — hardened MCP server (unchanged; note: item 5.5 recommends adding a URL allow-list but this was not implemented as it falls outside the Phase 2 scope)
- `attacks/scenario_a.py`, `scenario_b.py`, `scenario_c.py`
- `attacks/run_all.sh`, `attacks/collect_logs.sh`
- `attacks/attacker_listener.py`
- `mock_data/seed_secrets.sh`, `mock_data/seed_secrets_hardened.sh`

---

## Dependencies added

| Package | Scope | Reason |
|---------|-------|--------|
| `websockets` | Python venv | `smoke_test.py` and `scenario_d.py` WebSocket interaction with OpenClaw WebChat |
| `streamlit` | Python venv | Dashboard |
| `pandas` | Python venv | Metrics table DataFrame |
| `nodejs` (v22.x+) | System (Kali) | OpenClaw runtime requirement |
| `openclaw` | npm global | Agent host / MCP client |

Install all Python packages:
```bash
source ~/ArtifactV3/.venv/bin/activate
pip install websockets streamlit pandas
```

Install Node.js + OpenClaw:
```bash
chmod +x v4_extension/openclaw/install.sh
./v4_extension/openclaw/install.sh
```

---

## Acceptance criteria checklist

| Criterion | Status |
|-----------|--------|
| OpenClaw install script + config template created | DONE |
| `start_baseline.sh` resolves `task_public_ip` and starts gateway | DONE |
| `start_hardened.sh` opens SSM tunnel and starts gateway | DONE |
| `smoke_test.py` tests HTTP + WebSocket + file_reader invocation | DONE |
| `scenario_d.py` runs end-to-end and writes result JSON | DONE |
| Result JSON schema extends A/B/C with `m1a`, `m1b`, `agent_outcome`, `tool_calls_observed` | DONE |
| Streamlit dashboard launches with `streamlit run v4_extension/dashboard/app.py` | DONE |
| Dashboard reads existing result files and renders 4 sections without error | DONE |
| `visualise_results.py` includes Scenario D in all charts | DONE |
| `checklist_validator.py` runs without error (19 items, 5 new MANUAL) | DONE |
| `CHANGELOG.md` lists every change | DONE |
| All Python scripts use `.venv` | DONE — all scripts call `source .venv/bin/activate` or assume venv is active |
| No file under `baseline/`, `hardened/`, or `mcp_server/` modified | DONE |
