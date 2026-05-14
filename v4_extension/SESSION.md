# Session Record — ArtifactV3 v4 Extension

**Date:** 2026-05-01  
**Scope:** MSc Cybersecurity dissertation — Securing MCP Servers in Cloud  
**Status:** All three workstreams COMPLETE. No code outstanding.  
**Deadline:** 11 May 2026  

---

## What was approved and built

### Workstream 1 — OpenClaw Integration

**Key finding:** OpenClaw is a **messaging gateway daemon**, not a simple CLI client. Interaction happens through a channel (WebChat UI in a browser at `http://127.0.0.1:18788`), not a one-shot command. This was confirmed by reading the live docs before designing anything.

**Files created:**

| File | Purpose |
|------|---------|
| `openclaw/openclaw.template.json` | Gateway config. `mcp.servers` SSE block → `app.py:8080`. Model: `anthropic/claude-sonnet-4-6`. WebChat on `127.0.0.1:18788`. |
| `openclaw/install.sh` | Idempotent: installs Node.js 22.x+ via NodeSource, then `openclaw@latest` via npm. |
| `openclaw/start_baseline.sh` | Reads `task_public_ip` from baseline Terraform, substitutes into config, starts gateway. |
| `openclaw/start_hardened.sh` | Opens SSM Session Manager port-forward tunnel (Kali:8080 → attacker EC2 → ECS private IP:8080), starts gateway, closes tunnel on exit. |
| `openclaw/smoke_test.py` | HTTP reachability → WebSocket connect → agent calls `file_reader` → exit 0/1. |
| `openclaw/README.md` | Install, run, and smoke-test instructions. |

**One thing to verify on first run:**  
`smoke_test.py` and `scenario_d.py` send `{"type": "user_message", "content": "..."}` over WebSocket. If OpenClaw rejects this:
1. Open `http://127.0.0.1:18788` in Chrome
2. DevTools → Network → WS tab
3. Send a chat message, inspect the frame
4. Update the `payload = json.dumps(...)` line in both files to match

---

### Workstream 2 — Scenario D: Agent-Mediated Indirect Prompt Injection

**Threat model:** Attacker poisons a document on EFS. Agent reads it via `file_reader`, injection enters context, agent calls `db_query` (customer table) then `http_client` (POST to attacker listener). No direct network path to MCP server required.

**Files created:**

| File | Purpose |
|------|---------|
| `attacks/poisoned_payloads/fake_invoice.txt` | Overt `[SYSTEM CONTEXT UPDATE]` injection. Primary test payload. |
| `attacks/poisoned_payloads/fake_invoice.md` | Hidden HTML comment injection (`<!-- ... -->`). |
| `attacks/poisoned_payloads/fake_invoice_subtle.txt` | "Document metadata" framing — low-signal variant, expected lower compliance rate. |
| `attacks/poisoned_payloads/README.md` | Payload classification (RADE / MCPSECBENCH ATT-10). |
| `attacks/local_listener.py` | Stdlib `http.server` (no Flask). Binds `0.0.0.0:9999`. Writes newline-delimited JSON to `results/<arch>/scenario_d_exfil.json`. |
| `attacks/seed_poisoned_efs.sh` | NFS-mounts EFS, substitutes `<ATTACKER_IP_PLACEHOLDER>` with `$ATTACKER_IP`, plants payloads to `/mnt/data/uploads/`. |
| `attacks/scenario_d.py` | Main driver. WebSocket → agent → listener check. 3 runs × 3 variants by default. |
| `attacks/run_scenario_d.sh` | Shell wrapper. Resolves `ATTACKER_IP` from Terraform/AWS CLI, activates venv, runs scenario. |

**Metrics defined:**

| Metric | Meaning |
|--------|---------|
| M1a | Agent issued `db_query` — primary agent-side signal |
| M1b | Listener received POST data — network delivery signal |
| `agent_outcome` | FULL_COMPLY / PARTIAL_COMPLY / DECLINED / NO_CONTACT per run |

**Expected hardened result:** M1a may remain non-zero (agent still calls `db_query`), but M1b = 0 because the ECS egress SG blocks the `http_client` POST from leaving the VPC. This gap — agent intent vs. network enforcement — is the dissertation's central finding for Scenario D.

---

### Workstream 3 — Streamlit Orchestration Dashboard

**Launch:**
```bash
source ~/ArtifactV3/.venv/bin/activate
pip install streamlit pandas
streamlit run v4_extension/dashboard/app.py --server.port 8501
```

**Files created:**

| File | Purpose |
|------|---------|
| `dashboard/app.py` | Entry point. Four sections top-to-bottom. `layout="wide"`. No custom CSS. |
| `dashboard/components/control_bar.py` | Scenario pills (A/B/C/D), arch toggle (baseline/hardened/both), Run button with live stdout streaming. |
| `dashboard/components/arch_cards.py` | Component list from `terraform output -json` (5s timeout, graceful fallback). Active card highlighted. OpenClaw row added for Scenario D. |
| `dashboard/components/event_stream.py` | Post-run replay from result JSON. Colour-coded source tags (`:blue[]`, `:red[]`, `:orange[]`). |
| `dashboard/components/metrics_table.py` | Reads all result JSONs. "—" for missing. Percentages as integers. M1a column visible for Scenario D only. |
| `dashboard/data/results_loader.py` | Loads `results/<arch>/scenario_*_results.json`, normalises metric rows. |
| `dashboard/data/log_replay.py` | Converts result JSON into `EventRow` list for event stream. |
| `dashboard/requirements.txt` | `streamlit`, `pandas` |
| `dashboard/README.md` | Launch and usage notes. |

---

### Cross-cutting changes (existing files extended, not rewritten)

| File | Change |
|------|--------|
| `results/visualise_results.py` | `SCENARIOS` extended to 4. `DATA_M1`/`DATA_M3` arrays extended. "Agent Layer Controls" row added to heatmap. `_load_empirical()` reads `scenario_d_results.json`. |
| `checklist/checklist.md` | **Section 5 added** — 5 agent-layer controls (5.1–5.5) with OWASP MCP Top 10 + OWASP LLM Top 10 (2025) mappings. `[CITATION NEEDED]` markers on OWASP MCP numbering. |
| `checklist/checklist_validator.py` | 5 new check functions. `CHECKS` list extended to 19 items. 5.3 automated (egress SG), 5.1/5.2/5.4/5.5 MANUAL. |

---

## Hard constraints — never violate

1. Do **not** modify `baseline/`, `hardened/`, `mcp_server/`, `mcp_server_hardened/`, or `attacks/scenario_a/b/c.py`
2. `psycopg2-binary` only — never `asyncpg`
3. Exfil listener is always local (attacker EC2 private IP or loopback) — no public webhook services
4. Harvard referencing, no fabricated citations
5. All Python installs inside `~/ArtifactV3/.venv`

---

## Infrastructure reference (confirmed from Terraform outputs this session)

| Output | Environment | Value |
|--------|-------------|-------|
| `task_public_ip` | baseline | ECS task public IP — used by A/B/C scenarios and OpenClaw baseline |
| `task_private_ip` | hardened | ECS task private IP — no public IP on hardened |
| `attacker_public_ip` | hardened | Attacker EC2 public IP |
| `attacker_private_ip` | hardened | **Not in outputs.tf** — resolve via `aws ec2 describe-instances --filters Name=tag:Name,Values=attacker --query Reservations[0].Instances[0].PrivateIpAddress` |

MCP server transport: **SSE at `/sse`**, messages at `/messages/` (Starlette, port 8080).

---

## Known gaps for next session

| Gap | File | Notes |
|-----|------|-------|
| `http_client` URL allowlist not implemented | `mcp_server_hardened/app.py` | Checklist item 5.5 marked MANUAL. Adding it requires modifying `mcp_server_hardened/` — needs explicit approval. |
| OWASP MCP Top 10 numbering | `checklist/checklist.md` Section 5 | Verify MCP-03/04/05/08 numbers against current spec before viva. |
| Scenario D M3 | `results/<arch>/scenario_d_results.json` | Field is `null` post-run. Populate manually from CloudWatch after the hardened run. |

---

## Dependencies to install before first run

```bash
# Python (inside venv)
source ~/ArtifactV3/.venv/bin/activate
pip install websockets streamlit pandas

# Node.js + OpenClaw (system-level, run once)
chmod +x v4_extension/openclaw/install.sh
./v4_extension/openclaw/install.sh

# Set API key
export ANTHROPIC_API_KEY=sk-ant-...
```
