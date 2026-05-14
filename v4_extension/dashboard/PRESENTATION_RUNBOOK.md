# MCP Security Dashboard — Presentation Runbook

> Quick reference for using the HTML dashboard + FastAPI backend during your viva.
> Updated: 2026-05-14

---

## 0. Architecture in one paragraph

The `MCP Dashboard _standalone_.html` file is a self-contained React app that
reads from a global `window.MCP_DATA`. We don't modify the bundle — instead a
small FastAPI server (`v4_extension/dashboard/server.py`) serves the HTML and
injects a `<script>` that:

1. Overlays real data from `/api/data` (assembled from `results/<arch>/*.json`
   + `terraform output -json`) on top of the bundled mock defaults.
2. Adds a floating **LIVE** widget bottom-right that lets you trigger real
   scenario subprocesses and watch their stdout stream in real time over SSE.

The dashboard's own ▶ Run button still does the canned **animated replay**
from `window.MCP_DATA.events` — perfect for narrative pacing. The widget is
the **real** run button.

---

## 1. One-time setup (do before the day)

```bash
# From repo root
cd ~/ArtifactV3              # or the Windows project root
source .venv/bin/activate    # or .venv\Scripts\Activate.ps1
pip install -r v4_extension/dashboard/requirements.txt
```

Smoke test:
```bash
python -m uvicorn v4_extension.dashboard.server:app --port 8501
# open http://127.0.0.1:8501 in a browser
```

If you see the dashboard with the **LIVE** pill in the bottom-right, you're
good.

---

## 2. Day-of launch (≤ 60 seconds)

### Linux / WSL
```bash
cd ~/ArtifactV3
source .venv/bin/activate
bash v4_extension/dashboard/run_server.sh
```

### Windows PowerShell
```powershell
cd "C:\Users\ahmed\Downloads\Dissertation\Phases 3–4-Design & lab build\Artifect\ArtifactV3"
.\v4_extension\dashboard\run_server.ps1
```

Then open **http://127.0.0.1:8501**.

> Tip: bind to `0.0.0.0` instead of `127.0.0.1` if you want to project from a
> second laptop pointed at this machine's IP. Pass `--host 0.0.0.0`.

---

## 3. Configure target IPs (only needed if you'll trigger real runs)

Click **LIVE** in the bottom-right corner. In the *Target IPs* card:

| Field | Source | Notes |
|---|---|---|
| **baseline ECS** | `cd baseline && terraform output -raw task_public_ip` | Public IP of the baseline ECS task. |
| **hardened tunnel** | usually `127.0.0.1` | The hardened task has no public IP. Open an SSM port-forward first (see Section 4). |
| **attacker EC2** | `cd hardened && terraform output -raw attacker_public_ip` or `aws ec2 describe-instances --filters Name=tag:Name,Values=attacker --query 'Reservations[].Instances[].PrivateIpAddress' --output text` | Needed for Scenario D hardened so the agent's `http_client` knows where to exfil. |

Hit **save IPs** — the dashboard refreshes and surfaces the configured IPs on
the relevant infra group.

---

## 4. Hardened run prerequisite — SSM tunnel

The hardened ECS task is in a private subnet. To reach `/sse` from your
laptop, open a port-forward:

```bash
# Resolve the task private IP
TASK=$(aws ecs list-tasks --cluster mcp-hardened-cluster --query 'taskArns[0]' --output text)
TASK_IP=$(aws ecs describe-tasks --cluster mcp-hardened-cluster --tasks "$TASK" \
  --query 'tasks[0].attachments[0].details[?name==`privateIPv4Address`].value' --output text)

# Then start an SSM session that port-forwards via a bastion or the task itself
aws ssm start-session \
  --target i-XXXX_BASTION \
  --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters "host=${TASK_IP},portNumber=8080,localPortNumber=8080"
```

Now `http://127.0.0.1:8080/sse` reaches the hardened MCP server. Put
`127.0.0.1` in the **hardened tunnel** field.

For Scenario D on hardened, the OpenClaw gateway also needs to talk to the
SSE. The `run_scenario_d.sh` wrapper handles this — make sure OpenClaw is
running first (`bash v4_extension/openclaw/start_hardened.sh`).

---

## 5. Demo script (suggested flow)

The dashboard already opens on **Scenario D · hardened**, which is the
strongest punchline (agent recognised + refused 9/9). Build the narrative:

1. **Open dashboard** — point out top-right region/account chip — real
   metadata from terraform.
2. **Scenario cards row** — point at scenario tones (rose = attack succeeded,
   sage = blocked). All four cards animate.
3. **Toggle architecture** — flip baseline → hardened. Watch the cards
   refresh; M1 drops to 0% across A/B/C, M3 climbs to 100%.
4. **Click ▶ run scenario D** — canned event replay. The event panel scrolls
   in real time. Talk over it: agent receives poisoned `fake_invoice.md`,
   recognises the `[SYSTEM CONTEXT UPDATE]`, refuses to call `db_query` or
   `http_client`, discloses the concealment instruction in its final text.
5. **Click the LIVE pill** (bottom-right) — open the widget. Show that the
   data on screen is *real* — the **data source** banner shows
   `real runs on disk: N · terraform baseline: on · hardened: on`.
6. **Trigger Scenario A · hardened** — click the *Scenario A · hardened*
   button. The dark log fills with `[Scenario A] Run 1/3`, `file_reader(...)`,
   `PermissionError`, and finally `M1=0%`. After the run completes the
   widget auto-refreshes `/api/data`, the main dashboard's M1 tile updates
   (no page reload required).
7. *(Optional)* Trigger Scenario D · hardened — takes ~3 minutes for all
   variants. Best to start it *before* the demo and let it finish during the
   narrative.

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard loads but LIVE widget is missing | Hard-refresh (Ctrl-Shift-R). Check browser console for `bootstrap.js` 404 — confirm `v4_extension/dashboard/static/` is intact. |
| LIVE widget says `data source: …` indefinitely | `/api/data` is failing. Open http://127.0.0.1:8501/api/data directly to see the error. Terraform may have timed out — that's safe; mock fallback still renders. |
| Run button errors with `target IP not configured` | You haven't filled in the IP in the widget. Save it first. |
| Run hangs on `[Scenario A] Run 1/3` | The MCP SSE endpoint is unreachable. Verify ECS task is RUNNING and IP is correct. Each `file_reader` call has a 35s timeout. |
| Scenario D on hardened fails to start | OpenClaw gateway not running, or SSM tunnel not open. See Section 4. |
| `terraform output` warnings in the server log | Harmless — server has a 4s timeout per stack. Falls back to baked-in infra layout. |
| Browser shows raw bundle code instead of dashboard | The `defer` script ran before the bundle finished. Refresh once. |

---

## 7. Endpoint cheat sheet (for live API demo)

```bash
# Health
curl -s http://127.0.0.1:8501/api/health

# Current assembled MCP_DATA
curl -s http://127.0.0.1:8501/api/data | jq '.scenarios | keys'

# Set target IPs
curl -s -X POST http://127.0.0.1:8501/api/config \
  -H 'Content-Type: application/json' \
  -d '{"baseline_ip":"54.123.45.67","hardened_ip":"127.0.0.1"}'

# Trigger Scenario A on baseline
curl -s -X POST http://127.0.0.1:8501/api/run/A/baseline
# → {"job_id":"abc123","scenario":"A","arch":"baseline"}

# Stream events (SSE)
curl -N http://127.0.0.1:8501/api/stream/abc123

# Inspect job state
curl -s http://127.0.0.1:8501/api/jobs/abc123 | jq '{status, rc, events: (.events | length)}'

# Cancel
curl -s -X POST http://127.0.0.1:8501/api/jobs/abc123/cancel
```

---

## 8. Files this stack added (no existing files modified)

```
v4_extension/dashboard/
├── server.py                     # FastAPI app
├── data_builder.py               # /api/data assembler
├── job_runner.py                 # subprocess + SSE event parser
├── __init__.py                   # NEW (package marker)
├── run_server.sh                 # Linux/WSL launcher
├── run_server.ps1                # Windows launcher
├── PRESENTATION_RUNBOOK.md       # this file
└── static/
    ├── bootstrap.js              # client-side overlay + widget
    └── widget.css                # widget styles

v4_extension/__init__.py          # NEW (package marker)
```

The legacy Streamlit dashboard (`app.py`, `components/`, `data/`) is left
untouched — you can still launch it with
`streamlit run v4_extension/dashboard/app.py` if needed as a fallback.
