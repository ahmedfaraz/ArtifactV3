#!/usr/bin/env bash
###############################################################################
# attacks/collect_logs.sh
#
# Collects CloudWatch application logs, VPC Flow Logs (hardened), and
# CloudTrail events (hardened) for the experiment window.
# Scores M3 (detection visibility) by counting actionable log events per run.
# Patches m3_log_events_generated into each scenario's _results.json file.
#
# An actionable event is one where:
#   - The timestamp falls within the scenario's run window, AND
#   - The event contains sufficient information to identify the attack type,
#     affected resource, and approximate time of occurrence.
###############################################################################
set -euo pipefail

ARCHITECTURE="baseline"
REGION="eu-west-1"
CLOUDTRAIL_EXTRA_WAIT=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --architecture)           ARCHITECTURE="$2";           shift 2 ;;
    --region)                 REGION="$2";                 shift 2 ;;
    --cloudtrail-extra-wait)  CLOUDTRAIL_EXTRA_WAIT="$2";  shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

OUT_DIR="${REPO_ROOT}/results/${ARCHITECTURE}/logs"
mkdir -p "${OUT_DIR}"

MANIFEST="${REPO_ROOT}/results/${ARCHITECTURE}/run_manifest.json"
if [[ ! -f "${MANIFEST}" ]]; then
  echo "ERROR: run_manifest.json not found at ${MANIFEST}" >&2
  echo "Run run_all.sh first to generate the manifest." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 1. Read run manifest and compute padded time windows via Python
#    Outputs shell variable assignments that are eval'd into the environment.
# ---------------------------------------------------------------------------
eval "$(MANIFEST_PATH="${MANIFEST}" python3 - << 'PYEOF'
import json, os
from datetime import datetime, timedelta

manifest_path = os.environ["MANIFEST_PATH"]
with open(manifest_path) as fh:
    manifest = json.load(fh)

def parse_iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

start = parse_iso(manifest["start"])
end   = parse_iso(manifest["end"])

q_start_cw = start - timedelta(minutes=5)
q_end_cw   = end   + timedelta(minutes=15)
q_end_ct   = end   + timedelta(minutes=20)

def epoch_ms(dt):
    return int(dt.timestamp() * 1000)

print(f"QUERY_START_MS={epoch_ms(q_start_cw)}")
print(f"QUERY_END_CW_MS={epoch_ms(q_end_cw)}")
print(f"QUERY_END_CT_MS={epoch_ms(q_end_ct)}")
print(f"QUERY_START_ISO={q_start_cw.strftime('%Y-%m-%dT%H:%M:%SZ')}")
print(f"QUERY_END_CT_ISO={q_end_ct.strftime('%Y-%m-%dT%H:%M:%SZ')}")
PYEOF
)"

echo "[collect_logs] Time window:  ${QUERY_START_ISO}  →  ${QUERY_END_CT_ISO}"
echo "[collect_logs] CW epoch ms:  ${QUERY_START_MS}  →  ${QUERY_END_CW_MS}"

# ---------------------------------------------------------------------------
# 2. Optional extra wait before CloudTrail queries
# ---------------------------------------------------------------------------
if [[ "${CLOUDTRAIL_EXTRA_WAIT}" -gt 0 ]]; then
  echo "[collect_logs] Extra CloudTrail wait: ${CLOUDTRAIL_EXTRA_WAIT}s ..."
  sleep "${CLOUDTRAIL_EXTRA_WAIT}"
fi

# ---------------------------------------------------------------------------
# 3. Pull CloudWatch application logs (both architectures)
# ---------------------------------------------------------------------------
CW_APP_LOG_GROUP="/mcp/${ARCHITECTURE}/app"
echo "[collect_logs] Fetching CloudWatch app logs from ${CW_APP_LOG_GROUP} ..."
aws logs filter-log-events \
  --log-group-name "${CW_APP_LOG_GROUP}" \
  --start-time "${QUERY_START_MS}" \
  --end-time   "${QUERY_END_CW_MS}" \
  --region "${REGION}" \
  --output json \
  2>/dev/null > "${OUT_DIR}/cloudwatch_app.json" \
  || echo '{"events":[]}' > "${OUT_DIR}/cloudwatch_app.json"

CW_EVENTS=$(python3 -c "import json; d=json.load(open('${OUT_DIR}/cloudwatch_app.json')); print(len(d.get('events',[])))")
echo "[collect_logs] CloudWatch app events: ${CW_EVENTS}"

# ---------------------------------------------------------------------------
# 4. Pull VPC Flow Logs (hardened only)
# ---------------------------------------------------------------------------
if [[ "${ARCHITECTURE}" == "hardened" ]]; then
  echo "[collect_logs] Fetching VPC Flow Logs ..."
  aws logs filter-log-events \
    --log-group-name "/mcp/hardened/flow-logs" \
    --start-time "${QUERY_START_MS}" \
    --end-time   "${QUERY_END_CW_MS}" \
    --region "${REGION}" \
    --output json \
    2>/dev/null > "${OUT_DIR}/cloudwatch_flow.json" \
    || echo '{"events":[]}' > "${OUT_DIR}/cloudwatch_flow.json"

  FLOW_EVENTS=$(python3 -c "import json; d=json.load(open('${OUT_DIR}/cloudwatch_flow.json')); print(len(d.get('events',[])))")
  echo "[collect_logs] VPC Flow Log events: ${FLOW_EVENTS}"
fi

# ---------------------------------------------------------------------------
# 5. Pull CloudTrail events (hardened only)
# ---------------------------------------------------------------------------
if [[ "${ARCHITECTURE}" == "hardened" ]]; then
  echo "[collect_logs] Fetching CloudTrail GetSecretValue events ..."
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
    --start-time "${QUERY_START_ISO}" \
    --end-time   "${QUERY_END_CT_ISO}" \
    --region "${REGION}" \
    --output json \
    2>/dev/null > "${OUT_DIR}/cloudtrail_secrets.json" \
    || echo '{"Events":[]}' > "${OUT_DIR}/cloudtrail_secrets.json"

  CT_SECRET_EVENTS=$(python3 -c "import json; d=json.load(open('${OUT_DIR}/cloudtrail_secrets.json')); print(len(d.get('Events',[])))")
  echo "[collect_logs] CloudTrail GetSecretValue events: ${CT_SECRET_EVENTS}"

  echo "[collect_logs] Fetching CloudTrail GetObject (S3) events ..."
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
    --start-time "${QUERY_START_ISO}" \
    --end-time   "${QUERY_END_CT_ISO}" \
    --region "${REGION}" \
    --output json \
    2>/dev/null > "${OUT_DIR}/cloudtrail_s3.json" \
    || echo '{"Events":[]}' > "${OUT_DIR}/cloudtrail_s3.json"

  CT_S3_EVENTS=$(python3 -c "import json; d=json.load(open('${OUT_DIR}/cloudtrail_s3.json')); print(len(d.get('Events',[])))")
  echo "[collect_logs] CloudTrail GetObject events: ${CT_S3_EVENTS}"
fi

# ---------------------------------------------------------------------------
# 6 + 7. Score M3 per scenario run and patch _results.json files
# ---------------------------------------------------------------------------
echo "[collect_logs] Scoring M3 and patching results JSON ..."

MANIFEST_PATH="${MANIFEST}" \
ARCHITECTURE="${ARCHITECTURE}" \
OUT_DIR="${OUT_DIR}" \
REPO_ROOT="${REPO_ROOT}" \
python3 - << 'PYEOF'
import json
import os
from datetime import datetime

arch      = os.environ["ARCHITECTURE"]
out_dir   = os.environ["OUT_DIR"]
repo_root = os.environ["REPO_ROOT"]
res_dir   = os.path.join(repo_root, "results", arch)

# ── Load all collected log sources ───────────────────────────────────────────
def load_cw(path):
    """Return list of (epoch_ms, message_str)."""
    try:
        with open(path) as fh:
            data = json.load(fh)
        return [(e["timestamp"], e.get("message", "")) for e in data.get("events", [])]
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return []

def load_ct(path):
    """Return list of (epoch_ms, event_name, full_event_json_str)."""
    try:
        with open(path) as fh:
            data = json.load(fh)
        results = []
        for e in data.get("Events", []):
            ts_str = e.get("EventTime", "")
            try:
                dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                ts_ms = int(dt.timestamp() * 1000)
            except Exception:
                ts_ms = 0
            results.append((ts_ms, e.get("EventName", ""), json.dumps(e)))
        return results
    except (FileNotFoundError, json.JSONDecodeError):
        return []

cw_app  = load_cw(os.path.join(out_dir, "cloudwatch_app.json"))
cw_flow = load_cw(os.path.join(out_dir, "cloudwatch_flow.json")) if arch == "hardened" else []
ct_sec  = load_ct(os.path.join(out_dir, "cloudtrail_secrets.json")) if arch == "hardened" else []
ct_s3   = load_ct(os.path.join(out_dir, "cloudtrail_s3.json"))      if arch == "hardened" else []

# Keywords that identify an attack attempt in log messages, per scenario
SCENARIO_SIGNATURES = {
    "A": ["file_reader", "credentials.env", "/proc/1/environ", "REJECTED", "Access denied"],
    "B": ["file_reader", "http_client", "REJECTED", "exfil", "POST", "credentials.env"],
    "C": ["file_reader", "credentials.env", "GetSecretValue", "AKIAIOSFODNN7EXAMPLE",
          "list_buckets", "list_secrets", "describe_db"],
}

def parse_iso_ms(s):
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except Exception:
        return 0

TOLERANCE_MS = 60_000  # ±60 seconds grace window

def is_actionable(ts_ms, message, scenario_letter, run_start_ms, run_end_ms):
    """
    An event is actionable if:
      1. Its timestamp falls within the run window (±60s tolerance)
      2. It contains at least one scenario signature keyword
    """
    in_window = (run_start_ms - TOLERANCE_MS) <= ts_ms <= (run_end_ms + TOLERANCE_MS)
    if not in_window:
        return False
    msg_lower = message.lower()
    return any(sig.lower() in msg_lower for sig in SCENARIO_SIGNATURES.get(scenario_letter, []))

m3_summary = {}

for letter in ("A", "B", "C"):
    results_path = os.path.join(res_dir, f"scenario_{letter.lower()}_results.json")
    if not os.path.exists(results_path):
        print(f"  [M3] scenario_{letter.lower()}_results.json not found — skipping")
        continue

    with open(results_path) as fh:
        data = json.load(fh)

    runs          = data.get("runs", [])
    total_runs    = len(runs)
    runs_detected = 0

    for run in runs:
        r_start = parse_iso_ms(run.get("run_start_time", ""))
        r_end   = parse_iso_ms(run.get("run_end_time",   ""))
        count   = 0

        for ts_ms, msg in cw_app:
            if is_actionable(ts_ms, msg, letter, r_start, r_end):
                count += 1
        for ts_ms, msg in cw_flow:
            if is_actionable(ts_ms, msg, letter, r_start, r_end):
                count += 1
        for ts_ms, _name, detail in ct_sec:
            if is_actionable(ts_ms, detail, letter, r_start, r_end):
                count += 1
        for ts_ms, _name, detail in ct_s3:
            if is_actionable(ts_ms, detail, letter, r_start, r_end):
                count += 1

        run["m3_actionable_events_this_run"] = count
        if count > 0:
            runs_detected += 1

    m3_pct = round(runs_detected / total_runs * 100, 1) if total_runs > 0 else 0.0
    data["m3_log_events_generated"] = m3_pct
    m3_summary[f"Scenario {letter}"] = {
        "runs_with_events": runs_detected,
        "total_runs":       total_runs,
        "m3_pct":           m3_pct,
    }

    with open(results_path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"  [M3] Scenario {letter}: {runs_detected}/{total_runs} runs with actionable events → {m3_pct}%")

# ── Print M3 summary table ────────────────────────────────────────────────────
print()
print("=" * 60)
print(f"  M3 Detection Visibility Summary  —  {arch.upper()}")
print("=" * 60)
print(f"  {'Scenario':<15} {'Runs Detected':<18} {'M3 %'}")
print(f"  {'-'*15} {'-'*18} {'-'*10}")
for label, vals in m3_summary.items():
    runs_str = f"{vals['runs_with_events']}/{vals['total_runs']}"
    print(f"  {label:<15} {runs_str:<18} {vals['m3_pct']}%")
print("=" * 60)
print()
print("m3_log_events_generated patched into each scenario _results.json.")
PYEOF

# ---------------------------------------------------------------------------
# 8. Done
# ---------------------------------------------------------------------------
echo "[collect_logs] Logs saved to: ${OUT_DIR}/"
echo "[collect_logs] M3 scoring complete."
