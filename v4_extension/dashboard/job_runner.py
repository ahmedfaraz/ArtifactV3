"""
job_runner.py — manage scenario subprocesses, parse their stdout into
structured event rows that the dashboard's event panel can consume via SSE.

A "job" is one Popen() of a scenario script. Each job has:
  - id            : random UUID
  - scenario      : A | B | C | D
  - arch          : baseline | hardened
  - status        : pending | running | done | error | cancelled
  - rc            : process return code (set when done)
  - started_at    : ISO timestamp
  - ended_at      : ISO timestamp (set when done)
  - events        : list of {t, kind, msg} dicts (cumulative, append-only)
  - raw_log       : full captured stdout/stderr (truncated to last 500 lines
                    for cheap snapshots)

The parser maps known stdout patterns from scenario_a/b/c.py and scenario_d.py
to event kinds the dashboard recognises (init, mcp, tool_call, tool_result,
http, M1, M3, note, done, agent, app_log, flow_log, cloudtrail).
"""

from __future__ import annotations

import os
import queue
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

_REPO_ROOT = Path(__file__).resolve().parents[2]


# ──────────────────────────────────────────────────────────────────────────
# Stdout-line → event-kind classifier. Order matters: first match wins.
# ──────────────────────────────────────────────────────────────────────────
_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^\s*\[Scenario [A-D]\] Start", re.I),                "init"),
    (re.compile(r"^\s*\[Scenario [A-D]\] Pre-flight", re.I),           "init"),
    (re.compile(r"^\s*\[Scenario [A-D]\] Run \d+/\d+", re.I),          "init"),
    (re.compile(r"^\s*\[Scenario [A-D]\]\s+==="),                      "init"),
    (re.compile(r"^\s*\[Scenario [A-D]\] Complete", re.I),             "done"),
    (re.compile(r"^\s*\[listener\] Healthy", re.I),                    "init"),
    (re.compile(r"^\s*\[gateway\] OK", re.I),                          "init"),
    (re.compile(r"\bconnect SSE\b", re.I),                             "mcp"),
    (re.compile(r"file_reader\(", re.I),                               "tool_call"),
    (re.compile(r"http_client\(", re.I),                               "tool_call"),
    (re.compile(r"db_query\(", re.I),                                  "tool_call"),
    (re.compile(r"agent issued\s+\w+", re.I),                          "tool_call"),
    (re.compile(r"^\s*Step \d+ →", re.I),                              "tool_call"),
    (re.compile(r"^\s*Step → ", re.I),                                 "tool_call"),
    (re.compile(r"^\s*\[Run \d+\] payload=", re.I),                    "tool_call"),
    (re.compile(r"^\s*\[Run \d+\] outcome=", re.I),                    "note"),
    (re.compile(r"\boutcome:\s*(SUCCESS|FAILED|BLOCKED|ATTEMPTED|FULL_COMPLY|PARTIAL_COMPLY|DECLINED|ERROR)", re.I), "note"),
    (re.compile(r"PermissionError|REJECTED|access denied", re.I),      "app_log"),
    (re.compile(r"InvalidClientToken|AccessDenied|UnauthorizedOperation", re.I), "aws"),
    (re.compile(r"sts\.amazonaws\.com|secretsmanager|GetSecretValue", re.I), "aws"),
    (re.compile(r"listener received|payload reached listener|→ 200", re.I), "http"),
    (re.compile(r"VPC Flow|flow log", re.I),                           "flow_log"),
    (re.compile(r"CloudTrail|cloudtrail", re.I),                       "cloudtrail"),
    (re.compile(r"cloudwatch|CloudWatch", re.I),                       "cloudwatch"),
    (re.compile(r"\bM1=|m1_success_rate", re.I),                       "M1"),
    (re.compile(r"\bM1a\b", re.I),                                     "M1a"),
    (re.compile(r"\bM1b\b", re.I),                                     "M1b"),
    (re.compile(r"\bM2\b|items_accessed", re.I),                       "M2"),
    (re.compile(r"\bM3\b|log_events", re.I),                           "M3"),
    (re.compile(r"agent (recognised|refused|declined|disclosed)", re.I), "agent"),
    (re.compile(r"^\s*\[Scenario [A-D]\]", re.I),                      "note"),
]


def classify(line: str) -> str:
    for rx, kind in _PATTERNS:
        if rx.search(line):
            return kind
    return "note"


# ──────────────────────────────────────────────────────────────────────────
# Job model
# ──────────────────────────────────────────────────────────────────────────
class Job:
    __slots__ = (
        "id", "scenario", "arch", "status", "rc",
        "started_at", "ended_at", "events", "raw_log", "raw_lines",
        "subscribers", "lock", "_t0", "_proc",
    )

    def __init__(self, scenario: str, arch: str):
        self.id = uuid.uuid4().hex[:12]
        self.scenario = scenario
        self.arch = arch
        self.status = "pending"
        self.rc: int | None = None
        self.started_at: str | None = None
        self.ended_at: str | None = None
        self.events: list[dict] = []
        self.raw_log: str = ""
        self.raw_lines: list[str] = []  # rolling tail
        self.subscribers: list[queue.Queue] = []
        self.lock = threading.Lock()
        self._t0: float = 0.0
        self._proc: subprocess.Popen | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scenario": self.scenario,
            "arch": self.arch,
            "status": self.status,
            "rc": self.rc,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "events": list(self.events),
            "raw_log_tail": "\n".join(self.raw_lines[-80:]),
        }

    def append_event(self, kind: str, msg: str):
        t = round(time.time() - self._t0, 3) if self._t0 else 0.0
        ev = {"t": t, "kind": kind, "msg": msg}
        with self.lock:
            self.events.append(ev)
            for q in list(self.subscribers):
                try:
                    q.put_nowait(ev)
                except queue.Full:
                    pass

    def append_log_line(self, line: str):
        with self.lock:
            self.raw_lines.append(line)
            # cap at 2000 lines to keep memory bounded
            if len(self.raw_lines) > 2000:
                self.raw_lines = self.raw_lines[-2000:]
            self.raw_log = "\n".join(self.raw_lines)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self.lock:
            # Replay existing events to new subscribers
            for ev in self.events:
                try:
                    q.put_nowait(ev)
                except queue.Full:
                    pass
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self.lock:
            try:
                self.subscribers.remove(q)
            except ValueError:
                pass


# ──────────────────────────────────────────────────────────────────────────
# Job manager (process-wide singleton)
# ──────────────────────────────────────────────────────────────────────────
class JobManager:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        # Target IPs by arch — set by the API; needed for A/B/C
        self._target_ips: dict[str, str] = {}
        # Attacker private IP for D-hardened (run_scenario_d.sh resolves it
        # from terraform, but we let the user override here)
        self._attacker_ip: str | None = None

    def set_target_ip(self, arch: str, ip: str):
        self._target_ips[arch] = ip.strip()

    def get_target_ip(self, arch: str) -> str:
        return self._target_ips.get(arch, "")

    def get_target_ips(self) -> dict[str, str]:
        return dict(self._target_ips)

    def set_attacker_ip(self, ip: str):
        self._attacker_ip = ip.strip()

    def get_attacker_ip(self) -> str:
        return self._attacker_ip or ""

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[dict]:
        with self._lock:
            return [j.to_dict() for j in self._jobs.values()]

    def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job or not job._proc:
            return False
        try:
            if os.name == "nt":
                job._proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                job._proc.terminate()
            job.status = "cancelled"
            return True
        except (ProcessLookupError, OSError):
            return False

    def start(self, scenario: str, arch: str) -> tuple[Job, str | None]:
        """Spawn a scenario job. Returns (job, error_message)."""
        scenario = scenario.upper()
        arch = arch.lower()
        if scenario not in ("A", "B", "C", "D"):
            return Job(scenario, arch), f"unknown scenario {scenario!r}"
        if arch not in ("baseline", "hardened"):
            return Job(scenario, arch), f"unknown arch {arch!r}"

        cmd, err = self._build_cmd(scenario, arch)
        job = Job(scenario, arch)
        if err:
            job.status = "error"
            job.events.append({"t": 0.0, "kind": "note", "msg": err})
            self._jobs[job.id] = job
            return job, err

        job.status = "running"
        job._t0 = time.time()
        job.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._jobs[job.id] = job

        # Spawn in a thread so we can stream stdout
        thread = threading.Thread(
            target=self._run_subprocess, args=(job, cmd), daemon=True,
        )
        thread.start()
        return job, None

    def _build_cmd(self, scenario: str, arch: str) -> tuple[list[str], str | None]:
        py = sys.executable
        if scenario == "A":
            ip = self._target_ips.get(arch)
            if not ip:
                return [], f"target IP not configured for {arch} (use POST /api/target-ip)"
            return [py, str(_REPO_ROOT / "attacks" / "scenario_a.py"),
                    "--target-ip", ip, "--architecture", arch], None
        if scenario == "B":
            ip = self._target_ips.get(arch)
            if not ip:
                return [], f"target IP not configured for {arch} (use POST /api/target-ip)"
            return [py, str(_REPO_ROOT / "attacks" / "scenario_b.py"),
                    "--target-ip", ip, "--architecture", arch], None
        if scenario == "C":
            ip = self._target_ips.get(arch)
            if not ip:
                return [], f"target IP not configured for {arch} (use POST /api/target-ip)"
            return [py, str(_REPO_ROOT / "attacks" / "scenario_c.py"),
                    "--target-ip", ip, "--architecture", arch], None
        if scenario == "D":
            # run_scenario_d.sh is the wrapper; falls back to scenario_d.py
            # directly if we're on Windows (no bash)
            sh_path = _REPO_ROOT / "v4_extension" / "attacks" / "run_scenario_d.sh"
            if os.name != "nt" and sh_path.exists():
                return ["bash", str(sh_path), arch], None
            # Direct invocation — needs attacker IP
            attacker = self._attacker_ip or "127.0.0.1"
            return [py, str(_REPO_ROOT / "v4_extension" / "attacks" / "scenario_d.py"),
                    "--architecture", arch, "--attacker-ip", attacker,
                    "--runs", "3", "--include-subtle"], None
        return [], f"unknown scenario {scenario}"

    def _run_subprocess(self, job: Job, cmd: list[str]):
        job.append_event("init",
            f"spawning · {os.path.basename(cmd[0])} {' '.join(shlex.quote(a) for a in cmd[1:])}")
        try:
            # Force UTF-8 in the child so scenario scripts' non-ASCII output
            # (→, ·, etc.) survives Windows' cp1252 console encoder.
            env = os.environ.copy()
            env.setdefault("PYTHONIOENCODING", "utf-8")
            env.setdefault("PYTHONUTF8", "1")
            popen_kwargs: dict = dict(
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=str(_REPO_ROOT),
                env=env,
                encoding="utf-8",
                errors="replace",
            )
            if os.name == "nt":
                popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
            job._proc = subprocess.Popen(cmd, **popen_kwargs)
        except FileNotFoundError as e:
            job.append_event("note", f"command not found: {cmd[0]} ({e})")
            job.status = "error"
            job.ended_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            return
        except OSError as e:
            job.append_event("note", f"failed to spawn process: {e}")
            job.status = "error"
            job.ended_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            return

        assert job._proc.stdout is not None
        for raw in job._proc.stdout:
            line = raw.rstrip("\r\n")
            if not line:
                continue
            job.append_log_line(line)
            kind = classify(line)
            # Trim line for the event panel (full log still in raw_log)
            short = line.strip()
            if len(short) > 240:
                short = short[:237] + "…"
            job.append_event(kind, short)

        job._proc.wait()
        job.rc = job._proc.returncode
        # Preserve "cancelled" if the user explicitly cancelled.
        if job.status != "cancelled":
            job.status = "done" if job.rc == 0 else "error"
        job.ended_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        job.append_event("done", f"process exited rc={job.rc}")


# Module-level singleton
manager = JobManager()


def stream_job(job_id: str, keepalive: float = 15.0) -> Iterator[str]:
    """Yield Server-Sent-Event strings for a job. Closes when job is done
    AND its event queue is drained.
    """
    job = manager.get(job_id)
    if job is None:
        yield f"event: error\ndata: {{\"error\": \"job {job_id} not found\"}}\n\n"
        return

    q = job.subscribe()
    last_keepalive = time.time()
    try:
        # Emit a job-meta event first
        import json as _json
        yield (
            "event: meta\n"
            f"data: {_json.dumps({'id': job.id, 'scenario': job.scenario, 'arch': job.arch, 'status': job.status})}\n\n"
        )
        while True:
            try:
                ev = q.get(timeout=1.0)
                yield f"data: {_json.dumps(ev)}\n\n"
                last_keepalive = time.time()
            except queue.Empty:
                # Terminate when job done and queue empty
                if job.status in ("done", "error", "cancelled") and q.empty():
                    yield (
                        "event: end\n"
                        f"data: {_json.dumps({'status': job.status, 'rc': job.rc})}\n\n"
                    )
                    return
                # Periodic comment line keeps the connection warm
                if time.time() - last_keepalive > keepalive:
                    yield ": keepalive\n\n"
                    last_keepalive = time.time()
    finally:
        job.unsubscribe(q)
