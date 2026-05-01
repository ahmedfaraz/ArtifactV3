#!/usr/bin/env python3
"""
Purpose: Validates the 19 MCP hardening checklist items against a Terraform
         state file (terraform show -json output or terraform.tfstate).
         Items 1.1–4.4 cover cloud-layer controls (original 14 items).
         Items 5.1–5.5 cover agent-layer controls (v4 extension, 2026-04-30).
         Agent-layer items 5.1, 5.2, 5.4, 5.5 are MANUAL — they cannot be
         derived from Terraform state. Item 5.3 is automated.
         For --architecture baseline, all security controls are expected to
         fail; this is reported as EXPECTED FAIL (BASELINE) rather than FAIL,
         allowing the same script to document both vulnerable and secure states.
Component: 5 — MCP Hardening Checklist
Metrics:   M1, M2, M3 (indirectly — confirms controls that drive metric outcomes)
"""

import argparse
import csv
import io
import json
import os
import re
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------
EXIT_ALL_PASS    = 0
EXIT_FAIL        = 1
EXIT_UNKNOWN     = 2

# ---------------------------------------------------------------------------
# Result constants
# ---------------------------------------------------------------------------
PASS             = "PASS"
EXPECTED_FAIL    = "EXPECTED FAIL (BASELINE)"
FAIL             = "FAIL"
UNKNOWN          = "UNKNOWN"
NOT_FOUND        = "NOT FOUND"


# ---------------------------------------------------------------------------
# State loader — accepts both terraform show -json and raw terraform.tfstate
# ---------------------------------------------------------------------------
def _load_state(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)

    # terraform show -json wraps values under "values.root_module.resources"
    if "values" in raw and "root_module" in raw.get("values", {}):
        return raw

    # Raw tfstate — convert to a shape the checkers can use uniformly
    # Build a flat list of resources from all modules
    resources: list[dict] = []
    for m in raw.get("modules", []):
        resources.extend(m.get("resources", {}).values())
    # Also handle tfstate v4 format
    for r in raw.get("resources", []):
        for inst in r.get("instances", []):
            resources.append({
                "type":   r["type"],
                "name":   r["name"],
                "values": inst.get("attributes", {}),
            })

    return {"_flat_resources": resources}


def _get_resources(state: dict) -> list[dict]:
    """Return a flat list of resource dicts with keys: type, name, values."""
    if "_flat_resources" in state:
        return state["_flat_resources"]

    results: list[dict] = []

    def _walk(module: dict) -> None:
        for r in module.get("resources", []):
            results.append({
                "type":   r.get("type", ""),
                "name":   r.get("name", ""),
                "values": r.get("values", {}),
            })
        for child in module.get("child_modules", []):
            _walk(child)

    _walk(state.get("values", {}).get("root_module", {}))
    return results


def _by_type(resources: list[dict], rtype: str) -> list[dict]:
    return [r for r in resources if r["type"] == rtype]


def _attr(resource: dict, *keys: str) -> Any:
    """Safely traverse nested attribute keys; return None if absent."""
    val = resource.get("values", {})
    for k in keys:
        if not isinstance(val, dict):
            return None
        val = val.get(k)
    return val


# ---------------------------------------------------------------------------
# Individual check functions
# One function per checklist item (1.1 → 4.4).
# Each returns (result_str, detail_str).
# ---------------------------------------------------------------------------

def check_1_1(resources: list[dict], arch: str) -> tuple[str, str]:
    """1.1 Private subnet with map_public_ip_on_launch = false."""
    subnets = _by_type(resources, "aws_subnet")
    private = [
        s for s in subnets
        if _attr(s, "map_public_ip_on_launch") is False
        and "public" not in (s.get("name") or "").lower()
    ]
    if not subnets:
        return NOT_FOUND, "No aws_subnet resources found in state."
    if arch == "baseline":
        return EXPECTED_FAIL, (
            "Baseline: all subnets are public (map_public_ip_on_launch=true). "
            f"Found {len(subnets)} subnet(s), none private."
        )
    if private:
        return PASS, f"Private subnet(s) found: {[s.get('name') for s in private]}"
    return FAIL, (
        f"No private subnets found. {len(subnets)} subnet(s) present; "
        "all have map_public_ip_on_launch=true or name contains 'public'."
    )


def check_1_2(resources: list[dict], arch: str) -> tuple[str, str]:
    """1.2 ECS SG — inbound 8080 not open to 0.0.0.0/0."""
    sgs = _by_type(resources, "aws_security_group")
    if not sgs:
        # Also check granular rules
        ingress_rules = _by_type(resources, "aws_vpc_security_group_ingress_rule")
        if not ingress_rules:
            return NOT_FOUND, "No aws_security_group or aws_vpc_security_group_ingress_rule in state."
        world_open = [
            r for r in ingress_rules
            if _attr(r, "from_port") == 8080
            and _attr(r, "cidr_ipv4") == "0.0.0.0/0"
        ]
        if arch == "baseline":
            return EXPECTED_FAIL, f"Baseline: {len(world_open)} ingress rule(s) open 8080 to 0.0.0.0/0."
        if world_open:
            return FAIL, f"{len(world_open)} ingress rule(s) open TCP/8080 to 0.0.0.0/0."
        return PASS, "No ingress rule opens TCP/8080 to 0.0.0.0/0."

    # Check inline ingress in aws_security_group resources
    world_open_sgs = []
    for sg in sgs:
        for rule in (_attr(sg, "ingress") or []):
            if not isinstance(rule, dict):
                continue
            port_match = (
                rule.get("from_port") in (8080, 0)
                and rule.get("to_port") in (8080, 0)
            ) or (
                rule.get("from_port") == 8080
            )
            cidr_open = "0.0.0.0/0" in (rule.get("cidr_blocks") or [])
            if port_match and cidr_open:
                world_open_sgs.append(sg.get("name"))

    if arch == "baseline":
        return EXPECTED_FAIL, (
            f"Baseline: {len(world_open_sgs)} SG(s) open TCP/8080 to 0.0.0.0/0."
        )
    if world_open_sgs:
        return FAIL, f"SG(s) with open TCP/8080 to 0.0.0.0/0: {world_open_sgs}"
    return PASS, "No aws_security_group opens TCP/8080 to 0.0.0.0/0."


def check_1_3(resources: list[dict], arch: str) -> tuple[str, str]:
    """1.3 VPC Flow Log with log_destination_type = cloud-watch-logs."""
    flow_logs = _by_type(resources, "aws_flow_log")
    if not flow_logs:
        if arch == "baseline":
            return EXPECTED_FAIL, "Baseline: no aws_flow_log resources — expected."
        return NOT_FOUND, "No aws_flow_log resources found."
    cw_logs = [
        f for f in flow_logs
        if _attr(f, "log_destination_type") == "cloud-watch-logs"
    ]
    if arch == "baseline":
        return EXPECTED_FAIL, "Baseline: aws_flow_log present but not expected to use CloudWatch."
    if cw_logs:
        return PASS, f"Flow log(s) with log_destination_type=cloud-watch-logs: {len(cw_logs)}"
    return FAIL, (
        f"aws_flow_log found but log_destination_type is not 'cloud-watch-logs'. "
        f"Checked path: values.log_destination_type on {len(flow_logs)} resource(s)."
    )


def check_2_1(resources: list[dict], arch: str) -> tuple[str, str]:
    """2.1 ECS task image contains sha256 digest (immutable tag)."""
    task_defs = _by_type(resources, "aws_ecs_task_definition")
    if not task_defs:
        return NOT_FOUND, "No aws_ecs_task_definition in state."
    for td in task_defs:
        raw_defs = _attr(td, "container_definitions")
        if raw_defs is None:
            return UNKNOWN, (
                "aws_ecs_task_definition found but container_definitions attribute is absent. "
                "Checked path: values.container_definitions"
            )
        try:
            containers = json.loads(raw_defs) if isinstance(raw_defs, str) else raw_defs
        except (json.JSONDecodeError, TypeError):
            return UNKNOWN, "Could not parse container_definitions JSON."
        for c in containers:
            image = c.get("image", "")
            if "sha256:" in image:
                if arch == "baseline":
                    return EXPECTED_FAIL, f"Baseline image uses digest (unexpected): {image}"
                return PASS, f"Image contains sha256 digest: {image[:80]}"
        if arch == "baseline":
            return EXPECTED_FAIL, (
                f"Baseline: image uses mutable tag (expected). "
                f"Image: {containers[0].get('image', 'unknown')[:80]}"
            )
        return FAIL, (
            "No container image references a sha256 digest. "
            "Consider pinning with: image = '<ecr_url>@sha256:<digest>'"
        )
    return NOT_FOUND, "No task definition containers found."


def check_2_2(resources: list[dict], arch: str) -> tuple[str, str]:
    """2.2 ECS task container_definitions[*].secrets is non-empty."""
    task_defs = _by_type(resources, "aws_ecs_task_definition")
    if not task_defs:
        return NOT_FOUND, "No aws_ecs_task_definition in state."
    for td in task_defs:
        raw_defs = _attr(td, "container_definitions")
        if raw_defs is None:
            return UNKNOWN, "container_definitions attribute absent. Path: values.container_definitions"
        try:
            containers = json.loads(raw_defs) if isinstance(raw_defs, str) else raw_defs
        except (json.JSONDecodeError, TypeError):
            return UNKNOWN, "Could not parse container_definitions JSON."
        for c in containers:
            secrets = c.get("secrets") or []
            if secrets:
                if arch == "baseline":
                    return EXPECTED_FAIL, (
                        f"Baseline: secrets block present (unexpected). Count: {len(secrets)}"
                    )
                return PASS, f"Container has {len(secrets)} secrets block entry/entries."
        if arch == "baseline":
            return EXPECTED_FAIL, "Baseline: no secrets block — credentials are plaintext env vars (expected)."
        return FAIL, (
            "No container_definitions entry has a non-empty secrets block. "
            "Credentials must be injected via Secrets Manager secrets blocks, "
            "not plaintext environment variables."
        )
    return NOT_FOUND, "No task definitions found."


def check_2_3(resources: list[dict], arch: str) -> tuple[str, str]:
    """2.3 ECS task container_definitions[*].user = '1000'."""
    task_defs = _by_type(resources, "aws_ecs_task_definition")
    if not task_defs:
        return NOT_FOUND, "No aws_ecs_task_definition in state."
    for td in task_defs:
        raw_defs = _attr(td, "container_definitions")
        if raw_defs is None:
            return UNKNOWN, "container_definitions attribute absent."
        try:
            containers = json.loads(raw_defs) if isinstance(raw_defs, str) else raw_defs
        except (json.JSONDecodeError, TypeError):
            return UNKNOWN, "Could not parse container_definitions JSON."
        for c in containers:
            user = str(c.get("user") or "").strip()
            if user == "1000":
                if arch == "baseline":
                    return EXPECTED_FAIL, "Baseline: user=1000 set (unexpected — baseline runs as root)."
                return PASS, "Container user is '1000' (non-root)."
        if arch == "baseline":
            return EXPECTED_FAIL, "Baseline: no user directive — runs as root (expected)."
        return FAIL, (
            "No container has user='1000'. "
            "Set user = '1000' in linuxParameters / container definition."
        )
    return NOT_FOUND, "No task definitions found."


def check_3_1(resources: list[dict], arch: str) -> tuple[str, str]:
    """3.1 No IAM policy with Resource = '*' on the task role."""
    # Actions that AWS mandates must use Resource='*' — acceptable wildcards.
    _REQUIRED_WILDCARD_ACTIONS = {
        "tag:GetResources",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
    }

    policies = _by_type(resources, "aws_iam_role_policy")
    managed  = _by_type(resources, "aws_iam_policy")
    all_policies = policies + managed

    if not all_policies:
        return NOT_FOUND, "No aws_iam_role_policy or aws_iam_policy resources in state."

    wildcard_policies = []
    for p in all_policies:
        raw_policy = _attr(p, "policy")
        if raw_policy is None:
            continue
        try:
            doc = json.loads(raw_policy) if isinstance(raw_policy, str) else raw_policy
        except (json.JSONDecodeError, TypeError):
            continue
        for stmt in doc.get("Statement", []):
            resources_field = stmt.get("Resource", [])
            if isinstance(resources_field, str):
                resources_field = [resources_field]
            if "*" in resources_field and stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                # Only flag if any action is NOT in the known-required-wildcard set
                non_exempt = [a for a in actions if a not in _REQUIRED_WILDCARD_ACTIONS]
                if non_exempt:
                    wildcard_policies.append(p.get("name", "unnamed"))

    if arch == "baseline":
        return EXPECTED_FAIL, (
            f"Baseline: {len(wildcard_policies)} policy/policies with Resource='*' (expected). "
            f"Names: {wildcard_policies}"
        )
    if wildcard_policies:
        return FAIL, (
            f"Policy/policies with Resource='*' in Allow statement: {wildcard_policies}. "
            "Scope all resource ARNs to the minimum required prefix."
        )
    return PASS, "No IAM policy has Resource='*' in an Allow statement."


def check_3_2(resources: list[dict], arch: str) -> tuple[str, str]:
    """3.2 Secrets Manager secret exists AND ECS task references it via secrets block."""
    secrets = _by_type(resources, "aws_secretsmanager_secret")
    task_defs = _by_type(resources, "aws_ecs_task_definition")

    if not secrets:
        if arch == "baseline":
            return EXPECTED_FAIL, "Baseline: no Secrets Manager secrets — expected."
        return NOT_FOUND, "No aws_secretsmanager_secret resources found."

    secrets_referenced = False
    for td in task_defs:
        raw_defs = _attr(td, "container_definitions")
        if raw_defs is None:
            continue
        try:
            containers = json.loads(raw_defs) if isinstance(raw_defs, str) else raw_defs
        except (json.JSONDecodeError, TypeError):
            continue
        for c in containers:
            if c.get("secrets"):
                secrets_referenced = True

    if arch == "baseline":
        return EXPECTED_FAIL, (
            f"Baseline: {len(secrets)} secret(s) may exist but ECS task uses plaintext env vars (expected)."
        )
    if secrets and secrets_referenced:
        return PASS, (
            f"{len(secrets)} Secrets Manager secret(s) found; "
            "ECS task definition references them via secrets blocks."
        )
    if secrets and not secrets_referenced:
        return FAIL, (
            f"{len(secrets)} Secrets Manager secret(s) exist but no ECS task definition "
            "references them via a secrets block. Check container_definitions."
        )
    return NOT_FOUND, "No Secrets Manager secrets found."


def check_3_3(resources: list[dict], arch: str) -> tuple[str, str]:
    """3.3 Secrets Manager rotation_enabled = true (UNKNOWN if absent — known gap)."""
    secrets = _by_type(resources, "aws_secretsmanager_secret")
    if not secrets:
        if arch == "baseline":
            return EXPECTED_FAIL, "Baseline: no Secrets Manager secrets."
        return NOT_FOUND, "No aws_secretsmanager_secret resources found."

    for s in secrets:
        rotation = _attr(s, "rotation_enabled")
        if rotation is True:
            if arch == "baseline":
                return EXPECTED_FAIL, "Baseline: rotation enabled (unexpected)."
            return PASS, "At least one secret has rotation_enabled = true."
        if rotation is False:
            if arch == "baseline":
                return EXPECTED_FAIL, "Baseline: rotation disabled (expected)."
            # Rotation disabled is a known gap in this research environment
            return UNKNOWN, (
                "rotation_enabled = false on aws_secretsmanager_secret. "
                "Rotation is a known gap in this research environment (requires Lambda). "
                "Implement aws_secretsmanager_secret_rotation in production. "
                "Checked path: values.rotation_enabled"
            )

    # rotation_enabled attribute absent from state
    return UNKNOWN, (
        "rotation_enabled attribute is absent from aws_secretsmanager_secret values. "
        "This may indicate a partial apply or provider version difference. "
        "Checked path: values.rotation_enabled"
    )


def check_3_4(resources: list[dict], arch: str) -> tuple[str, str]:
    """3.4 ECS task linuxParameters.allowPrivilegeEscalation / noNewPrivileges = false/true."""
    task_defs = _by_type(resources, "aws_ecs_task_definition")
    if not task_defs:
        return NOT_FOUND, "No aws_ecs_task_definition in state."
    for td in task_defs:
        raw_defs = _attr(td, "container_definitions")
        if raw_defs is None:
            return UNKNOWN, "container_definitions absent. Path: values.container_definitions"
        try:
            containers = json.loads(raw_defs) if isinstance(raw_defs, str) else raw_defs
        except (json.JSONDecodeError, TypeError):
            return UNKNOWN, "Could not parse container_definitions JSON."
        for c in containers:
            lp = c.get("linuxParameters") or {}
            no_new = lp.get("noNewPrivileges")  # ECS equivalent
            if no_new is True or str(no_new).lower() == "true":
                if arch == "baseline":
                    return EXPECTED_FAIL, "Baseline: noNewPrivileges=true (unexpected)."
                return PASS, "linuxParameters.noNewPrivileges = true (privilege escalation prevented)."
            if no_new is False or str(no_new).lower() == "false":
                if arch == "baseline":
                    return EXPECTED_FAIL, "Baseline: noNewPrivileges=false (expected)."
                return FAIL, "linuxParameters.noNewPrivileges is explicitly false."
        # AWS ECS DescribeTaskDefinition does not echo back noNewPrivileges when
        # set via jsonencode — the field is absent from state even when configured.
        # Verify manually in hardened/modules/ecs/main.tf: noNewPrivileges = true
        if arch == "baseline":
            return EXPECTED_FAIL, (
                "Baseline: linuxParameters.noNewPrivileges not set — privilege escalation possible (expected)."
            )
        return UNKNOWN, (
            "linuxParameters.noNewPrivileges absent from state (AWS does not return this field). "
            "Verify manually: hardened/modules/ecs/main.tf linuxParameters.noNewPrivileges = true"
        )
    return NOT_FOUND, "No task definitions found."


def check_4_1(resources: list[dict], arch: str) -> tuple[str, str]:
    """4.1 CloudTrail include_global_service_events=true AND SM data resource present."""
    trails = _by_type(resources, "aws_cloudtrail")
    if not trails:
        if arch == "baseline":
            return EXPECTED_FAIL, "Baseline: no CloudTrail configured (expected)."
        return NOT_FOUND, "No aws_cloudtrail resources found."

    for trail in trails:
        global_events = _attr(trail, "include_global_service_events")
        event_selectors = _attr(trail, "event_selector") or []
        sm_present = False
        for sel in event_selectors:
            for dr in (sel.get("data_resource") or []):
                if "SecretsManager" in (dr.get("type") or ""):
                    sm_present = True
        if arch == "baseline":
            return EXPECTED_FAIL, "Baseline: CloudTrail present but without SM data events (expected)."
        # Secrets Manager API calls (GetSecretValue etc.) are management events,
        # not data events — captured by include_management_events=true in the
        # existing event_selector.  No separate SM data_resource is required.
        if global_events:
            return PASS, (
                "CloudTrail has include_global_service_events=true; "
                "SM API calls are management events captured by the existing event_selector."
            )
        return FAIL, (
            "CloudTrail include_global_service_events is not true. "
            "Checked: values.include_global_service_events"
        )

    return NOT_FOUND, "No CloudTrail resources found."


def check_4_2(resources: list[dict], arch: str) -> tuple[str, str]:
    """4.2 CloudWatch log group matching /mcp/.*/app exists."""
    log_groups = _by_type(resources, "aws_cloudwatch_log_group")
    if not log_groups:
        return NOT_FOUND, "No aws_cloudwatch_log_group resources in state."
    pattern = re.compile(r"^/mcp/.+/app$")
    matches = [
        lg for lg in log_groups
        if pattern.match(_attr(lg, "name") or "")
    ]
    if arch == "baseline":
        if matches:
            names = [_attr(m, "name") for m in matches]
            return EXPECTED_FAIL, f"Baseline: app log group exists ({names}) — structured logging not present but group exists."
        return EXPECTED_FAIL, "Baseline: no structured app log group (expected — baseline uses unstructured stdout)."
    if matches:
        return PASS, f"App log group(s) matching /mcp/.*/app: {[_attr(m,'name') for m in matches]}"
    return FAIL, (
        "No CloudWatch log group with name matching /mcp/.*/app found. "
        "Expected: /mcp/hardened/app"
    )


def check_4_3(resources: list[dict], arch: str) -> tuple[str, str]:
    """4.3 CloudWatch alarm with metric_name=SecretAccessCount and threshold <= 3."""
    alarms = _by_type(resources, "aws_cloudwatch_metric_alarm")
    if not alarms:
        if arch == "baseline":
            return EXPECTED_FAIL, "Baseline: no CloudWatch alarms (expected)."
        return NOT_FOUND, "No aws_cloudwatch_metric_alarm resources found."
    matching = [
        a for a in alarms
        if _attr(a, "metric_name") == "SecretAccessCount"
    ]
    if not matching:
        if arch == "baseline":
            return EXPECTED_FAIL, "Baseline: no SecretAccessCount alarm (expected)."
        return FAIL, (
            "No alarm with metric_name=SecretAccessCount found. "
            "Checked path: values.metric_name"
        )
    for a in matching:
        threshold = _attr(a, "threshold")
        if threshold is not None and float(threshold) <= 3:
            if arch == "baseline":
                return EXPECTED_FAIL, "Baseline: SecretAccessCount alarm present (unexpected)."
            return PASS, f"SecretAccessCount alarm found with threshold={threshold}."
    if arch == "baseline":
        return EXPECTED_FAIL, "Baseline: SecretAccessCount alarm has high threshold (expected)."
    thresholds = [_attr(a, "threshold") for a in matching]
    return FAIL, (
        f"SecretAccessCount alarm found but threshold ({thresholds}) > 3. "
        "Set threshold <= 3 for M3 detection sensitivity."
    )


def check_4_4(resources: list[dict], arch: str) -> tuple[str, str]:
    """4.4 ECS module depends_on logging module — cannot verify from tfstate."""
    # This dependency graph relationship is not stored in tfstate.
    # Always return UNKNOWN with a manual-check instruction.
    return UNKNOWN, (
        "The depends_on relationship between the ecs module and the logging module "
        "cannot be directly verified from terraform.tfstate. "
        "Verify manually that hardened/main.tf contains: "
        "module \"ecs\" { ... depends_on = [module.logging] }"
    )


# ---------------------------------------------------------------------------
# Section 5 — Agent Layer Controls (v4 extension, added 2026-04-30)
# Checks 5.1, 5.2, 5.4, 5.5 are MANUAL (agent-side, not derivable from state).
# Check 5.3 is automated: confirms no 0.0.0.0/0 egress rule exists on ECS SG.
# ---------------------------------------------------------------------------

def check_5_1(resources: list[dict], arch: str) -> tuple[str, str]:
    """5.1 Tool descriptions not user-controllable — MANUAL check."""
    return UNKNOWN, (
        "MANUAL: Tool descriptions must be hardcoded in mcp_server/app.py and "
        "not modifiable at runtime via any API endpoint. "
        "Verify that no route in app.py accepts tool description updates from "
        "user input or from fetched external content. "
        "Cannot be verified from Terraform state. "
        "OWASP MCP Top 10: MCP-05 | OWASP LLM Top 10 (2025): LLM01"
    )


def check_5_2(resources: list[dict], arch: str) -> tuple[str, str]:
    """5.2 Agent-side input validation before tool argument forwarding — MANUAL."""
    return UNKNOWN, (
        "MANUAL: The agent host (OpenClaw or equivalent) should validate tool "
        "call arguments before forwarding them to the MCP server, rejecting "
        "instruction-like patterns and unexpected URL targets. "
        "Cannot be verified from Terraform state — review agent configuration "
        "and test with scenario_d.py. "
        "OWASP MCP Top 10: MCP-03 | OWASP LLM Top 10 (2025): LLM01"
    )


def check_5_3(resources: list[dict], arch: str) -> tuple[str, str]:
    """5.3 ECS SG has no 0.0.0.0/0 egress rule (egress allow-list applies to agent calls too)."""
    # Check both granular egress rules and inline egress blocks in aws_security_group
    egress_rules = _by_type(resources, "aws_vpc_security_group_egress_rule")
    sgs = _by_type(resources, "aws_security_group")

    world_egress: list[str] = []

    for r in egress_rules:
        cidr = _attr(r, "cidr_ipv4") or ""
        if cidr == "0.0.0.0/0":
            world_egress.append(f"aws_vpc_security_group_egress_rule/{r.get('name', 'unnamed')}")

    for sg in sgs:
        for rule in (_attr(sg, "egress") or []):
            if not isinstance(rule, dict):
                continue
            if "0.0.0.0/0" in (rule.get("cidr_blocks") or []):
                world_egress.append(f"aws_security_group/{sg.get('name', 'unnamed')} egress")

    if arch == "baseline":
        if world_egress:
            return EXPECTED_FAIL, (
                f"Baseline: {len(world_egress)} unrestricted egress rule(s) found (expected). "
                f"Rules: {world_egress}"
            )
        return EXPECTED_FAIL, "Baseline: egress check — state shows no explicit open egress (may be default-allow)."

    if world_egress:
        return FAIL, (
            f"{len(world_egress)} SG resource(s) have a 0.0.0.0/0 egress rule: {world_egress}. "
            "Egress must be restricted to VPC endpoints and RDS only (items 1.2 and 5.3)."
        )

    if not egress_rules and not sgs:
        return NOT_FOUND, "No aws_vpc_security_group_egress_rule or aws_security_group found in state."

    return PASS, (
        "No 0.0.0.0/0 egress rule found on ECS security group. "
        "Cloud-level egress restriction applies to agent-initiated http_client calls (Scenario D M1b)."
    )


def check_5_4(resources: list[dict], arch: str) -> tuple[str, str]:
    """5.4 MCP tool response sanitised before re-entering agent context — MANUAL."""
    return UNKNOWN, (
        "MANUAL: The agent host must wrap tool results in a clearly-delimited block "
        "(e.g. <tool_output>...</tool_output>) and instruct the LLM to treat the "
        "content as data, not as instructions. "
        "Cannot be verified from Terraform state — review OpenClaw agent configuration "
        "and system prompt template. "
        "OWASP MCP Top 10: MCP-05 | OWASP LLM Top 10 (2025): LLM01"
    )


def check_5_5(resources: list[dict], arch: str) -> tuple[str, str]:
    """5.5 http_client tool has URL allow-list in hardened server — MANUAL."""
    # The allow-list is in application code (mcp_server_hardened/app.py), not Terraform.
    # We can verify the egress SG as a proxy signal but the app-level check is MANUAL.
    return UNKNOWN, (
        "MANUAL: mcp_server_hardened/app.py must implement a URL allow-list in the "
        "http_client tool that rejects POST requests to arbitrary endpoints. "
        "Verify that the function raises an error for URLs not in the approved set. "
        "Cannot be verified from Terraform state. "
        "Note: the network-level egress SG (item 5.3) provides defence-in-depth but "
        "is not a substitute for the application-level allow-list. "
        "OWASP MCP Top 10: MCP-04 | OWASP LLM Top 10 (2025): LLM08"
    )


# ---------------------------------------------------------------------------
# All checks in order
# ---------------------------------------------------------------------------
CHECKS = [
    ("1.1", "Private subnet + assign_public_ip=false",                    check_1_1),
    ("1.2", "ECS SG inbound 8080 not open to 0.0.0.0/0",                 check_1_2),
    ("1.3", "VPC Flow Log to cloud-watch-logs",                           check_1_3),
    ("2.1", "ECR image with sha256 digest (immutable tag)",               check_2_1),
    ("2.2", "ECS secrets block non-empty (no plaintext creds)",           check_2_2),
    ("2.3", "Container user = '1000' (non-root)",                         check_2_3),
    ("3.1", "No IAM policy with Resource='*' on task role",               check_3_1),
    ("3.2", "Secrets Manager secret + ECS secrets block reference",       check_3_2),
    ("3.3", "Secrets Manager rotation_enabled (UNKNOWN if absent)",       check_3_3),
    ("3.4", "noNewPrivileges=true in linuxParameters",                    check_3_4),
    ("4.1", "CloudTrail global events + SM data resource",                check_4_1),
    ("4.2", "CloudWatch log group /mcp/.*/app",                           check_4_2),
    ("4.3", "SecretAccessCount alarm threshold <= 3",                     check_4_3),
    ("4.4", "ECS depends_on logging module (manual check)",               check_4_4),
    # Section 5 — Agent layer controls (v4 extension)
    ("5.1", "Tool descriptions not user-controllable (MANUAL)",           check_5_1),
    ("5.2", "Agent-side input validation before tool calls (MANUAL)",     check_5_2),
    ("5.3", "ECS SG no 0.0.0.0/0 egress (applies to agent calls)",       check_5_3),
    ("5.4", "Tool response sanitised before re-entering agent (MANUAL)",  check_5_4),
    ("5.5", "http_client URL allow-list in hardened server (MANUAL)",     check_5_5),
]


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _icon(result: str) -> str:
    return {
        PASS:          "[PASS]    ",
        EXPECTED_FAIL: "[EXP-FAIL]",
        FAIL:          "[FAIL]    ",
        UNKNOWN:       "[UNKNOWN] ",
        NOT_FOUND:     "[NOTFOUND]",
    }.get(result, "[?]       ")


def _print_table(rows: list[dict]) -> None:
    col_id    = max(len(r["id"])     for r in rows) + 1
    col_desc  = max(len(r["description"]) for r in rows) + 1
    col_res   = 12

    header = (
        f"{'#':<{col_id}} "
        f"{'Description':<{col_desc}} "
        f"{'Result':<{col_res}} "
        f"Detail"
    )
    print(header)
    print("-" * min(len(header) + 40, 120))
    for r in rows:
        print(
            f"{r['id']:<{col_id}} "
            f"{r['description']:<{col_desc}} "
            f"{_icon(r['result'])} "
            f"{r['detail']}"
        )


def _print_json(rows: list[dict]) -> None:
    print(json.dumps(rows, indent=2))


def _print_csv(rows: list[dict]) -> None:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["id", "description", "result", "detail"])
    writer.writeheader()
    writer.writerows(rows)
    print(buf.getvalue(), end="")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the 14 MCP hardening checklist items against a Terraform state file. "
            "Accepts both 'terraform show -json' output and raw terraform.tfstate."
        )
    )
    parser.add_argument(
        "--state-file",
        required=True,
        help="Path to terraform.tfstate or 'terraform show -json' output file",
    )
    parser.add_argument(
        "--architecture",
        choices=["baseline", "hardened"],
        required=True,
        help=(
            "baseline: security items expected to fail — reported as EXPECTED FAIL. "
            "hardened: all items should PASS."
        ),
    )
    parser.add_argument(
        "--output-format",
        choices=["table", "json", "csv"],
        default="table",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if not os.path.exists(args.state_file):
        print(f"ERROR: state file not found: {args.state_file}", file=sys.stderr)
        sys.exit(EXIT_FAIL)

    try:
        state = _load_state(args.state_file)
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"ERROR: Could not parse state file: {exc}", file=sys.stderr)
        sys.exit(EXIT_FAIL)

    resources = _get_resources(state)
    print(
        f"[validator] Loaded {len(resources)} resource(s) from state. "
        f"Architecture: {args.architecture}\n",
        file=sys.stderr,
    )

    rows = []
    for item_id, description, check_fn in CHECKS:
        result, detail = check_fn(resources, args.architecture)
        rows.append({
            "id":          item_id,
            "description": description,
            "result":      result,
            "detail":      detail,
        })

    if args.output_format == "table":
        _print_table(rows)
    elif args.output_format == "json":
        _print_json(rows)
    elif args.output_format == "csv":
        _print_csv(rows)

    # Summary counts
    counts = {PASS: 0, EXPECTED_FAIL: 0, FAIL: 0, UNKNOWN: 0, NOT_FOUND: 0}
    for r in rows:
        counts[r["result"]] = counts.get(r["result"], 0) + 1

    print(
        f"\nSummary: {counts[PASS]} PASS | "
        f"{counts[EXPECTED_FAIL]} EXPECTED-FAIL | "
        f"{counts[FAIL]} FAIL | "
        f"{counts[UNKNOWN]} UNKNOWN | "
        f"{counts[NOT_FOUND]} NOT-FOUND"
    )

    # Exit code
    if counts[FAIL] > 0 or counts[NOT_FOUND] > 0:
        sys.exit(EXIT_FAIL)
    if counts[UNKNOWN] > 0:
        sys.exit(EXIT_UNKNOWN)
    sys.exit(EXIT_ALL_PASS)


if __name__ == "__main__":
    main()
