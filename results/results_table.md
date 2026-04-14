<!--
  DESIGN-TIME PREDICTIONS — NOT EMPIRICAL DATA
  These values are projected from the architecture design in Components 1 and 2.
  Replace each cell marked [EMPIRICAL] with the actual value from
  results/<architecture>/scenario_*_results.json after running run_all.sh.
  Do not submit this file with placeholder values in your dissertation.
  All M3 values are to be confirmed by collect_logs.sh.
  Note: Scenario B / hardened M1 is explicitly TBD pending Residual Risk 4
  experimental outcome (see Phase 1 Component 3 design notes).
-->

# Experimental Results — Securing MCP Servers in Cloud

## Table 4.1 — Attack Success Rate (M1): Baseline vs. Hardened

M1 is defined as the percentage of attack runs (out of three per scenario) in
which the attacker achieved the primary objective of that scenario.

- **Scenario A**: Credentials read from EFS (`credentials.env` or `/proc/1/environ`)
- **Scenario B**: Credentials exfiltrated to attacker-controlled listener (confirmed receipt)
- **Scenario C**: Extracted credentials used to reach an AWS API endpoint

| Scenario | Baseline M1 (%) | Hardened M1 (%) | Reduction |
|---|---|---|---|
| A — File-read credential exfiltration | 100% (predicted) | 0% (predicted) | [EMPIRICAL] |
| B — HTTP exfiltration via http_client | 100% (predicted) | TBD† | [EMPIRICAL] |
| C — AWS API abuse via extracted creds | 100% ATTEMPTED‡ (predicted) | 0% (predicted) | [EMPIRICAL] |

> † Scenario B / hardened M1 is TBD pending Residual Risk 4 experimental
> outcome. The hardened http_client URL allowlist blocks the public listener
> URL; the ECS SG additionally blocks outbound TCP to non-VPC-endpoint
> destinations. If both controls function as designed, M1 = 0%.
>
> ‡ Scenario C baseline M1 is scored as ATTEMPTED (not SUCCESS) because mock
> credentials are used. The mock key `AKIAIOSFODNN7EXAMPLE` conforms to the
> AWS key format and causes boto3 to contact the AWS API before receiving
> `InvalidClientTokenId`. For a real attacker with valid credentials, ATTEMPTED
> would be SUCCESS. The mock credentials create a reproducible approximation
> of the attack path.

**Replace predicted values with empirical values after running:**
```
cd attacks/
./run_all.sh --target-ip <ip> --architecture baseline
./run_all.sh --architecture hardened
```

| Scenario | Baseline M1 — EMPIRICAL | Hardened M1 — EMPIRICAL |
|---|---|---|
| A | [EMPIRICAL] | [EMPIRICAL] |
| B | [EMPIRICAL] | [EMPIRICAL] |
| C | [EMPIRICAL] | [EMPIRICAL] |

---

## Table 4.2 — Scope of Compromise (M2): Credential Items Accessed

M2 counts the number of distinct sensitive credential items exposed or accessed
per scenario per architecture. Four items are defined:

| ID | Item | Sensitivity Tier |
|---|---|---|
| C1 | `AWS_ACCESS_KEY_ID` | High |
| C2 | `AWS_SECRET_ACCESS_KEY` | High |
| C3 | `DB_CONNECTION_STRING` | High |
| C4 | `INTERNAL_API_TOKEN` | Medium |

### Baseline M2

| Scenario | Items Accessed | Count | Notes |
|---|---|---|---|
| A — credentials.env read | C1, C2, C3, C4 | 4/4 (predicted) | All four items present in credentials.env |
| A — /proc/1/environ read | C1, C2 (predicted) | 2/4 (predicted) | ECS task env vars include AWS mock creds |
| B — Exfiltrated payload | C1, C2, C3, C4 | 4/4 (predicted) | Full credentials.env POSTed to listener |
| C — AWS API calls | C1, C2 | 2/4 (predicted) | Key + secret used for boto3 session |

**Empirical M2 — Baseline (fill from scenario_*_results.json):**

| Scenario | Items Accessed | [EMPIRICAL] Count |
|---|---|---|
| A | [EMPIRICAL] | [EMPIRICAL] |
| B | [EMPIRICAL] | [EMPIRICAL] |
| C | [EMPIRICAL] | [EMPIRICAL] |

### Hardened M2

All scenarios expected to return 0 items (controls block access before any
credential is read). If file_reader is rejected by the path allowlist, no
credential content is returned; http_client is blocked by URL allowlist; boto3
cannot reach the AWS API due to ECS SG egress restrictions.

| Scenario | Items Accessed | Count | Notes |
|---|---|---|---|
| A | None (predicted) | 0/4 (predicted) | Path allowlist rejects /mnt/data/config/ |
| B | None (predicted) | 0/4 (predicted) | Step 1 (file_reader) fails; no payload built |
| C | None (predicted) | 0/4 (predicted) | Step 1 fails; boto3 session never constructed |

**Empirical M2 — Hardened (fill from scenario_*_results.json):**

| Scenario | Items Accessed | [EMPIRICAL] Count |
|---|---|---|
| A | [EMPIRICAL] | [EMPIRICAL] |
| B | [EMPIRICAL] | [EMPIRICAL] |
| C | [EMPIRICAL] | [EMPIRICAL] |

---

## Table 4.3 — Detection Visibility (M3): Log Events Generated

M3 is defined as the percentage of attack runs (out of three) for which at
least one actionable log event was generated — i.e., an event with sufficient
information to identify the attack type, affected resource, and approximate
time. Scored by `collect_logs.sh` and patched into each `_results.json`.

### Log sources by architecture

| Source | Baseline | Hardened |
|---|---|---|
| CloudWatch app logs (`/mcp/<arch>/app`) | ✓ stdout only | ✓ structured JSON (tool + outcome + timestamp) |
| VPC Flow Logs | ✗ not enabled | ✓ `/mcp/hardened/flow-logs` |
| CloudTrail (GetSecretValue) | ✗ not enabled | ✓ via `aws_cloudtrail.main` |
| CloudTrail (GetObject S3) | ✗ not enabled | ✓ via `aws_cloudtrail.main` |

### Predicted M3 values

| Scenario | Baseline M3 (%) | Hardened M3 (%) | Delta |
|---|---|---|---|
| A — File-read | 0% (no structured logs; stdout only) | 100% (path rejection → WARNING JSON) | +100% (predicted) |
| B — HTTP exfil | 0% (no structured logs) | 100% (both tools log REJECTED) | +100% (predicted) |
| C — AWS API abuse | 0% (no structured logs) | 100% (SM CloudTrail + app WARNING) | +100% (predicted) |

**Empirical M3 (fill from collect_logs.sh output):**

| Scenario | Baseline M3 — [EMPIRICAL] | Hardened M3 — [EMPIRICAL] |
|---|---|---|
| A | [EMPIRICAL] | [EMPIRICAL] |
| B | [EMPIRICAL] | [EMPIRICAL] |
| C | [EMPIRICAL] | [EMPIRICAL] |

> **Known gap:** EFS file-read operations do not generate CloudTrail data
> events. Application-level structured logging (item 4.2 in the checklist)
> is therefore the primary detection mechanism for `file_reader` tool abuse
> in the absence of an EFS-native audit trail.

---

## Table 4.4 — Control Effectiveness Summary

Effect size scale:
- **None (0)**: Control has no measurable effect on this metric.
- **Low (1)**: Partial reduction; attack still achievable via alternative path.
- **Moderate (2)**: Significant reduction; attack requires additional capability.
- **Large (3)**: Attack blocked entirely or detection rate reaches 100%.

| Control Family | M1 Effect (Attack Rate) | M2 Effect (Scope) | M3 Effect (Detection) |
|---|---|---|---|
| Network Isolation (private subnet, NAT, SG egress scoping, VPC endpoints) | Large (3) | Moderate (2) | Moderate (2) |
| Container Hardening (non-root uid, readonlyRootFilesystem, noNewPrivileges, tmpfs) | Moderate (2) | Moderate (2) | Low (1) |
| Managed Identities + Secrets Management (least-privilege IAM, Secrets Manager, resource policy Deny) | Large (3) | Large (3) | Moderate (2) |
| Logging and Monitoring (CloudTrail, VPC Flow Logs, structured app logs, metric alarm) | None (0) | None (0) | Large (3) |

**Empirical control effectiveness (replace after experiment):**

| Control Family | M1 — [EMPIRICAL] | M2 — [EMPIRICAL] | M3 — [EMPIRICAL] |
|---|---|---|---|
| Network Isolation | [EMPIRICAL] | [EMPIRICAL] | [EMPIRICAL] |
| Container Hardening | [EMPIRICAL] | [EMPIRICAL] | [EMPIRICAL] |
| Managed Identities + Secrets Management | [EMPIRICAL] | [EMPIRICAL] | [EMPIRICAL] |
| Logging and Monitoring | [EMPIRICAL] | [EMPIRICAL] | [EMPIRICAL] |

---

*Generated by Component 4 of the MSc Cybersecurity Applied Research Project artefact.*
*Title: "Securing Model Context Protocol Servers in Cloud: Evaluating the Effectiveness*
*of Standard Cloud Security Controls Against Practical Attacks."*
*Dublin Business School, 2025.*
