# MCP Server Hardening Checklist

## Purpose and Scope

This checklist is a **practitioner-facing deliverable** produced as part of an
MSc Cybersecurity Applied Research Project at Dublin Business School (2025).
It is designed to be read and applied independently of the full dissertation.

**What it covers:** fourteen concrete, verifiable controls for securing a
Model Context Protocol (MCP) server deployed on AWS Elastic Container Service
(ECS) Fargate.  Each control is mapped to the attack scenario it mitigates,
the metric it improves, the AWS service that implements it, and a peer-reviewed
or authoritative evidence source.

**Audience:** Cloud engineers, DevSecOps practitioners, and security architects
deploying MCP-based AI tool-use systems in AWS.  No prior knowledge of the
dissertation is required.  Each item is self-contained.

**How to verify:** Use `checklist_validator.py` to check Terraform state
automatically.  Items marked UNKNOWN require manual inspection; see the note
under each affected item.

---

## Section 1 — Network Isolation

**1.1** Deploy the MCP server in a **private subnet with no directly-attached public IP address**, routing outbound traffic through a NAT Gateway.

- **AWS service / config:** `aws_subnet` (`map_public_ip_on_launch = false`); `aws_nat_gateway`; ECS service `assign_public_ip = false`
- **Risk addressed:** Scenario A, B, C — removes the direct internet attack surface (M1); without a public IP the server is unreachable from arbitrary external hosts
- **Evidence:** National Institute of Standards and Technology (NIST), 2020. *Security and Privacy Controls for Information Systems and Organizations* (SP 800-53 Rev. 5). Control SC-7 (Boundary Protection). Gaithersburg, MD: NIST. Available at: https://doi.org/10.6028/NIST.SP.800-53r5
- **Terraform reference:** `hardened/modules/vpc/main.tf` — `aws_subnet.private`, `aws_nat_gateway.main`, `aws_ecs_service.mcp`

---

**1.2** Restrict the ECS Security Group so that **inbound port 8080 is permitted only from the VPC CIDR**, and **outbound traffic is limited to VPC Endpoint SG (TCP/443) and RDS SG (TCP/5432)**; no `0.0.0.0/0` egress rule.

- **AWS service / config:** `aws_security_group` + `aws_vpc_security_group_ingress_rule` / `aws_vpc_security_group_egress_rule`
- **Risk addressed:** Scenario B, C — scoped egress prevents the http_client tool from reaching an external attacker listener, and blocks boto3 from contacting AWS APIs outside the VPC endpoint path (M1); combined with the URL allowlist in app.py for defence-in-depth
- **Evidence:** Amazon Web Services, 2023. *AWS Security Best Practices*. Seattle, WA: AWS. Available at: https://docs.aws.amazon.com/whitepapers/latest/aws-security-best-practices/security-groups.html
- **Terraform reference:** `hardened/modules/vpc/main.tf` — `aws_security_group.ecs`, `aws_vpc_security_group_egress_rule.ecs_to_endpoints_443`, `aws_vpc_security_group_egress_rule.ecs_to_rds_5432`

---

**1.3** Enable **VPC Flow Logs** on the hardened VPC, delivered to a dedicated CloudWatch log group.

- **AWS service / config:** `aws_flow_log` (`log_destination_type = "cloud-watch-logs"`); `aws_cloudwatch_log_group.flow_logs`; dedicated IAM delivery role
- **Risk addressed:** Scenario B, C — network-layer detection of anomalous outbound connection attempts even if application-layer controls are bypassed (M3)
- **Evidence:** Cloud Security Alliance, 2022. *Cloud Controls Matrix v4.0*. Seattle, WA: CSA. Control LOG-09 (Logging / Monitoring). Available at: https://cloudsecurityalliance.org/research/cloud-controls-matrix/
- **Terraform reference:** `hardened/modules/vpc/main.tf` — `aws_flow_log.main`; `hardened/modules/logging/main.tf` — `aws_cloudwatch_log_group.flow_logs`

---

## Section 2 — Container Hardening

**2.1** Build the container image from a **minimal, pinned base image** and push with an **immutable ECR image tag** (or image digest) to prevent silent replacement.

- **AWS service / config:** ECR repository with `image_tag_mutability = "IMMUTABLE"`; `image_scanning_configuration.scan_on_push = true`; Dockerfile `FROM python:3.12-slim`
- **Risk addressed:** Scenario A, B, C — immutable tags prevent supply-chain attacks that replace the running image with a backdoored version; scanning detects known CVEs before deployment (M1 supply-chain path)
- **Evidence:** National Institute of Standards and Technology (NIST), 2022. *Guidelines on Minimum Standards for Developer Verification of Software* (NISTIR 8397). Gaithersburg, MD: NIST. Available at: https://doi.org/10.6028/NIST.IR.8397
- **Terraform reference:** `hardened/modules/ecs/main.tf` — `aws_ecr_repository.mcp`

---

**2.2** Inject all credentials via **AWS Secrets Manager secrets blocks** in the ECS task definition; **no plaintext environment variables** for any credential key.

- **AWS service / config:** `aws_ecs_task_definition` `container_definitions[*].secrets` blocks; no `environment` block entries for credential keys
- **Risk addressed:** Scenario A — even if an attacker reads `/proc/1/environ` or the ECS task metadata endpoint, no credential strings are present in the process environment (M2); Secrets Manager injects values as ephemeral environment variables visible only inside the running container
- **Evidence:** Open Web Application Security Project (OWASP), 2021. *OWASP Top 10:2021 — A02 Cryptographic Failures*. Beaverton, OR: OWASP Foundation. Available at: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- **Terraform reference:** `hardened/modules/ecs/main.tf` — `aws_ecs_task_definition.mcp` (`secrets` block)

---

**2.3** Run the container process as **non-root user uid/gid 1000** with `readonlyRootFilesystem = true`, `noNewPrivileges = true`, and `capabilities.drop = ["ALL"]`.

- **AWS service / config:** ECS task definition `linuxParameters.noNewPrivileges = true`, `readonlyRootFilesystem = true`, `user = "1000"`, `linuxParameters.capabilities.drop = ["ALL"]`; Dockerfile `USER 1000`; tmpfs mount at `/tmp`
- **Risk addressed:** Scenario A — prevents the container from reading files outside permitted mount points if the path allowlist is bypassed; `noNewPrivileges` stops privilege escalation via setuid binaries (M1 container-escape path; M2 lateral movement)
- **Evidence:** Center for Internet Security, 2023. *CIS Docker Benchmark v1.6*. East Greenbush, NY: CIS. Control 5.4 (Ensure that privileged containers are not used). Available at: https://www.cisecurity.org/benchmark/docker
- **Terraform reference:** `hardened/modules/ecs/main.tf` — `aws_ecs_task_definition.mcp` (`linuxParameters`, `readonlyRootFilesystem`, `user`)

---

## Section 3 — Identity and Secrets

**3.1** Apply **least-privilege IAM policies** to the ECS Task Role: three separate `aws_iam_policy` resources (one per MCP tool), each scoped to the minimum required resource ARN.  No inline policies.  No wildcard resource (`*`) in any statement.

- **AWS service / config:** `aws_iam_policy` + `aws_iam_role_policy_attachment` (×3); `file_reader` policy scoped to one S3 prefix ARN; `db_query` policy scoped to one RDS resource ARN (`rds-db:connect`); `http_client` policy grants no useful AWS data access
- **Risk addressed:** Scenario C — even if credentials are extracted, the task role cannot enumerate all S3 buckets or all Secrets Manager secrets (M2 blast-radius reduction)
- **Evidence:** Amazon Web Services, 2022. *IAM Best Practices: Grant Least Privilege*. Seattle, WA: AWS. Available at: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege
- **Terraform reference:** `hardened/modules/iam/main.tf` — `aws_iam_policy.file_reader`, `aws_iam_policy.db_query`, `aws_iam_policy.http_client`

---

**3.2** Store all sensitive configuration values in **AWS Secrets Manager** and reference them via the ECS task definition `secrets` block rather than plaintext `environment` entries.

- **AWS service / config:** `aws_secretsmanager_secret` (×4); `aws_secretsmanager_secret_version`; ECS task definition `secrets` blocks reference ARNs
- **Risk addressed:** Scenario A, C — credentials are not written to EFS, not present in plaintext task environment, and not visible in `describe-tasks` API output (M1 credential-at-rest exposure; M2 scope)
- **Evidence:** Amazon Web Services, 2023. *AWS Secrets Manager Best Practices*. Seattle, WA: AWS. Available at: https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html
- **Terraform reference:** `hardened/modules/secrets/main.tf` — `aws_secretsmanager_secret.*`; `hardened/modules/ecs/main.tf` — `secrets` block

---

**3.3** Enable **automatic rotation** for Secrets Manager secrets in production deployments.

- **AWS service / config:** `aws_secretsmanager_secret.rotation_rules` with `aws_secretsmanager_secret_rotation` (requires a Lambda rotation function)
- **Risk addressed:** Scenario C — automatic rotation limits the window of exploitability if credentials are extracted; an attacker who exfiltrates a credential that has since been rotated cannot use it (M1 temporal reduction)
- **Evidence:** Saltzer, J.H. and Schroeder, M.D., 1975. The protection of information in computer systems. *Proceedings of the IEEE*, 63(9), pp.1278–1308. Available at: https://doi.org/10.1109/PROC.1975.9939
- **Terraform reference:** `hardened/modules/secrets/main.tf` — rotation not configured in this research environment (lab constraint); implement `aws_secretsmanager_secret_rotation` in production
- **Known gap:** Rotation setup requires a VPC-connected Lambda function and is out of scope for this research deployment. The `checklist_validator.py` marks this item UNKNOWN rather than FAIL for the hardened architecture.

---

**3.4** Apply a **Secrets Manager resource-based Deny policy** to each secret that blocks `GetSecretValue` for all principals except the ECS Task Role ARN.

- **AWS service / config:** `aws_secretsmanager_secret_policy` with `Effect: Deny`, `Principal: *`, `Condition: StringNotEquals aws:PrincipalArn: <task_role_arn>`
- **Risk addressed:** Scenario C — prevents any over-permissive IAM role (including a future misconfigured role) from reading the secrets, even if that role has an explicit `Allow` in its own policy; the resource-based Deny takes precedence (M2 blast-radius hard cap)
- **Evidence:** Amazon Web Services, 2023. *How IAM Works: Policy Evaluation Logic*. Seattle, WA: AWS. Available at: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
- **Terraform reference:** `hardened/modules/secrets/main.tf` — `aws_secretsmanager_secret_policy.*`

---

## Section 4 — Logging and Observability

**4.1** Enable **AWS CloudTrail** with `include_global_service_events = true`, `enable_log_file_validation = true`, and data event selectors for **all Secrets Manager secrets** and **all S3 objects**.

- **AWS service / config:** `aws_cloudtrail` with `event_selector` data resources for `AWS::SecretsManager::Secret` and `AWS::S3::Object`; S3 bucket for trail storage with KMS encryption and versioning; CloudWatch Logs delivery
- **Risk addressed:** Scenario C — every `GetSecretValue` API call is recorded in CloudTrail regardless of whether it succeeds or fails; enables post-incident forensics and drives the M3 metric alarm (M3 detection)
- **Evidence:** Mell, P. and Grance, T., 2011. *The NIST Definition of Cloud Computing* (SP 800-145). Gaithersburg, MD: NIST. Available at: https://doi.org/10.6028/NIST.SP.800-145
- **Terraform reference:** `hardened/modules/logging/main.tf` — `aws_cloudtrail.main`

---

**4.2** Emit **structured JSON application logs** from the MCP server to CloudWatch Logs for every tool invocation, including: timestamp, tool name, sanitised input parameters, outcome (SUCCESS / REJECTED / ERROR), and ECS task ID.

- **AWS service / config:** Application-level logging in `mcp_server_hardened/app.py`; `awslogs` log driver in ECS task definition; `aws_cloudwatch_log_group.app_logs` (`/mcp/hardened/app`)
- **Risk addressed:** Scenario A, B, C — invocation-level audit trail enables detection of reconnaissance and exploitation attempts that may not generate AWS API events (e.g. file reads via `file_reader`); this is the **primary detection mechanism for `file_reader` abuse** because EFS does not generate CloudTrail data events (M3)
- **Evidence:** Chuvakin, A., Schmidt, K. and Phillips, C., 2012. *Logging and Log Management: The Authoritative Guide to Understanding the Concepts Surrounding Logging and Log Management*. Waltham, MA: Syngress.
- **Terraform reference:** `hardened/modules/logging/main.tf` — `aws_cloudwatch_log_group.app_logs`; `hardened/modules/ecs/main.tf` — `logConfiguration`

---

**4.3** Create a **CloudWatch Log Metric Filter** on the CloudTrail log group that counts `GetSecretValue` events, and attach a **CloudWatch Metric Alarm** that fires when the count exceeds **3 in 60 seconds**.

- **AWS service / config:** `aws_cloudwatch_log_metric_filter` (pattern `{ $.eventName = "GetSecretValue" }`, namespace `MCPSecurity`, metric `SecretAccessCount`); `aws_cloudwatch_metric_alarm` (threshold ≤ 3, period 60s, statistic Sum); `aws_sns_topic.alerts` for alarm actions
- **Risk addressed:** Scenario C — automated near-real-time detection of credential harvesting attempts; the 3-call threshold in 60 seconds correlates to the three-run attack loop executed by `scenario_c.py` (M3)
- **Evidence:** Scarfone, K. and Mell, P., 2007. *Guide to Intrusion Detection and Prevention Systems (IDPS)* (SP 800-94). Gaithersburg, MD: NIST. Available at: https://doi.org/10.6028/NIST.SP.800-94
- **Terraform reference:** `hardened/modules/logging/main.tf` — `aws_cloudwatch_log_metric_filter.secret_access`, `aws_cloudwatch_metric_alarm.secret_access_anomaly`

---

**4.4** Ensure the **ECS module declares `depends_on` the logging module** in `hardened/main.tf` so that all CloudWatch log groups are fully provisioned before the first ECS task starts.

- **AWS service / config:** `depends_on = [module.logging]` in the `module "ecs"` block of `hardened/main.tf`
- **Risk addressed:** All scenarios — eliminates the detection blind spot that occurs when a container starts before its log group exists; CloudWatch silently discards log events sent to a non-existent group, creating a gap in the M3 audit trail during initial container startup
- **Evidence:** HashiCorp, 2023. *Terraform Language: depends\_on Meta-Argument*. San Francisco, CA: HashiCorp. Available at: https://developer.hashicorp.com/terraform/language/meta-arguments/depends_on
- **Terraform reference:** `hardened/main.tf` — `module "ecs" { ... depends_on = [module.logging] }`
- **Validator note:** This dependency cannot be directly verified from `terraform.tfstate`. The `checklist_validator.py` marks this item UNKNOWN with the instruction to verify manually that `depends_on = [module.logging]` is present in `hardened/main.tf`.

---

## Limitations

> **Known gap:** EFS file read operations do not generate CloudTrail data
> events. Invocation-level logging via the MCP server application (item 4.2)
> is therefore the primary detection mechanism for file_reader tool abuse
> in the absence of an EFS-native audit trail.

Additional limitations of this checklist:

- Item 3.3 (automatic secret rotation) is not implemented in the research
  environment due to the additional Lambda infrastructure required.  Production
  deployments must implement rotation.
- Items in Section 2 address ECS Fargate hardening only.  Kubernetes
  deployments require equivalent Pod Security Standards controls.
- This checklist does not address MCP protocol-level authentication
  (OAuth 2.0 bearer token validation on the SSE endpoint), which is an
  open gap in the current MCP specification (as of MCP v1.0, March 2025).

*Last updated: 2025. MSc Cybersecurity Applied Research Project, Dublin Business School.*
