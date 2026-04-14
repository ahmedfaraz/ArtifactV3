# Securing MCP Servers in Cloud — Research Artefact

**MSc Cybersecurity Applied Research Project**
**Dublin Business School, 2025**
**Title:** Securing Model Context Protocol Servers in Cloud: Evaluating the Effectiveness of Standard Cloud Security Controls Against Practical Attacks

---

## 1. Repository Structure

```
.
├── baseline/                   # Component 1 — Deliberately misconfigured MCP deployment
│   ├── main.tf                 # Root module wiring all five sub-modules
│   ├── variables.tf / outputs.tf
│   └── modules/
│       ├── vpc/                # Public subnet, IGW, permissive SG, no Flow Logs
│       ├── iam/                # Over-permissive Task Role (wildcard S3 + SM)
│       ├── efs/                # Unencrypted EFS, world-accessible mount target
│       ├── rds/                # publicly_accessible=true, mock password
│       └── ecs/                # Fargate, public IP, root user, plaintext env creds
│
├── hardened/                   # Component 2 — Hardened MCP deployment
│   ├── main.tf                 # Module order: vpc->iam->efs->rds->secrets->logging->ecs
│   ├── variables.tf / outputs.tf
│   └── modules/
│       ├── vpc/                # Private subnet, NAT GW, Flow Logs, VPC Endpoints
│       ├── iam/                # Least-privilege per-tool attached policies
│       ├── efs/                # Encrypted EFS, access point uid 1000
│       ├── rds/                # Private, not publicly accessible, IAM auth
│       ├── secrets/            # Secrets Manager + resource-based Deny policies
│       ├── logging/            # CloudTrail, CW log groups, metric filter, alarm, SNS
│       └── ecs/                # Private subnet, no public IP, uid 1000,
│                               #   readonlyRootFilesystem, noNewPrivileges, SM secrets
│
├── mcp_server/                 # Component 1 — Baseline MCP server (Python)
│   ├── app.py                  # file_reader, http_client, db_query — no validation
│   ├── requirements.txt
│   └── Dockerfile              # python:3.12-slim, no USER directive (runs as root)
│
├── mcp_server_hardened/        # Component 2 — Hardened MCP server (Python)
│   ├── app.py                  # Same tools + path allowlist, URL allowlist,
│   │                           #   SELECT-only SQL, structured JSON logging
│   ├── requirements.txt
│   └── Dockerfile              # Adds USER 1000 (mcpuser)
│
├── mock_data/
│   ├── seed_secrets.sh         # Seeds baseline EFS: credentials.env + customers.csv
│   └── seed_secrets_hardened.sh# Seeds hardened EFS: customers.csv only (no creds)
│
├── attacks/                    # Component 3 — Attack scenarios and orchestration
│   ├── attacker_listener.py    # Local HTTP exfil listener (replaces webhook.site)
│   ├── scenario_a.py           # File-read credential exfiltration (M1/M2/M3)
│   ├── scenario_b.py           # HTTP exfil via http_client tool (M1/M2/M3)
│   ├── scenario_c.py           # AWS API abuse with extracted credentials (M1/M2/M3)
│   ├── run_all.sh              # Orchestrates all scenarios; handles hardened EC2 attacker
│   └── collect_logs.sh         # Collects CW + CloudTrail logs; scores M3
│
├── results/                    # Component 4 — Results and visualisation
│   ├── results_table.md        # Tables 4.1–4.4 with [EMPIRICAL] placeholders
│   └── visualise_results.py    # Generates M1 bar chart, M3 bar chart, heatmap
│
├── checklist/                  # Component 5 — MCP hardening checklist
│   ├── checklist.md            # 14 items across 4 sections; practitioner-facing
│   └── checklist_validator.py  # Validates checklist items against Terraform state
│
└── README.md                   # This file
```

---

## 2. Prerequisites

Before running any component, ensure the following are installed and configured.

### AWS
- **AWS CLI** v2 configured with credentials for your research account.
  The minimum configuration is `aws configure` with an IAM user or role.
  No credentials are hardcoded anywhere in this repository.
- **Required IAM permissions** for the researcher's account (see Section 3).

### Infrastructure
- **Terraform** >= 1.5 (`terraform version`)
- **Docker** (to build and push the MCP server image to ECR)

### Python
- **Python 3.12** (the MCP server and all scripts target Python 3.12)
- Install dependencies:
  ```bash
  pip install mcp[cli] httpx psycopg2-binary boto3 matplotlib numpy
  ```

### System packages (for seed_secrets.sh)
- **nfs-utils** (Amazon Linux / RHEL) or **nfs-common** (Debian / Ubuntu) —
  required for NFS mount in `seed_secrets.sh`.
  `seed_secrets.sh` must be run as root (or with `sudo`) from within the VPC.

---

## 3. Required IAM Permissions

The researcher's AWS account needs the following permissions to deploy and run the experiment. The simplest approach in a dedicated research account is to attach these AWS-managed policies to your IAM user or role:

| Action category | AWS managed policy (or equivalent) |
|---|---|
| ECS / ECR | `AmazonECS_FullAccess`, `AmazonEC2ContainerRegistryFullAccess` |
| VPC / EC2 | `AmazonVPCFullAccess`, `AmazonEC2FullAccess` |
| IAM | `IAMFullAccess` (needed to create task roles and instance profiles) |
| S3 | `AmazonS3FullAccess` |
| Secrets Manager | `SecretsManagerReadWrite` |
| CloudTrail | `AWSCloudTrail_FullAccess` |
| CloudWatch | `CloudWatchFullAccess`, `CloudWatchLogsFullAccess` |
| RDS | `AmazonRDSFullAccess` |
| SSM | `AmazonSSMFullAccess` (used by run_all.sh for hardened attacker EC2) |
| SNS | `AmazonSNSFullAccess` |
| EFS | `AmazonElasticFileSystemFullAccess` |

> **Note:** In a production or shared account, scope these permissions to the
> specific resources created by this project.  In a dedicated research account
> the managed policies above are acceptable for the duration of the experiment.

---

## 4. Step-by-Step Experiment Sequence

### Step 1 — Deploy the baseline architecture

```bash
cd baseline/
terraform init
terraform apply
```

Expected duration: **5–8 minutes** (dominated by RDS provisioning).

### Step 2 — Wait for RDS and EFS to become available

- **RDS:** Takes 4–8 minutes after `terraform apply` completes.
  Poll until status is `available`:
  ```bash
  aws rds describe-db-instances \
    --db-instance-identifier mcp-baseline-rds \
    --query 'DBInstances[0].DBInstanceStatus' \
    --output text
  ```
- **EFS mount target:** Takes ~90 seconds after apply.
  Poll until lifecycle state is `available`:
  ```bash
  aws efs describe-mount-targets \
    --file-system-id $(terraform output -raw efs_id) \
    --query 'MountTargets[0].LifeCycleState' \
    --output text
  ```

### Step 3 — Build and push the baseline Docker image

```bash
ECR_URL=$(terraform output -raw ecr_repository_url)
aws ecr get-login-password --region eu-west-1 \
  | docker login --username AWS --password-stdin "${ECR_URL}"
docker build -t "${ECR_URL}:latest" ../mcp_server/
docker push "${ECR_URL}:latest"
```

### Step 4 — Seed the EFS filesystem

```bash
export EFS_DNS_NAME=$(terraform output -raw efs_dns_name)
sudo bash ../mock_data/seed_secrets.sh
```

This writes `/mnt/efs-temp/config/credentials.env` and
`/mnt/efs-temp/customers/mock_customers.csv` to the EFS.
Must be run from a host that has NFS access to the EFS (i.e. within the VPC,
or from an EC2 instance in the same subnet).

### Step 5 — Wait for ECS task to reach RUNNING state

```bash
CLUSTER=$(terraform output -raw ecs_cluster_name)
SERVICE=$(terraform output -raw ecs_service_name)
aws ecs describe-services \
  --cluster "${CLUSTER}" \
  --services "${SERVICE}" \
  --query 'services[0].{running:runningCount,desired:desiredCount,status:status}' \
  --output table
```

Expected: `runningCount = 1`. Takes 60–90 seconds after image push.

### Step 6 — Get the ECS task public IP

```bash
TASK_IP=$(terraform output -raw task_public_ip)
echo "Baseline target IP: ${TASK_IP}"
```

### Step 7 — Run baseline attacks

Open a second terminal and start the exfil listener:

```bash
python3 attacks/attacker_listener.py --port 9999
```

In the first terminal:

```bash
cd ../attacks/
./run_all.sh --target-ip "${TASK_IP}" --architecture baseline --region eu-west-1
```

`run_all.sh` manages all sleep delays internally (see Section 6).
After completing the attacks it automatically calls `collect_logs.sh` to score M3.

### Step 8 — Deploy the hardened architecture

```bash
cd ../hardened/
terraform init
terraform apply -var="db_password=<your-chosen-password>"
```

Expected duration: **10–15 minutes** (NAT Gateway + RDS).

### Step 9 — Build and push the hardened Docker image

```bash
ECR_URL=$(terraform output -raw ecr_repository_url)
aws ecr get-login-password --region eu-west-1 \
  | docker login --username AWS --password-stdin "${ECR_URL}"
docker build -t "${ECR_URL}:latest" ../mcp_server_hardened/
docker push "${ECR_URL}:latest"
```

### Step 10 — Seed the hardened EFS (customers only — no credentials)

```bash
export EFS_DNS_NAME=$(terraform output -raw efs_dns_name)
sudo bash ../mock_data/seed_secrets_hardened.sh
```

### Step 11 — Run hardened attacks

```bash
cd ../attacks/
./run_all.sh --architecture hardened --region eu-west-1
```

`run_all.sh` detects the hardened architecture, automatically creates a
temporary EC2 attacker instance in the private subnet (using SSM — no SSH key
required), executes the attacks from inside the VPC, retrieves results, and
terminates the EC2 on completion.

### Step 12 — Generate result charts

```bash
python3 results/visualise_results.py \
  --results-dir results \
  --output-dir results/charts
```

Charts are saved as PNG files in `results/charts/`.

### Step 13 — Validate checklist against Terraform state

```bash
# Baseline (expected-fail mode)
terraform -chdir=baseline show -json > /tmp/baseline_state.json
python3 checklist/checklist_validator.py \
  --state-file /tmp/baseline_state.json \
  --architecture baseline

# Hardened (all items should PASS or UNKNOWN)
terraform -chdir=hardened show -json > /tmp/hardened_state.json
python3 checklist/checklist_validator.py \
  --state-file /tmp/hardened_state.json \
  --architecture hardened
```

---

## 5. Cleanup

Destroy resources in this order (**hardened first**, then baseline):

```bash
cd hardened/ && terraform destroy
cd ../baseline/ && terraform destroy
```

If the architectures share no VPC resources (they use separate VPCs as
designed), order does not strictly matter — but destroying hardened first
is good practice to avoid any implicit dependencies.

Also clean up any manually-created resources:
- The IAM role `mcp-attacker-ssm-role` and instance profile
  `mcp-attacker-ssm-profile` created by `run_all.sh` are not managed by
  Terraform and must be deleted manually via the AWS console or CLI if no
  longer needed.

---

## 6. Known Timing Constraints

All sleep durations in `run_all.sh` are documented here for the reader's reference.
Do not reduce them — shorter windows produce incomplete M3 results.

| Event | Typical wait | Buffer used |
|---|---|---|
| RDS `available` after `terraform apply` | 4–8 minutes | Wait for poll confirmation before seeding |
| EFS mount target `available` after apply | ~90 seconds | Wait for poll confirmation before seeding |
| ECS task `RUNNING` after image push | 60–90 seconds | Wait for poll confirmation before attacks |
| CloudWatch log propagation after event | 30–150 seconds | `run_all.sh` waits **150 seconds** |
| CloudTrail S3 delivery after API call | 5–15 minutes | `run_all.sh` waits **900 seconds** (15 min) |
| Attacker EC2 status checks pass | 60–120 seconds | `run_all.sh` polls every 15s, max 5 min |
| SSM agent registration on attacker EC2 | ~30 seconds | `run_all.sh` sleeps 30s after status checks pass |

If CloudTrail events are still missing after `collect_logs.sh` completes,
re-run with extra wait time:

```bash
./collect_logs.sh --architecture hardened --cloudtrail-extra-wait 600
```

---

## 7. Ethical Statement

All experiments are conducted within a purpose-built AWS account using
synthetic data. No real credentials, customer data, or third-party
infrastructure are used at any stage.

The mock credential strings (e.g. `AKIAIOSFODNN7EXAMPLE`) are publicly
documented AWS example values that are not associated with any real account.
Their inclusion in the baseline architecture is intentional and documented as
the pre-control attack surface.

The attacker listener (`attacker_listener.py`) runs locally on the
researcher's machine and captures data only to a local log file
(`results/exfil_received.log`). No data is sent to external services.

All cloud resources must be decommissioned with `terraform destroy`
immediately after the experimental phase completes. The experiment is
designed to run in a single session; do not leave the baseline architecture
running unattended.

---

*Artefact version: 1.0 | Dublin Business School MSc Cybersecurity | 2025*
