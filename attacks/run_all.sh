#!/usr/bin/env bash
###############################################################################
# attacks/run_all.sh
#
# Orchestrator for all three attack scenarios against baseline or hardened
# architecture.  Handles:
#   baseline  — direct TCP reachability check; runs scenarios locally
#   hardened  — spins up a temporary attacker EC2 in the private subnet,
#               executes attacks via SSM, terminates the EC2 on completion
#
# Sleep durations are not arbitrary:
#   150s  — CloudWatch log propagation buffer (events typically arrive in
#            30–120s; 150s is a conservative safe minimum)
#   900s  — CloudTrail S3 delivery buffer (typically 5–15 min after the
#            API call; 900s = 15 min minimum safe window before querying)
###############################################################################
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
TARGET_IP=""
ARCHITECTURE="baseline"
REGION="eu-west-1"
PORT=8080
SKIP_LISTENER_CHECK=false
CLOUDTRAIL_EXTRA_WAIT=0
ATTACKER_INSTANCE_ID=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-ip)              TARGET_IP="$2";           shift 2 ;;
    --architecture)           ARCHITECTURE="$2";        shift 2 ;;
    --region)                 REGION="$2";              shift 2 ;;
    --port)                   PORT="$2";                shift 2 ;;
    --skip-listener-check)    SKIP_LISTENER_CHECK=true; shift   ;;
    --cloudtrail-extra-wait)  CLOUDTRAIL_EXTRA_WAIT="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ "${ARCHITECTURE}" != "baseline" && "${ARCHITECTURE}" != "hardened" ]]; then
  echo "ERROR: --architecture must be 'baseline' or 'hardened'" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Cleanup trap — terminates attacker EC2 if hardened run fails mid-way
# ---------------------------------------------------------------------------
cleanup() {
  if [[ -n "${ATTACKER_INSTANCE_ID}" ]]; then
    echo "Cleanup: terminating attacker EC2 ${ATTACKER_INSTANCE_ID} ..."
    aws ec2 terminate-instances \
      --instance-ids "${ATTACKER_INSTANCE_ID}" \
      --region "${REGION}" >/dev/null 2>&1 || true
    echo "Cleanup: termination requested."
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Create results directory
# ---------------------------------------------------------------------------
mkdir -p "${REPO_ROOT}/results/${ARCHITECTURE}"

# ---------------------------------------------------------------------------
# 2. Architecture-specific setup
# ---------------------------------------------------------------------------
if [[ "${ARCHITECTURE}" == "baseline" ]]; then
  # ── Baseline: verify TCP reachability ───────────────────────────────────
  if [[ -z "${TARGET_IP}" ]]; then
    echo "ERROR: --target-ip is required for baseline architecture." >&2
    echo "Get it with: terraform -chdir=${REPO_ROOT}/baseline output -raw task_public_ip" >&2
    exit 1
  fi

  echo "Checking TCP reachability of ${TARGET_IP}:${PORT} ..."
  if ! python3 -c "
import socket, sys
try:
    s = socket.create_connection(('${TARGET_IP}', ${PORT}), timeout=10)
    s.close()
    print('TCP check PASSED')
except Exception as e:
    print(f'TCP check FAILED: {e}')
    sys.exit(1)
"; then
    echo "ERROR: ${TARGET_IP}:${PORT} is not reachable." >&2
    echo "Ensure the ECS task is in RUNNING state and the Docker image is pushed to ECR." >&2
    exit 1
  fi

else
  # ── Hardened: spin up attacker EC2 in private subnet ────────────────────
  echo ""
  echo "WARNING: Hardened architecture has no public IP."
  echo "Attacks will be executed from a temporary EC2 attacker instance inside the VPC."
  echo "Ensure AWS credentials are configured for the research account."
  echo ""

  # Get VPC/subnet from hardened Terraform outputs
  echo "Reading Terraform outputs from hardened/ ..."
  HARDENED_DIR="${REPO_ROOT}/hardened"
  TF_OUTPUTS=$(terraform -chdir="${HARDENED_DIR}" output -json 2>/dev/null)
  PRIVATE_SUBNET_ID=$(echo "${TF_OUTPUTS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['private_subnet_id']['value'])")
  VPC_ID=$(echo "${TF_OUTPUTS}"             | python3 -c "import sys,json; print(json.load(sys.stdin)['vpc_id']['value'])")
  ECS_CLUSTER=$(echo "${TF_OUTPUTS}"        | python3 -c "import sys,json; print(json.load(sys.stdin)['ecs_cluster_name']['value'])")
  ECS_SERVICE=$(echo "${TF_OUTPUTS}"        | python3 -c "import sys,json; print(json.load(sys.stdin)['ecs_service_name']['value'])")

  echo "VPC ID:          ${VPC_ID}"
  echo "Private subnet:  ${PRIVATE_SUBNET_ID}"
  echo "ECS cluster:     ${ECS_CLUSTER}"

  # ── Find latest Amazon Linux 2023 AMI ────────────────────────────────────
  echo "Looking up Amazon Linux 2023 AMI ..."
  AL2023_AMI=$(aws ec2 describe-images \
    --owners amazon \
    --filters \
      "Name=name,Values=al2023-ami-2023.*-x86_64" \
      "Name=state,Values=available" \
    --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
    --output text \
    --region "${REGION}")
  echo "AMI: ${AL2023_AMI}"

  # ── Create SSM IAM instance profile (idempotent) ─────────────────────────
  SSM_PROFILE_NAME="mcp-attacker-ssm-profile"
  SSM_ROLE_NAME="mcp-attacker-ssm-role"

  # Create role if it doesn't exist
  aws iam get-role --role-name "${SSM_ROLE_NAME}" >/dev/null 2>&1 || \
  aws iam create-role \
    --role-name "${SSM_ROLE_NAME}" \
    --assume-role-policy-document '{
      "Version":"2012-10-17",
      "Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]
    }' >/dev/null

  aws iam attach-role-policy \
    --role-name "${SSM_ROLE_NAME}" \
    --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" 2>/dev/null || true

  aws iam attach-role-policy \
    --role-name "${SSM_ROLE_NAME}" \
    --policy-arn "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess" 2>/dev/null || true

  # Create instance profile if it doesn't exist
  aws iam get-instance-profile --instance-profile-name "${SSM_PROFILE_NAME}" >/dev/null 2>&1 || {
    aws iam create-instance-profile --instance-profile-name "${SSM_PROFILE_NAME}" >/dev/null
    aws iam add-role-to-instance-profile \
      --instance-profile-name "${SSM_PROFILE_NAME}" \
      --role-name "${SSM_ROLE_NAME}" >/dev/null
    echo "Waiting 10s for instance profile to propagate ..."
    sleep 10
  }

  # ── Create attacker SG (outbound TCP/8080 to ECS SG) ─────────────────────
  ATTACKER_SG_NAME="mcp-hardened-attacker-sg"
  EXISTING_SG=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=${ATTACKER_SG_NAME}" "Name=vpc-id,Values=${VPC_ID}" \
    --query 'SecurityGroups[0].GroupId' --output text --region "${REGION}" 2>/dev/null || echo "")

  if [[ -z "${EXISTING_SG}" || "${EXISTING_SG}" == "None" ]]; then
    ATTACKER_SG_ID=$(aws ec2 create-security-group \
      --group-name "${ATTACKER_SG_NAME}" \
      --description "Temporary attacker EC2 SG — outbound 8080 to ECS" \
      --vpc-id "${VPC_ID}" \
      --region "${REGION}" \
      --query 'GroupId' --output text)
    aws ec2 create-tags \
      --resources "${ATTACKER_SG_ID}" \
      --tags "Key=Name,Value=mcp-hardened-attacker-sg" \
      --region "${REGION}"
    # Allow all outbound (SSM needs 443; attacks need 8080)
    aws ec2 authorize-security-group-egress \
      --group-id "${ATTACKER_SG_ID}" \
      --protocol tcp --port 0-65535 \
      --cidr "10.0.0.0/16" \
      --region "${REGION}" 2>/dev/null || true
    aws ec2 authorize-security-group-egress \
      --group-id "${ATTACKER_SG_ID}" \
      --protocol tcp --port 443 \
      --cidr "0.0.0.0/0" \
      --region "${REGION}" 2>/dev/null || true
  else
    ATTACKER_SG_ID="${EXISTING_SG}"
  fi
  echo "Attacker SG: ${ATTACKER_SG_ID}"

  # ── Launch attacker EC2 ───────────────────────────────────────────────────
  echo "Launching attacker EC2 (t3.micro, private subnet, no public IP) ..."
  ATTACKER_INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "${AL2023_AMI}" \
    --instance-type "t3.micro" \
    --subnet-id "${PRIVATE_SUBNET_ID}" \
    --security-group-ids "${ATTACKER_SG_ID}" \
    --iam-instance-profile "Name=${SSM_PROFILE_NAME}" \
    --no-associate-public-ip-address \
    --tag-specifications \
      "ResourceType=instance,Tags=[{Key=Name,Value=mcp-hardened-attacker-ec2}]" \
    --region "${REGION}" \
    --query 'Instances[0].InstanceId' \
    --output text)
  echo "Attacker instance ID: ${ATTACKER_INSTANCE_ID}"

  # ── Wait for EC2 status checks ────────────────────────────────────────────
  echo "Waiting for EC2 status checks to pass (poll every 15s, max 5 min) ..."
  for i in $(seq 1 20); do
    STATUS=$(aws ec2 describe-instance-status \
      --instance-ids "${ATTACKER_INSTANCE_ID}" \
      --region "${REGION}" \
      --query 'InstanceStatuses[0].InstanceStatus.Status' \
      --output text 2>/dev/null || echo "")
    echo "  [${i}/20] Status: ${STATUS}"
    if [[ "${STATUS}" == "ok" ]]; then
      echo "  EC2 status checks passed."
      break
    fi
    sleep 15
  done

  # Wait for SSM agent to register
  echo "Waiting 30s for SSM agent registration ..."
  sleep 30

  # ── Get ECS task private IP ───────────────────────────────────────────────
  echo "Retrieving ECS task private IP ..."
  TASK_ARN=$(aws ecs list-tasks \
    --cluster "${ECS_CLUSTER}" \
    --service-name "${ECS_SERVICE}" \
    --region "${REGION}" \
    --query 'taskArns[0]' \
    --output text)
  ENI_ID=$(aws ecs describe-tasks \
    --cluster "${ECS_CLUSTER}" \
    --tasks "${TASK_ARN}" \
    --region "${REGION}" \
    --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value | [0]' \
    --output text)
  TARGET_IP=$(aws ec2 describe-network-interfaces \
    --network-interface-ids "${ENI_ID}" \
    --region "${REGION}" \
    --query 'NetworkInterfaces[0].PrivateIpAddress' \
    --output text)
  echo "ECS task private IP: ${TARGET_IP}"

  # ── Stage attack scripts to S3 ───────────────────────────────────────────
  STAGING_BUCKET="mcp-attacker-staging-$(python3 -c "import random,string; print(''.join(random.choices(string.hexdigits[:16], k=6))).lower()")"
  echo "Creating S3 staging bucket: ${STAGING_BUCKET} ..."
  aws s3 mb "s3://${STAGING_BUCKET}" --region "${REGION}" >/dev/null
  aws s3 cp "${SCRIPT_DIR}/scenario_a.py"        "s3://${STAGING_BUCKET}/attacks/scenario_a.py"        --region "${REGION}"
  aws s3 cp "${SCRIPT_DIR}/scenario_b.py"        "s3://${STAGING_BUCKET}/attacks/scenario_b.py"        --region "${REGION}"
  aws s3 cp "${SCRIPT_DIR}/scenario_c.py"        "s3://${STAGING_BUCKET}/attacks/scenario_c.py"        --region "${REGION}"
  aws s3 cp "${SCRIPT_DIR}/attacker_listener.py" "s3://${STAGING_BUCKET}/attacks/attacker_listener.py" --region "${REGION}"

  echo "Attack scripts staged to s3://${STAGING_BUCKET}/attacks/"
fi

# ---------------------------------------------------------------------------
# 4. Record experiment start time
# ---------------------------------------------------------------------------
EXPERIMENT_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo ""
echo "============================================================"
echo " Experiment START: ${EXPERIMENT_START}"
echo " Architecture:     ${ARCHITECTURE}"
echo " Target IP:        ${TARGET_IP}"
echo " Region:           ${REGION}"
echo "============================================================"
echo ""

# ---------------------------------------------------------------------------
# Helper: run a Python attack script (local or via SSM on attacker EC2)
# ---------------------------------------------------------------------------
run_scenario() {
  local script="$1"
  shift
  local extra_args=("$@")

  if [[ "${ARCHITECTURE}" == "baseline" ]]; then
    python3 "${SCRIPT_DIR}/${script}" \
      --target-ip "${TARGET_IP}" \
      --port "${PORT}" \
      --architecture "${ARCHITECTURE}" \
      "${extra_args[@]}"
  else
    # Build the command string for SSM
    local cmd_str="cd /home/ssm-user && mkdir -p attacks results/hardened && "
    cmd_str+="aws s3 cp s3://${STAGING_BUCKET}/attacks/ attacks/ --recursive --region ${REGION} --quiet && "
    cmd_str+="pip3 install --quiet mcp httpx psycopg2-binary boto3 2>/dev/null; "
    cmd_str+="python3 attacks/${script} --target-ip ${TARGET_IP} --port ${PORT} --architecture hardened"
    for arg in "${extra_args[@]}"; do
      cmd_str+=" ${arg}"
    done
    cmd_str+=" && aws s3 cp results/hardened/ s3://${STAGING_BUCKET}/results/hardened/ --recursive --region ${REGION} --quiet"

    local cmd_id
    cmd_id=$(aws ssm send-command \
      --instance-ids "${ATTACKER_INSTANCE_ID}" \
      --document-name "AWS-RunShellScript" \
      --parameters "commands=[\"${cmd_str}\"]" \
      --region "${REGION}" \
      --query 'Command.CommandId' \
      --output text)

    echo "  SSM command ID: ${cmd_id} — waiting for completion ..."
    aws ssm wait command-executed \
      --command-id "${cmd_id}" \
      --instance-id "${ATTACKER_INSTANCE_ID}" \
      --region "${REGION}" 2>/dev/null || true

    # Retrieve output
    aws ssm get-command-invocation \
      --command-id "${cmd_id}" \
      --instance-id "${ATTACKER_INSTANCE_ID}" \
      --region "${REGION}" \
      --query 'StandardOutputContent' \
      --output text || true

    # Pull results JSON back from S3
    aws s3 cp \
      "s3://${STAGING_BUCKET}/results/hardened/" \
      "${REPO_ROOT}/results/hardened/" \
      --recursive --region "${REGION}" --quiet 2>/dev/null || true
  fi
}

# ---------------------------------------------------------------------------
# 5. Run Scenario A
# ---------------------------------------------------------------------------
echo "[run_all.sh] Starting Scenario A at $(date -u +%H:%M:%SZ)"
run_scenario "scenario_a.py"
echo "[run_all.sh] Scenario A complete at $(date -u +%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# 6. Brief gap between scenarios
# ---------------------------------------------------------------------------
echo "[run_all.sh] Sleeping 10s between Scenario A and B ..."
sleep 10

# ---------------------------------------------------------------------------
# 7. Start attacker_listener.py (background)
# ---------------------------------------------------------------------------
LISTENER_LOG="${REPO_ROOT}/results/${ARCHITECTURE}/listener_stdout.log"
LISTENER_URL="http://127.0.0.1:${PORT}"
LISTENER_EXFIL="${REPO_ROOT}/results/exfil_received.log"

if [[ "${ARCHITECTURE}" == "baseline" ]]; then
  if [[ "${SKIP_LISTENER_CHECK}" == "false" ]]; then
    echo "[run_all.sh] Starting attacker_listener.py on port 9999 ..."
    python3 "${SCRIPT_DIR}/attacker_listener.py" \
      --port 9999 \
      --output-file "${LISTENER_EXFIL}" \
      > "${LISTENER_LOG}" 2>&1 &
    LISTENER_PID=$!
    LISTENER_URL="http://127.0.0.1:9999"
    echo "[run_all.sh] Listener PID: ${LISTENER_PID}"
    sleep 2  # give listener time to bind
  else
    LISTENER_URL="http://127.0.0.1:9999"
    LISTENER_PID=""
  fi
else
  # For hardened, listener runs on the attacker EC2; start via SSM
  LISTENER_URL="http://127.0.0.1:9999"
  LISTENER_PID=""
  LISTENER_CMD="nohup python3 attacks/attacker_listener.py --port 9999 --output-file results/exfil_received.log > /tmp/listener.log 2>&1 &"
  aws ssm send-command \
    --instance-ids "${ATTACKER_INSTANCE_ID}" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[\"cd /home/ssm-user && ${LISTENER_CMD}\"]" \
    --region "${REGION}" \
    --query 'Command.CommandId' \
    --output text >/dev/null
  sleep 3
fi

# ---------------------------------------------------------------------------
# 8. Run Scenario B
# ---------------------------------------------------------------------------
echo "[run_all.sh] Starting Scenario B at $(date -u +%H:%M:%SZ)"
run_scenario "scenario_b.py" "--listener-url" "${LISTENER_URL}"
echo "[run_all.sh] Scenario B complete at $(date -u +%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# 9. Stop attacker listener
# ---------------------------------------------------------------------------
if [[ -n "${LISTENER_PID:-}" ]]; then
  echo "[run_all.sh] Stopping listener (PID ${LISTENER_PID}) ..."
  kill "${LISTENER_PID}" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 10. Gap between Scenario B and C
# ---------------------------------------------------------------------------
echo "[run_all.sh] Sleeping 10s between Scenario B and C ..."
sleep 10

# ---------------------------------------------------------------------------
# 11. Run Scenario C
# ---------------------------------------------------------------------------
echo "[run_all.sh] Starting Scenario C at $(date -u +%H:%M:%SZ)"
run_scenario "scenario_c.py" "--aws-region" "${REGION}"
echo "[run_all.sh] Scenario C complete at $(date -u +%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# 12. Record experiment end time
# ---------------------------------------------------------------------------
EXPERIMENT_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo ""
echo "============================================================"
echo " Experiment END:   ${EXPERIMENT_END}"
echo "============================================================"
echo ""

# ---------------------------------------------------------------------------
# 13. Write run manifest
# ---------------------------------------------------------------------------
MANIFEST_PATH="${REPO_ROOT}/results/${ARCHITECTURE}/run_manifest.json"
python3 - << PYEOF
import json
manifest = {
    "architecture": "${ARCHITECTURE}",
    "start":        "${EXPERIMENT_START}",
    "end":          "${EXPERIMENT_END}",
    "target_ip":    "${TARGET_IP}",
    "region":       "${REGION}",
    "port":         ${PORT},
}
with open("${MANIFEST_PATH}", "w") as fh:
    json.dump(manifest, fh, indent=2)
print(f"Manifest written to ${MANIFEST_PATH}")
PYEOF

# ---------------------------------------------------------------------------
# 14. Wait for CloudWatch log propagation (150s) + CloudTrail delivery (900s)
# ---------------------------------------------------------------------------
echo ""
echo "Attacks complete. Waiting 150 seconds for CloudWatch log propagation..."
sleep 150

echo "Waiting additional 900 seconds for CloudTrail S3 delivery..."
sleep 900

echo "Log propagation window complete. Running collect_logs.sh..."
echo ""

# ---------------------------------------------------------------------------
# 15. Call collect_logs.sh
# ---------------------------------------------------------------------------
bash "${SCRIPT_DIR}/collect_logs.sh" \
  --architecture "${ARCHITECTURE}" \
  --region "${REGION}" \
  --cloudtrail-extra-wait "${CLOUDTRAIL_EXTRA_WAIT}"

# ---------------------------------------------------------------------------
# 16. Terminate attacker EC2 (hardened only) — also handled by trap EXIT
# ---------------------------------------------------------------------------
if [[ "${ARCHITECTURE}" == "hardened" && -n "${ATTACKER_INSTANCE_ID}" ]]; then
  echo "[run_all.sh] Terminating attacker EC2 ${ATTACKER_INSTANCE_ID} ..."
  aws ec2 terminate-instances \
    --instance-ids "${ATTACKER_INSTANCE_ID}" \
    --region "${REGION}" \
    --query 'TerminatingInstances[0].CurrentState.Name' \
    --output text
  echo "[run_all.sh] Termination confirmed."

  # Clean up staging bucket
  echo "[run_all.sh] Removing S3 staging bucket ${STAGING_BUCKET} ..."
  aws s3 rb "s3://${STAGING_BUCKET}" --force --region "${REGION}" >/dev/null 2>&1 || true

  ATTACKER_INSTANCE_ID=""  # prevent double-terminate in trap
fi

echo ""
echo "run_all.sh finished. Review results in: results/${ARCHITECTURE}/"
