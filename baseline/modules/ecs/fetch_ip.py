#!/usr/bin/env python3
"""
Terraform external data source: poll ECS for a Fargate task public IP.

Protocol (Terraform external provider):
  - Reads a JSON object from stdin  : {"cluster": "...", "service": "...", "region": "..."}
  - Writes a JSON object to stdout  : {"public_ip": "<ip-or-sentinel>"}
  - Exits 0 always (errors returned as sentinel value to avoid Terraform crash)

Polls every 15 seconds for up to 6 minutes (24 iterations).
If the Docker image has not yet been pushed to ECR the task will be in
PENDING/STOPPED state and the sentinel "unavailable-push-image-and-reapply"
is returned. Resolution: push the image then run 'terraform apply' again.
"""

import json
import subprocess
import sys
import time


POLL_INTERVAL = 15   # seconds between polls
MAX_ATTEMPTS  = 24   # 24 x 15s = 6 minutes


def aws(*args):
    """Run an AWS CLI command; return (stdout_stripped, returncode)."""
    result = subprocess.run(
        ["aws"] + list(args),
        capture_output=True,
        text=True,
    )
    return result.stdout.strip(), result.returncode


def main():
    query   = json.load(sys.stdin)
    cluster = query["cluster"]
    service = query["service"]
    region  = query["region"]

    for _ in range(MAX_ATTEMPTS):
        # Step 1: find a running task ARN
        task_arn, rc = aws(
            "ecs", "list-tasks",
            "--cluster",      cluster,
            "--service-name", service,
            "--region",       region,
            "--query",        "taskArns[0]",
            "--output",       "text",
        )
        if rc != 0 or not task_arn or task_arn in ("None", "null", ""):
            time.sleep(POLL_INTERVAL)
            continue

        # Step 2: extract the Elastic Network Interface ID
        eni, rc = aws(
            "ecs", "describe-tasks",
            "--cluster", cluster,
            "--tasks",   task_arn,
            "--region",  region,
            "--query",
            "tasks[0].attachments[0].details[?name==`networkInterfaceId`].value | [0]",
            "--output",  "text",
        )
        if rc != 0 or not eni or eni in ("None", "null", ""):
            time.sleep(POLL_INTERVAL)
            continue

        # Step 3: get the public IP from the ENI
        public_ip, rc = aws(
            "ec2", "describe-network-interfaces",
            "--network-interface-ids", eni,
            "--region",  region,
            "--query",   "NetworkInterfaces[0].Association.PublicIp",
            "--output",  "text",
        )
        if rc == 0 and public_ip and public_ip not in ("None", "null", ""):
            print(json.dumps({"public_ip": public_ip}))
            sys.exit(0)

        time.sleep(POLL_INTERVAL)

    # Task never became reachable (image not pushed yet)
    print(json.dumps({"public_ip": "unavailable-push-image-and-reapply"}))
    sys.exit(0)


if __name__ == "__main__":
    main()
