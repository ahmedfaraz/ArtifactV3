#!/usr/bin/env python3
"""
Terraform external data source helper — polls ECS until the Fargate task
has a private IP, then prints {"private_ip": "<ip>"} to stdout.
Reads cluster/service/region as JSON from stdin (Terraform external protocol).
"""
import json
import subprocess
import sys
import time


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout.strip()


def main():
    inp = json.load(sys.stdin)
    cluster = inp["cluster"]
    service = inp["service"]
    region = inp["region"]

    for _ in range(24):
        task = run([
            "aws", "ecs", "list-tasks",
            "--cluster", cluster,
            "--service-name", service,
            "--region", region,
            "--query", "taskArns[0]",
            "--output", "text",
        ])
        if task and task != "None":
            eni = run([
                "aws", "ecs", "describe-tasks",
                "--cluster", cluster,
                "--tasks", task,
                "--region", region,
                "--query",
                "tasks[0].attachments[0].details[?name==`networkInterfaceId`].value | [0]",
                "--output", "text",
            ])
            if eni and eni != "None":
                ip = run([
                    "aws", "ec2", "describe-network-interfaces",
                    "--network-interface-ids", eni,
                    "--region", region,
                    "--query", "NetworkInterfaces[0].PrivateIpAddress",
                    "--output", "text",
                ])
                if ip and ip != "None":
                    print(json.dumps({"private_ip": ip}))
                    return
        time.sleep(15)

    print(json.dumps({"private_ip": "unavailable-push-image-and-reapply"}))


if __name__ == "__main__":
    main()
