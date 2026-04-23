#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# import_state.sh
#
# Re-imports all existing AWS resources into a fresh Terraform state.
# Run this once from the baseline/ directory on any machine that has a
# blank state but whose AWS resources were already created.
#
# Usage:
#   cd ~/ArtifactV3/baseline
#   bash import_state.sh
# ---------------------------------------------------------------------------
set -euo pipefail

REGION="eu-west-1"

echo "==> terraform init"
terraform init -input=false

echo ""
echo "==> Importing VPC resources"
terraform import module.vpc.aws_vpc.main                              vpc-04634c8909a5ea9eb
terraform import module.vpc.aws_subnet.public                         subnet-0628ba3bbca2117a6
terraform import module.vpc.aws_subnet.public_secondary               subnet-0f973e1ab5ae54e46
terraform import module.vpc.aws_internet_gateway.main                 igw-0d0eabdd0c04e6213
terraform import module.vpc.aws_route_table.public                    rtb-0a194d855a195df8a
terraform import module.vpc.aws_route_table_association.public        rtbassoc-055c565e8e02ff868
terraform import module.vpc.aws_route_table_association.public_secondary rtbassoc-094df7460be2199ab
terraform import module.vpc.aws_security_group.ecs                    sg-0bfbee63c55f632c8

echo ""
echo "==> Importing IAM resources"
terraform import module.iam.aws_iam_role.task_execution \
  mcp-baseline-ecs-execution-role
terraform import module.iam.aws_iam_role.task \
  mcp-baseline-ecs-task-role
terraform import module.iam.aws_iam_role_policy.task_overpermissive \
  "mcp-baseline-ecs-task-role:mcp-baseline-task-overpermissive-policy"
terraform import 'module.iam.aws_iam_role_policy_attachment.task_execution_managed' \
  "mcp-baseline-ecs-execution-role/arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"

echo ""
echo "==> Importing EFS resources"
terraform import module.efs.aws_security_group.efs    sg-00b876dbd69cc5a46
terraform import module.efs.aws_efs_file_system.mcp   fs-0385eb6998f401a3b
terraform import module.efs.aws_efs_mount_target.mcp  fsmt-0cf60da4d7fde0e41

echo ""
echo "==> Importing RDS resources"
terraform import module.rds.aws_security_group.rds      sg-0c43431bca0b4cf82
terraform import module.rds.aws_db_subnet_group.mcp     mcp-baseline-db-subnet-group
terraform import module.rds.aws_db_instance.mcp         db-HWTTJD3F752IMEWSZEQSJ3BQGA

echo ""
echo "==> Importing ECS resources"
terraform import module.ecs.aws_cloudwatch_log_group.app  /mcp/baseline/app
terraform import module.ecs.aws_ecr_repository.mcp        mcp-baseline-mcp-server
terraform import module.ecs.aws_ecs_cluster.mcp \
  "arn:aws:ecs:${REGION}:927289246985:cluster/mcp-baseline-ecs-cluster"

echo "    Resolving task definition ARN..."
TASK_DEF_ARN=$(aws ecs describe-task-definition \
  --task-definition mcp-baseline-task \
  --region "${REGION}" \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)
echo "    ARN: ${TASK_DEF_ARN}"
terraform import module.ecs.aws_ecs_task_definition.mcp "${TASK_DEF_ARN}"

terraform import module.ecs.aws_ecs_service.mcp \
  "arn:aws:ecs:${REGION}:927289246985:service/mcp-baseline-ecs-cluster/mcp-baseline-service"

echo ""
echo "==> All imports complete. Running terraform plan to verify..."
terraform plan -input=false
