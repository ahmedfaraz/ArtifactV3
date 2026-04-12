# baseline/mcp_server/Dockerfile
#
# Deliberately insecure baseline image:
#   - No USER directive: process runs as root (uid 0)
#   - No readonlyRootFilesystem (set in task definition, not Dockerfile)
#   - No allowPrivilegeEscalation restrictions
#
# Build and push:
#   ECR_URL=$(terraform -chdir=baseline output -raw ecr_repository_url)
#   docker build -t ${ECR_URL}:latest mcp_server/
#   aws ecr get-login-password --region eu-west-1 \
#     | docker login --username AWS --password-stdin ${ECR_URL}
#   docker push ${ECR_URL}:latest

FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .

EXPOSE 8080

# NO USER directive — intentional baseline misconfiguration.
# The process runs as root (uid 0). This is the attack surface for
# Component 1 container hardening metrics (M1/M2).

CMD ["python3", "app.py"]
