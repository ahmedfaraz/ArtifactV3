# mcp_server_hardened/Dockerfile
#
# Hardened image changes vs baseline:
#   + Non-root user: mcpuser (uid/gid 1000) — matches EFS access point POSIX uid
#   + USER 1000 directive — process cannot write outside permitted mount points
#
# readonlyRootFilesystem and noNewPrivileges are set in the ECS task
# definition (hardened/modules/ecs/main.tf), not the Dockerfile.
#
# Build and push:
#   ECR_URL=$(terraform -chdir=hardened output -raw ecr_repository_url)
#   docker build -t ${ECR_URL}:latest mcp_server_hardened/
#   aws ecr get-login-password --region eu-west-1 \
#     | docker login --username AWS --password-stdin ${ECR_URL}
#   docker push ${ECR_URL}:latest

FROM python:3.12-slim

WORKDIR /app

# Create non-root user mcpuser (uid 1000, gid 1000)
# uid 1000 matches:
#   - EFS access point posix_user.uid = 1000
#   - ECS task definition user = "1000"
RUN groupadd -r mcpuser && useradd -r -g mcpuser -u 1000 mcpuser

# Install dependencies (as root, before switching user)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .

# Set ownership of app directory
RUN chown -R mcpuser:mcpuser /app

EXPOSE 8080

# Switch to non-root user — process runs as uid 1000
USER 1000

CMD ["python3", "app.py"]
