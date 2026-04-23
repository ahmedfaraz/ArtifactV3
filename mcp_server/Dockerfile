# Baseline MCP Server — DELIBERATELY MISCONFIGURED
#
# Intentional misconfigurations (mirrors ECS task definition weaknesses):
#   - No USER directive: process runs as root (uid 0)
#   - No read-only root filesystem flag (set in task definition)
#   - No capability dropping (set in task definition)
#   - No health-check (visibility intentionally reduced)
#   - Image tag mutability: MUTABLE (set in ECR resource)

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app.py .

EXPOSE 8080

CMD ["python", "app.py"]
