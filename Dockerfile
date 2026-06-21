# ──────────────────────────────────────────────────────────────────────────────
# SENTINEL GRC — Production Docker Image
# Multi-stage build for minimal footprint
# ──────────────────────────────────────────────────────────────────────────────

# Stage 1: Build
FROM python:3.11-slim AS builder
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ src/

RUN pip install --upgrade pip \
    && pip install --prefix=/install -e .

# Stage 2: Runtime
FROM python:3.11-slim AS runtime
LABEL maintainer="SENTINEL GRC"
LABEL version="1.1.0"
LABEL description="Deterministic Vendor Risk Scoring Engine — Enterprise GRC Pipeline"

WORKDIR /sentinel

# Copy installed packages from builder
COPY --from=builder /install /usr/local
COPY --from=builder /build /sentinel

# Copy rules, assets, and data
COPY src/vendor_risk_engine/rules/ /sentinel/src/vendor_risk_engine/rules/
COPY assets/ /sentinel/assets/
COPY data/ /sentinel/data/

# Create output directory
RUN mkdir -p /sentinel/output/audit

# Non-root user for security hardening
RUN useradd -m -u 1001 sentinel && chown -R sentinel:sentinel /sentinel
USER sentinel

# Environment defaults (override via docker-compose or --env-file)
ENV QUESTIONNAIRE_SCHEMA_PATH=/sentinel/src/vendor_risk_engine/rules/questionnaire_schema.yaml
ENV WEIGHT_CONFIG_PATH=/sentinel/src/vendor_risk_engine/rules/weight_config.yaml
ENV THRESHOLD_CONFIG_PATH=/sentinel/src/vendor_risk_engine/rules/threshold_config.yaml
ENV OUTPUT_DIR=/sentinel/output
ENV LOG_LEVEL=INFO

# Expose FastAPI port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default command: start the REST API server
CMD ["python", "-m", "vendor_risk_engine.main", "api", "--host", "0.0.0.0", "--port", "8000"]
