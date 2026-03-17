# ION - Air-gapped Deployment Image
# Intelligent Operating Network
# Part of Guarded Glass Security Toolkit
# Multi-stage build for smaller final image

# ============================================================================
# Stage 1: Build stage - install dependencies
# ============================================================================
FROM python:3.14-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install dependencies first (better layer caching)
COPY pyproject.toml .
COPY src/ src/

# Install the package with all dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# ============================================================================
# Stage 2: Runtime stage - minimal image
# ============================================================================
FROM python:3.14-slim as runtime

LABEL org.opencontainers.image.title="ION" \
      org.opencontainers.image.description="Intelligent Operating Network - Security Operations Portal" \
      org.opencontainers.image.version="0.9.15" \
      org.opencontainers.image.source="https://hub.docker.com/repository/docker/ixion36/ion"

# Security: Run as non-root user
RUN groupadd -r ion && useradd -r -g ion ion

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source, seed scripts, and entrypoint
COPY src/ src/
COPY seed_*.py /app/
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create data directory for database and config
RUN mkdir -p /data/.ion && chown -R ion:ion /data

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV ION_DATA_DIR=/data
ENV ION_HOST=0.0.0.0
ENV ION_PORT=8000

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

# Switch to non-root user
USER ion

# Entrypoint handles initialization
ENTRYPOINT ["docker-entrypoint.sh"]
