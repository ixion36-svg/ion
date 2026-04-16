# ION - Air-gapped Deployment Image
# Intelligent Operating Network
# Part of Guarded Glass Security Toolkit
# Multi-stage build for smaller final image

# ============================================================================
# Stage 1: Build stage - install dependencies
# ============================================================================
FROM python:3.14-slim AS builder

WORKDIR /build

# Install build dependencies (including libpq-dev for psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libpq-dev \
    libpango1.0-dev \
    libcairo2-dev \
    libgdk-pixbuf-2.0-dev \
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
FROM python:3.14-slim AS runtime

LABEL org.opencontainers.image.title="ION" \
      org.opencontainers.image.description="Intelligent Operating Network - Security Operations Portal" \
      org.opencontainers.image.version="0.9.91" \
      org.opencontainers.image.source="https://hub.docker.com/repository/docker/ixion36/ion"

# Install runtime libraries (PostgreSQL client + WeasyPrint deps + fonts)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libcairo2 \
    libglib2.0-0 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Security: Run as non-root user
RUN groupadd -r ion && useradd -r -g ion ion

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source, seed scripts, and entrypoint
COPY src/ src/
# Only ship production seed scripts — dev-only seeds (alerts, observables,
# skills_team, etc.) contain hardcoded test data and should not be in the image.
COPY seed_all.py seed_ion_data.py seed_knowledge_base.py \
     seed_knowledge_base_blueteam.py seed_knowledge_base_foundations.py \
     seed_knowledge_base_security_fundamentals.py \
     seed_playbooks.py seed_soc_templates.py /app/
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
# ION_DATABASE_URL is set at runtime via docker-compose or entrypoint default
# Do NOT set it here — PostgreSQL hostname doesn't exist during build

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

# Switch to non-root user
USER ion

# Entrypoint handles initialization
ENTRYPOINT ["docker-entrypoint.sh"]
