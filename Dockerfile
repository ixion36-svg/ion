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

# v0.26.0: Software Bill of Materials (SBOM) generation via syft.
# Closes the SDLC §8 SBOM gap. Generated at build time against the
# resolved venv so the SPDX-JSON output lists every Python package
# pip actually installed (not just declared deps). Syft is installed
# as a pinned static binary so the SBOM-tool layer is reproducible.
# The generated artefact is copied into Stage 2 at /app/sbom.spdx.json;
# the syft binary itself is NOT shipped to the runtime image.
#
# Verify post-build:
#   docker run --rm ixion36/ion:vX.Y.Z cat /app/sbom.spdx.json | head -20
# v0.35.0: syft is sourced from its official Docker Hub image via COPY
# --from rather than curl-installed from GitHub. The Docker Desktop build
# VM has intermittent GitHub egress (github.com IPv6 dead-routes, raw
# .githubusercontent connect timeouts); Docker Hub is reliable. This also
# removes a build-time GitHub dependency, which suits the air-gapped ethos.
# The syft binary is a static Go executable, so it runs as-is in the
# python:3.14-slim builder. Pin the tag to keep SBOM tooling reproducible.
ARG SYFT_VERSION=1.44.0
COPY --from=anchore/syft:v1.44.0 /syft /usr/local/bin/syft
RUN syft /opt/venv -o spdx-json=/build/sbom.spdx.json && \
    rm -f /usr/local/bin/syft

# ============================================================================
# Stage 2: Runtime stage - minimal image
# ============================================================================
FROM python:3.14-slim AS runtime

LABEL org.opencontainers.image.title="ION" \
      org.opencontainers.image.description="Intelligent Operating Network - Security Operations Portal" \
      org.opencontainers.image.version="0.80.2" \
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

# v0.26.0: copy the SBOM generated in the builder stage. Deployers can
# extract it with `docker cp <container>:/app/sbom.spdx.json .` for
# supplier-assurance auditing.
COPY --from=builder /build/sbom.spdx.json /app/sbom.spdx.json

# Copy application source, seed scripts, and entrypoint
COPY src/ src/
# Only ship production seed scripts — dev-only seeds (alerts, observables,
# skills_team, etc.) contain hardcoded test data and should not be in the image.
COPY seed_all.py seed_ion_data.py seed_knowledge_base.py \
     seed_knowledge_base_blueteam.py seed_knowledge_base_foundations.py \
     seed_knowledge_base_security_fundamentals.py \
     seed_playbooks.py seed_soc_templates.py seed_courses.py \
     seed_lab_fixtures.py /app/
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

# Health check.
#
# v0.79.2: start-period 10s -> 90s. Boot runs migrations plus ~12 advisory-
# locked seeders before the workers can answer anything; first successful probe
# on a 4-CPU host is ~40s. compose overrides this for compose-started
# containers, but a plain `docker run` of the image gets THIS one — so it has
# to be realistic too, or the image looks broken for its first half-minute
# under any orchestrator that acts on health.
#
# Probes that fail inside the start period do not count toward --retries, so
# widening it costs nothing at steady state.
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

# Switch to non-root user
USER ion

# Entrypoint handles initialization
ENTRYPOINT ["docker-entrypoint.sh"]
