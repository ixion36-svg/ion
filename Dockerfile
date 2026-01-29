# IXION - Air-gapped Deployment Image
# Intelligence eXchange & Integration Operations Network
# Part of Guarded Glass Security Toolkit
# Multi-stage build for smaller final image

# ============================================================================
# Stage 1: Build stage - install dependencies
# ============================================================================
FROM python:3.11-slim as builder

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

# Download NLTK data for NLP features
RUN python -c "import nltk; \
    nltk.download('punkt', quiet=True); \
    nltk.download('punkt_tab', quiet=True); \
    nltk.download('averaged_perceptron_tagger', quiet=True); \
    nltk.download('averaged_perceptron_tagger_eng', quiet=True); \
    nltk.download('maxent_ne_chunker', quiet=True); \
    nltk.download('maxent_ne_chunker_tab', quiet=True); \
    nltk.download('words', quiet=True)"

# ============================================================================
# Stage 2: Runtime stage - minimal image
# ============================================================================
FROM python:3.11-slim as runtime

# Security: Run as non-root user
RUN groupadd -r ixion && useradd -r -g ixion ixion

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy NLTK data from builder
COPY --from=builder /root/nltk_data /home/ixion/nltk_data
RUN chown -R ixion:ixion /home/ixion/nltk_data
ENV NLTK_DATA=/home/ixion/nltk_data

# Copy application source and entrypoint
COPY src/ src/
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create data directory for database and config
RUN mkdir -p /data/.ixion && chown -R ixion:ixion /data

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV IXION_DATA_DIR=/data
ENV IXION_HOST=0.0.0.0
ENV IXION_PORT=8000

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/stats')" || exit 1

# Switch to non-root user
USER ixion

# Entrypoint handles initialization
ENTRYPOINT ["docker-entrypoint.sh"]
