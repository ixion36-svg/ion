#!/bin/bash
# =============================================================================
# Generate Self-Signed TLS Certificates for DocForge
# =============================================================================
# This script generates self-signed certificates for testing/development.
# For production, use certificates from your organization's CA or Let's Encrypt.
#
# Usage: ./generate-certs.sh [hostname]
# Example: ./generate-certs.sh docforge.local
# =============================================================================

set -e

HOSTNAME="${1:-localhost}"
SSL_DIR="./ssl"
DAYS_VALID=365

echo "=============================================="
echo "Generating Self-Signed TLS Certificates"
echo "=============================================="
echo "Hostname: ${HOSTNAME}"
echo "Valid for: ${DAYS_VALID} days"
echo ""

# Create SSL directory
mkdir -p "${SSL_DIR}"

# Generate private key
echo "[1/3] Generating private key..."
openssl genrsa -out "${SSL_DIR}/server.key" 2048

# Generate certificate signing request
echo "[2/3] Generating certificate signing request..."
openssl req -new \
    -key "${SSL_DIR}/server.key" \
    -out "${SSL_DIR}/server.csr" \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=DocForge/CN=${HOSTNAME}"

# Generate self-signed certificate
echo "[3/3] Generating self-signed certificate..."
openssl x509 -req \
    -days ${DAYS_VALID} \
    -in "${SSL_DIR}/server.csr" \
    -signkey "${SSL_DIR}/server.key" \
    -out "${SSL_DIR}/server.crt" \
    -extfile <(printf "subjectAltName=DNS:${HOSTNAME},DNS:localhost,IP:127.0.0.1")

# Set permissions
chmod 600 "${SSL_DIR}/server.key"
chmod 644 "${SSL_DIR}/server.crt"

# Clean up CSR
rm -f "${SSL_DIR}/server.csr"

echo ""
echo "=============================================="
echo "Certificates generated successfully!"
echo "=============================================="
echo ""
echo "Files created:"
echo "  - ${SSL_DIR}/server.crt (certificate)"
echo "  - ${SSL_DIR}/server.key (private key)"
echo ""
echo "WARNING: These are self-signed certificates."
echo "For production, use certificates from a trusted CA."
echo ""

# Show certificate info
echo "Certificate details:"
openssl x509 -in "${SSL_DIR}/server.crt" -noout -subject -dates
