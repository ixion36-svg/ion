# Arkime 6.1.1 from official packages
FROM ubuntu:24.04

ARG ARKIME_VERSION=6.1.1
ARG DEBIAN_FRONTEND=noninteractive

# Install dependencies first
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install official Arkime package (let apt fix deps)
RUN curl -fSL "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/arkime_${ARKIME_VERSION}-1.ubuntu2404_amd64.deb" \
    -o /tmp/arkime.deb \
    && apt-get update \
    && apt-get install -y -f /tmp/arkime.deb \
    && rm /tmp/arkime.deb \
    && rm -rf /var/lib/apt/lists/*

# Create data directories
RUN mkdir -p /opt/arkime/raw /opt/arkime/logs

# Copy entrypoint
COPY entrypoint.sh /opt/arkime/entrypoint.sh
RUN chmod +x /opt/arkime/entrypoint.sh

EXPOSE 8005

WORKDIR /opt/arkime
ENTRYPOINT ["/opt/arkime/entrypoint.sh"]
