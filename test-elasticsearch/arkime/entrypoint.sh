#!/bin/bash
set -e

ES_URL="${ARKIME_ELASTICSEARCH:-http://elasticsearch:9200}"
ADMIN_PASS="${ARKIME_ADMIN_PASSWORD:-arkime}"
PASSWORD_SECRET="${ARKIME_PASSWORD_SECRET:-ion-arkime-secret}"

# Write config.ini
cat > /opt/arkime/etc/config.ini << CONF
[default]
elasticsearch=${ES_URL}
rotateIndex=daily
passwordSecret=${PASSWORD_SECRET}
httpRealm=Arkime
interface=eth0
bpf=not port 9200
pcapDir=/opt/arkime/raw
maxFileSizeG=12
freeSpaceG=5%
viewPort=8005
viewHost=0.0.0.0
dropUser=nobody
dropGroup=nogroup
userAuthIps=0.0.0.0/0
CONF

echo "[entrypoint] Waiting for Elasticsearch..."
until curl -sf "${ES_URL}" >/dev/null 2>&1; do
    sleep 2
done
echo "[entrypoint] Elasticsearch is up"

# Initialize or upgrade DB
if ! curl -sf "${ES_URL}/arkime_sequence_v30" >/dev/null 2>&1; then
    echo "[entrypoint] Initializing Arkime DB..."
    /opt/arkime/db/db.pl "${ES_URL}" init --noinput
else
    echo "[entrypoint] Upgrading Arkime DB..."
    echo "UPGRADE" | /opt/arkime/db/db.pl "${ES_URL}" upgrade || true
fi

# Create admin user if not exists
if ! curl -sf "${ES_URL}/arkime_users/_doc/arkime" >/dev/null 2>&1; then
    echo "[entrypoint] Creating admin user..."
    /opt/arkime/bin/arkime_add_user.sh arkime "Admin User" "${ADMIN_PASS}" --admin --packetSearch
fi

echo "[entrypoint] Starting Arkime viewer on port 8005..."
cd /opt/arkime/viewer
exec /opt/arkime/bin/node viewer.js -c /opt/arkime/etc/config.ini
