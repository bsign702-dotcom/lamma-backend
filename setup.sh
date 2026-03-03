#!/bin/bash
set -e

SERVER_NAME="${1:-localhost}"
ADMIN_USER="${2:-admin}"

echo "==> Setting up Matrix Synapse for server: $SERVER_NAME"

# Create data directory
mkdir -p synapse-data postgres-data

# Step 1: Generate homeserver config
echo "==> Generating Synapse config..."
docker run --rm \
  --mount type=bind,src="$(pwd)/synapse-data",dst=/data \
  -e SYNAPSE_SERVER_NAME="$SERVER_NAME" \
  -e SYNAPSE_REPORT_STATS=no \
  matrixdotorg/synapse:latest generate

# Step 2: Patch homeserver.yaml to use PostgreSQL
echo "==> Configuring PostgreSQL database..."
YAML_FILE="synapse-data/homeserver.yaml"

# Replace SQLite database block with PostgreSQL config
python3 - <<'PYEOF'
import re

with open("synapse-data/homeserver.yaml", "r") as f:
    content = f.read()

# Replace database section
sqlite_block = re.search(r'database:\n  name: sqlite3\n  args:\n    database: /data/homeserver\.db', content)
if sqlite_block:
    pg_config = """database:
  name: psycopg2
  args:
    user: synapse
    password: synapse_password
    database: synapse
    host: db
    cp_min: 5
    cp_max: 10"""
    content = content.replace(sqlite_block.group(0), pg_config)
    with open("synapse-data/homeserver.yaml", "w") as f:
        f.write(content)
    print("  PostgreSQL configured.")
else:
    print("  WARNING: Could not find SQLite config block. Check homeserver.yaml manually.")
PYEOF

# Step 3: Enable registration (for local dev only)
echo "==> Enabling user registration..."
python3 - <<'PYEOF'
with open("synapse-data/homeserver.yaml", "r") as f:
    content = f.read()

if "enable_registration:" not in content:
    content += "\nenable_registration: true\nenable_registration_without_verification: true\n"
else:
    content = content.replace("enable_registration: false", "enable_registration: true")

with open("synapse-data/homeserver.yaml", "w") as f:
    f.write(content)
print("  Registration enabled.")
PYEOF

# Step 4: Add registration_shared_secret for admin user creation
echo "==> Adding registration shared secret..."
python3 - <<'PYEOF'
import secrets
with open("synapse-data/homeserver.yaml", "r") as f:
    content = f.read()
if "registration_shared_secret" not in content:
    secret = secrets.token_hex(32)
    content += f"\nregistration_shared_secret: \"{secret}\"\n"
    with open("synapse-data/homeserver.yaml", "w") as f:
        f.write(content)
    print(f"  Shared secret added.")
PYEOF

echo ""
echo "==> Starting services..."
docker compose up -d

echo ""
echo "==> Waiting for Synapse to be healthy..."
until docker compose exec synapse curl -fsSq http://localhost:8008/health 2>/dev/null; do
    printf "."
    sleep 2
done
echo ""

echo ""
echo "==> Creating admin user: $ADMIN_USER"
docker compose exec synapse register_new_matrix_user \
  -u "$ADMIN_USER" \
  -p "changeme123!" \
  -a \
  -c /data/homeserver.yaml \
  http://localhost:8008

echo ""
echo "============================================"
echo " Matrix Synapse is running!"
echo "============================================"
echo " Homeserver:   http://localhost:8008"
echo " Element Web:  http://localhost:8080"
echo ""
echo " Admin user:   @${ADMIN_USER}:${SERVER_NAME}"
echo " Password:     changeme123!"
echo ""
echo " iOS app settings:"
echo "   Homeserver URL: http://localhost:8008"
echo "   or use your Mac's LAN IP for device testing"
echo "============================================"
