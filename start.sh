#!/bin/bash
# Boot YaCy + auth-proxy sidecar for OpenHost.
#
# Topology:
#
#   browser → OpenHost router (gates zone_auth, stamps
#                              X-OpenHost-Is-Owner: true)
#           → container :8080  (auth_proxy.py)
#                  ├─ owner → Authorization: Basic <admin:pw> → YaCy :8090
#                  └─ anon  → passthrough → YaCy :8090
#
#   another YaCy peer (freeworld) → host :8090/tcp → container :8090
#                                 → YaCy Jetty
#
#   anonymous search visitor → router (public_paths matched) →
#                                container :8080 (auth-proxy) → YaCy
#
# First-boot:
#   * Generate random admin password.
#   * Persist {username, password} in admin-credentials.txt.
#   * Run setup_admin.py to seed DATA/SETTINGS/yacy.conf from
#     defaults/yacy.init, hash the password, set port + publicPort.
#
# Subsequent boots load the persisted credentials and just re-run
# setup_admin.py to re-apply our managed yacy.conf fields (defensive
# against operator edits that would break OpenHost integration).

set -euo pipefail

PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/yacy}"
APP_NAME="${OPENHOST_APP_NAME:-yacy}"
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"

# Where YaCy thinks its data lives.  The upstream image has
# WORKDIR /opt at runtime and the YaCy app at
# /opt/yacy_search_server.  yacy.conf is at
# /opt/yacy_search_server/DATA/SETTINGS/yacy.conf, where DATA is a
# named volume in the upstream Dockerfile (VOLUME directive).
#
# OpenHost mounts our app_data at /data/app_data/yacy.  We bind
# YaCy's DATA dir to a sub-directory in our persistent area via a
# symlink so YaCy's state persists across container rebuilds AND
# is visible at the standard OpenHost data-dir path (for file-
# browser, backups, etc.).
YACY_APP_DIR="/opt/yacy_search_server"
YACY_DATA_DIR_PERSIST="$PERSIST/DATA"
YACY_DATA_DIR_LINKED="$YACY_APP_DIR/DATA"

mkdir -p "$YACY_DATA_DIR_PERSIST"

# Replace the upstream DATA dir (which is a VOLUME mountpoint, but
# we're not using that volume) with a symlink to our persisted dir.
# If it's already a symlink to the right place, leave it.
if [[ -L "$YACY_DATA_DIR_LINKED" ]]; then
    current="$(readlink -f "$YACY_DATA_DIR_LINKED" || echo "")"
    if [[ "$current" != "$YACY_DATA_DIR_PERSIST" ]]; then
        rm -f "$YACY_DATA_DIR_LINKED"
        ln -s "$YACY_DATA_DIR_PERSIST" "$YACY_DATA_DIR_LINKED"
    fi
elif [[ -d "$YACY_DATA_DIR_LINKED" ]]; then
    # Real dir from the image; move any contents into our persisted
    # dir (preserves any first-boot bootstrap files the image
    # shipped) then replace with a symlink.
    if [[ -n "$(ls -A "$YACY_DATA_DIR_LINKED" 2>/dev/null)" ]]; then
        echo "[start.sh] Migrating pre-existing $YACY_DATA_DIR_LINKED into persistent dir"
        cp -an "$YACY_DATA_DIR_LINKED"/. "$YACY_DATA_DIR_PERSIST"/ 2>/dev/null || true
    fi
    rm -rf "$YACY_DATA_DIR_LINKED"
    ln -s "$YACY_DATA_DIR_PERSIST" "$YACY_DATA_DIR_LINKED"
else
    ln -s "$YACY_DATA_DIR_PERSIST" "$YACY_DATA_DIR_LINKED"
fi

# -----------------------------------------------------------------
# Admin credentials.  Persisted across reboots.
# -----------------------------------------------------------------
CRED_FILE="$PERSIST/admin-credentials.txt"
ADMIN_USERNAME="admin"

if [[ ! -f "$CRED_FILE" ]]; then
    # 32 alnum chars ≈ 190 bits of entropy.
    PASS="$(head -c 64 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)"
    umask 077
    cat > "$CRED_FILE" <<EOF
# Generated on first container start.  Used by auth_proxy.py to
# auto-log the OpenHost zone owner in to YaCy admin pages.  THIS
# IS A CREDENTIAL — anyone who can read this file can manage your
# YaCy peer (which also gives them the peer's private key and
# crawl index — the whole DATA/ dir next to this file is sensitive).
export YACY_ADMIN_USERNAME='${ADMIN_USERNAME}'
export YACY_ADMIN_PASSWORD='${PASS}'
EOF
    chmod 0600 "$CRED_FILE"
    echo "[start.sh] Generated admin credentials at $CRED_FILE"
else
    echo "[start.sh] Loaded existing admin credentials from $CRED_FILE"
fi

# shellcheck disable=SC1090
source "$CRED_FILE"

# -----------------------------------------------------------------
# Render yacy.conf.  Always re-applied on every boot so accidental
# edits to admin/port/network settings don't break OpenHost
# integration.
# -----------------------------------------------------------------
echo "[start.sh] Bootstrapping yacy.conf"
export YACY_APP_DIR
export YACY_DATA_DIR="$YACY_DATA_DIR_LINKED"
export YACY_ADMIN_USERNAME
export YACY_ADMIN_PASSWORD
# YaCy listens on this port internally (loopback only).
export YACY_PORT=8090
# Advertise this same port to peers (and clients) — it matches
# host_port in openhost.toml's [[ports]] entry so external peers
# can reach us at <zone-public-ip>:8090.
export YACY_PUBLIC_PORT=8090
export YACY_NETWORK_DEFINITION=freeworld

python3 /opt/openhost-yacy/setup_admin.py

# -----------------------------------------------------------------
# Start the auth-proxy first.  It serves /_healthz immediately so
# the OpenHost router has a stable target during YaCy's JVM warm-up
# (cold start can be 30s+, especially on a fresh index).
# -----------------------------------------------------------------
echo "[start.sh] Starting auth-proxy on 0.0.0.0:8080"
export AUTH_PROXY_LISTEN_PORT=8080
export AUTH_PROXY_UPSTREAM_HOST=127.0.0.1
export AUTH_PROXY_UPSTREAM_PORT="$YACY_PORT"
export AUTH_PROXY_CRED_FILE="$CRED_FILE"
python3 /opt/openhost-yacy/auth_proxy.py &
PROXY_PID=$!

# -----------------------------------------------------------------
# Start YaCy.  Run the upstream startYACY.sh in foreground mode.
# -----------------------------------------------------------------
echo "[start.sh] Starting YaCy (Jetty + Solr index) on 127.0.0.1:$YACY_PORT"
cd "$YACY_APP_DIR"

# Default heap is 600 MB; bump to 1800 MB for a public-mode peer
# (Solr index + crawler workers + DHT chunks add up).  This is below
# our manifest memory_mb=2048 so the JVM has headroom for off-heap
# usage.
export javastart_Xmx=Xmx1800m

/bin/sh "$YACY_APP_DIR/startYACY.sh" -f &
YACY_PID=$!

# -----------------------------------------------------------------
# Supervision
# -----------------------------------------------------------------
trap 'kill -TERM "$PROXY_PID" "$YACY_PID" 2>/dev/null; wait' TERM INT

set +e
wait -n "$PROXY_PID" "$YACY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] A child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$PROXY_PID" "$YACY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
