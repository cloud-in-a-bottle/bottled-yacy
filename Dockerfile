# openhost-yacy
#
# Builds on top of the upstream yacy/yacy_search_server image. We add:
#   * python3 (for the auth-proxy sidecar)
#   * the start.sh / auth_proxy.py / setup_admin.py control plane
#
# The upstream image's CMD is overridden by our start.sh, which:
#   1. Bind-mounts /data/app_data/yacy → /opt/yacy_search_server/DATA
#      via symlink so YaCy's state persists across container rebuilds.
#   2. On first boot, generates a random admin password, computes the
#      YaCy MD5(user:realm:password) hash, and writes it directly into
#      DATA/SETTINGS/yacy.conf (preferred path per upstream's
#      bin/passwd.sh when the server isn't running yet).
#   3. Sets `port`, `publicPort`, `network.unit.name=freeworld`,
#      `adminAccountForLocalhost=false` in yacy.conf.
#   4. Launches the auth-proxy on 0.0.0.0:8080 (the OpenHost-routed
#      port) and YaCy on 127.0.0.1:8090.
#   5. Supervises both with `wait -n`.
FROM yacy/yacy_search_server:latest

USER root

# Ubuntu base; install python3 + curl + tini-free bash supervision.
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-minimal curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Sidecar + bootstrap scripts live under /opt/openhost-yacy and run
# in the YaCy user's home for filesystem-permission convenience.
COPY start.sh /opt/openhost-yacy/start.sh
COPY auth_proxy.py /opt/openhost-yacy/auth_proxy.py
COPY setup_admin.py /opt/openhost-yacy/setup_admin.py
RUN chmod 0755 /opt/openhost-yacy/start.sh \
              /opt/openhost-yacy/auth_proxy.py \
              /opt/openhost-yacy/setup_admin.py && \
    chown -R yacy:yacy /opt/openhost-yacy

WORKDIR /opt/openhost-yacy

# YaCy's upstream image declares VOLUME /opt/yacy_search_server/DATA.
# We'll bind-mount our persistent dir to that path via a symlink in
# start.sh (the VOLUME directive doesn't prevent the symlink trick).

# Disable upstream HEALTHCHECK — OpenHost has its own routing-level
# health probe wired in via openhost.toml.
HEALTHCHECK NONE

USER yacy
CMD ["/opt/openhost-yacy/start.sh"]
