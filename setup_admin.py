#!/usr/bin/env python3
"""One-shot YaCy admin bootstrap.

Reads admin user/password from environment, computes YaCy's
``MD5:hex(md5("<user>:<realm>:<password>"))`` hash format, and writes
it directly into ``DATA/SETTINGS/yacy.conf`` (or seeds the file from
``defaults/yacy.init`` on first run).

Also sets:
  * ``port=<container_port>``
  * ``publicPort=<host_port>`` so peers can find us at the public port
  * ``network.unit.name=freeworld`` (P2P public mode — explicit even
    though it's the default)
  * ``adminAccountForLocalhost=false`` so we can hit /admin pages
    through the auth-proxy from 127.0.0.1
  * ``adminAccountAllPages=false`` so public pages stay public
  * ``server.https=false`` so YaCy speaks plain HTTP (TLS is
    terminated by the OpenHost router)

This script is idempotent: subsequent runs preserve the existing
config except for re-applying our managed fields.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path


# Realm string from yacy.init.  Hashed into the password digest;
# changing it would invalidate every previously-set admin password
# so we keep the upstream default verbatim.
DEFAULT_REALM = (
    "The YaCy access is limited to administrators. "
    "If you don't know the password, you can change it using "
    "<yacy-home>/bin/passwd.sh <new-password>"
)


def _yacy_md5(user: str, realm: str, password: str) -> str:
    """Compute YaCy's MD5-hashed admin credential.

    Format: ``MD5:<hex digest of UTF-8-encoded "<user>:<realm>:<password>">``.
    Verified against the upstream Dockerfile's pre-baked
    ``MD5:8cffbc0d66567a0987a4aba1ec46d63c`` for user=admin password=yacy.
    """
    key = f"{user}:{realm}:{password}".encode("utf-8")
    return "MD5:" + hashlib.md5(key).hexdigest()


def _read_init_template(yacy_app_dir: Path) -> str:
    """Load the upstream ``defaults/yacy.init`` to seed a fresh
    SETTINGS/yacy.conf on first start."""
    template = yacy_app_dir / "defaults" / "yacy.init"
    return template.read_text(encoding="utf-8")


def _apply_overrides(conf_text: str, overrides: dict[str, str]) -> str:
    """Replace or append each ``key=value`` line in conf_text.

    Match leading-whitespace + key + optional whitespace + '=' so
    we can handle both ``key=value`` and ``key = value`` forms.
    """
    lines = conf_text.splitlines(keepends=True)
    seen: set[str] = set()
    for i, line in enumerate(lines):
        for key, value in overrides.items():
            if key in seen:
                continue
            pattern = re.compile(rf"^\s*{re.escape(key)}\s*=.*$")
            if pattern.match(line):
                # Preserve trailing newline (or lack thereof).
                ends_with_nl = line.endswith("\n")
                lines[i] = f"{key}={value}" + ("\n" if ends_with_nl else "")
                seen.add(key)
                break
    # Append any keys we didn't find.
    missing = set(overrides.keys()) - seen
    if missing:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        for key in sorted(missing):
            lines.append(f"{key}={overrides[key]}\n")
    return "".join(lines)


def main() -> int:
    yacy_app_dir = Path(os.environ.get("YACY_APP_DIR", "/opt/yacy_search_server"))
    yacy_data_dir = Path(os.environ.get("YACY_DATA_DIR", str(yacy_app_dir / "DATA")))
    admin_user = os.environ.get("YACY_ADMIN_USERNAME", "admin")
    admin_password = os.environ.get("YACY_ADMIN_PASSWORD")
    container_port = os.environ.get("YACY_PORT", "8090")
    public_port = os.environ.get("YACY_PUBLIC_PORT", container_port)
    network = os.environ.get("YACY_NETWORK_DEFINITION", "freeworld")

    if not admin_password:
        print("[setup_admin] ERROR: YACY_ADMIN_PASSWORD must be set", file=sys.stderr)
        return 1

    settings_dir = yacy_data_dir / "SETTINGS"
    conf_path = settings_dir / "yacy.conf"

    if conf_path.exists():
        conf_text = conf_path.read_text(encoding="utf-8")
        print(f"[setup_admin] Loaded existing yacy.conf ({conf_path})")
    else:
        # First-ever boot: seed from defaults/yacy.init.
        settings_dir.mkdir(parents=True, exist_ok=True)
        conf_text = _read_init_template(yacy_app_dir)
        print(f"[setup_admin] Seeded yacy.conf from defaults/yacy.init")

    # Extract the realm currently in the conf (or the default if absent)
    # so the password hash matches what the YaCy server will compute
    # when it reads back its own conf.
    realm_match = re.search(r"^adminRealm=(.+)$", conf_text, flags=re.MULTILINE)
    realm = realm_match.group(1).rstrip("\r\n") if realm_match else DEFAULT_REALM

    pw_hash = _yacy_md5(admin_user, realm, admin_password)

    # Pin adminRealm explicitly so the hash we just computed always
    # matches what YaCy will look up.  Without this, an operator who
    # tweaks adminRealm after install would silently invalidate every
    # admin login attempt.
    overrides = {
        "adminAccountUserName": admin_user,
        "adminAccountBase64MD5": pw_hash,
        "adminAccountForLocalhost": "false",
        "adminAccountAllPages": "false",
        "adminRealm": realm,
        "port": container_port,
        "publicPort": public_port,
        "server.https": "false",
        "network.unit.definition": f"defaults/yacy.network.{network}.unit",
    }

    new_text = _apply_overrides(conf_text, overrides)
    conf_path.write_text(new_text, encoding="utf-8")
    print(f"[setup_admin] Wrote yacy.conf with admin={admin_user!r}, "
          f"port={container_port}, publicPort={public_port}, "
          f"network={network}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
