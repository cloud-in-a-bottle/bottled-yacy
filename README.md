# bottled-yacy

[YaCy](https://yacy.net/) — decentralized peer-to-peer search engine —
packaged as a Cloud in a Bottle app in **freeworld (public)** mode.

## What this gives you

Your zone runs a YaCy peer that:

- Joins the public YaCy `freeworld` network (the global decentralized
  index used by yacy.net's demo peer and other community installs).
- Serves public search results at `https://yacy.<zone>/yacysearch.html`.
- Lets you crawl pages, build your own index, and contribute to the
  shared DHT.
- Auto-logs the zone owner into the admin UI for crawl config,
  blacklist management, network status, etc.

## Telemetry

None. From yacy.net: *"YaCy has a strong connection to privacy-aware
tools. As such it does not collect personalized data. It also has no
'phoning-home' integrated."*

## Topology

```
browser → OpenHost router (zone_auth check; stamps
                            X-OpenHost-Is-Owner: true)
        → container :8080 (auth-proxy)
              ├─ owner → +Authorization: Basic admin:<pw> → YaCy
              └─ anon  → passthrough → YaCy

anonymous search visitor → router (public_paths matched) →
                            container :8080 (auth-proxy) →
                            127.0.0.1:8090 (YaCy Jetty)

YaCy peer (freeworld) → host :8090/tcp → container :8090 (YaCy)
                        (P2P protocol: /yacy/hello, /yacy/search,
                         /yacy/transferRWI, etc.)
```

## SSO

X-Real-IP localhost-spoofing:

- `setup_admin.py` writes `adminAccountForLocalhost=true` into
  `DATA/SETTINGS/yacy.conf`. That tells YaCy: "treat any request
  whose client IP is loopback as the authenticated admin."
- On owner requests (router sets `X-OpenHost-Is-Owner: true`), the
  auth-proxy sets `X-Real-IP: 127.0.0.1` on the upstream request.
  YaCy reads this header (per its standard reverse-proxy support
  in `RequestHeader.client()`) and treats the request as
  localhost → auto-admin.
- On anonymous requests, the auth-proxy sets `X-Real-IP` to the
  real client IP from `X-Forwarded-For`. YaCy applies normal
  rules: public pages are accessible, `_p` admin pages return 401.
- A randomly-generated admin password is also written (in YaCy's
  `MD5(user:realm:pw)` hash format) so YaCy's CLI tools and the
  classic Digest auth path work too, for operators who SSH in.

Why not HTTP Basic / Digest replay? YaCy's Jetty defaults to
Digest on the wire (confirmed by `WWW-Authenticate: Digest...` on
401s). Replaying Digest requires a nonce-fetch round-trip and is
fiddly to cache. X-Real-IP is the one-line solution YaCy itself
documents for nginx-style reverse proxies.

### Credentials file

`$OPENHOST_APP_DATA_DIR/admin-credentials.txt` is a credential
(holds the plaintext admin password). The entire data dir is
already sensitive (contains your peer's private key, search
index, crawl history); the password file doesn't expand the
threat model. Treat the whole dir as secret.

If `file-browser` is installed on the same zone with the default
`access_all_data` permission, it can read this file. Either avoid
installing file-browser alongside, or revoke its `access_all_data`
permission.

### Rotating the admin password

```bash
# Edit the cred file with the new password:
sed -i "s/^export YACY_ADMIN_PASSWORD=.*/export YACY_ADMIN_PASSWORD='<new>'/" \
  /home/host/.openhost/local_compute_space/persistent_data/app_data/yacy/admin-credentials.txt

# Then restart the container so setup_admin.py re-applies the hash:
oh app reload yacy
```

Note: the Cloud in a Bottle SSO path uses X-Real-IP spoofing, so rotating
the password won't affect owner access in the browser — it only
affects YaCy's CLI tools and direct Digest-auth logins.

## Ports

- **8080/tcp** (Cloud in a Bottle-routed, HTTPS-terminated): web UI + REST API
- **8090/tcp** (published directly to the public internet): the YaCy
  peer-to-peer protocol. Other freeworld peers reach us at
  `<zone>:8090` for the `/yacy/*` endpoints.

The HTTPS-routed `:8080` is also a fully functional YaCy front end
— any path that goes there reaches YaCy after auth-proxy treatment.
The split exists because the Cloud in a Bottle router only handles HTTPS
and many YaCy peers in the network speak plain HTTP only.

## Public paths

The Cloud in a Bottle router lets the following paths through without
zone_auth (matches `routing.public_paths` in `openhost.toml`):

| Path prefix | Used by |
|---|---|
| `/yacy/` | Other freeworld peers (P2P protocol) |
| `/yacysearch` | Public search results (HTML/JSON/RSS/Atom) |
| `/yacysearchitem` | Result-rendering helpers used by search HTML |
| `/suggest.json` | Autocomplete suggestions |
| `/Network.html`, `/Network.json`, `/Network.xml` | Public peer-network info |
| `/opensearchdescription.xml` | Browser OpenSearch plugin |
| `/env/`, `/js/`, `/css/`, `/img/` | Static assets |
| `/robots.txt`, `/favicon.ico` | Standard |
| `/_healthz` | Cloud in a Bottle router liveness probe |

YaCy's per-page auth model is "any URL containing `_p` is admin-only
(401 if not authenticated), everything else is public." The
`public_paths` list is a superset of what's public on YaCy itself
plus the P2P-protocol endpoints YaCy needs reachable to participate
in the network.

## Resources

- **Memory**: 4 GiB container, 3 GiB JVM heap. YaCy's
  `ResourceObserver` auto-pauses the crawler when free heap drops
  below ~24 MB; on default 600 MB heap that happens within minutes
  of a real freeworld crawl. 3 GiB gives plenty of headroom for
  the in-memory crawl queue + Solr buffers.
- **CPU**: 2 cores. YaCy's crawler is multi-threaded and Solr
  benefits from extra cores during indexing.
- **Disk**: grows with your crawl. A few hundred MB for a fresh
  peer; tens of GB if you do serious crawling.

## What's *not* included

- **Intranet mode** (`network.unit.name=intranet`) — for a private,
  zone-only search portal without joining the public network.
  Switch in `DATA/SETTINGS/yacy.conf`'s `network.unit.definition` if
  desired; `start.sh` re-applies `freeworld` on every boot, so
  you'd need to disable that line in `setup_admin.py` or change
  the `YACY_NETWORK_DEFINITION` env in `start.sh`.
- **HTTPS on the peer port** — the YaCy peer protocol uses plain
  HTTP. TLS is terminated by the Cloud in a Bottle router for the web UI
  on port 8080 only.
- **wkhtmltopdf for PDF export** — the upstream image has it but
  it requires X libs that may not be cleanly available in our
  rootless container. The "export to PDF" feature in YaCy may not
  work; everything else does.

## Files

```
openhost.toml           manifest (port 8080 routed; TCP 8090 published)
Dockerfile              yacy/yacy_search_server:latest + python3 + scripts
start.sh                bootstrap (creds, symlink DATA dir, supervisor)
setup_admin.py          one-shot yacy.conf renderer
auth_proxy.py           Pattern A SSO sidecar (Authorization injection)
README.md               this file
```

## Authoring notes

- Built per the Cloud in a Bottle `openhost-app` skill (Pattern A — trusted
  header → injected Authorization).
- YaCy's admin auth uses `MD5(user:realm:password)` stored in
  `adminAccountBase64MD5`; `setup_admin.py` computes that
  server-side and writes it directly into `yacy.conf` (preferred
  path per upstream's `bin/passwd.sh` when YaCy is not running).
- `publicPort` is set equal to the Cloud in a Bottle `host_port` so peers
  in the freeworld network can reach us at the same number they
  see in our seed.
