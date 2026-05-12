"""OpenHost SSO sidecar for YaCy via X-Real-IP localhost-spoofing.

Sits between the OpenHost router and YaCy's web UI (Jetty on
127.0.0.1).  Behavior:

  * Strip any client-supplied ``X-Real-IP``, ``Authorization``, and
    ``X-OpenHost-*`` headers (defense in depth — the OpenHost router
    stamps the real ``X-OpenHost-Is-Owner`` fresh on every request).
  * Strip ``Referer`` (YaCy's localhost-admin check requires
    Referer to be empty or also-localhost to honor the bypass;
    a public-domain Referer would defeat us).
  * If the request has ``X-OpenHost-Is-Owner: true`` (zone owner
    visiting): set ``X-Real-IP: 127.0.0.1`` before forwarding to
    YaCy.  Combined with ``adminAccountForLocalhost=true`` (set in
    setup_admin.py), YaCy treats the request as the authenticated
    admin and lets it through on _p (admin-only) pages.
  * Otherwise (anonymous internet visitor or peer-protocol caller):
    set ``X-Real-IP`` to the actual remote IP from
    ``X-Forwarded-For``.  YaCy sees a real remote IP and applies
    normal access rules (anonymous visitors can hit
    ``/yacysearch`` and ``/yacy/*`` but not ``_p`` admin pages).
  * ``/_healthz`` is served locally as a static 200 so the OpenHost
    healthcheck doesn't depend on YaCy's JVM warm-up (~30s on cold
    start).

Why X-Real-IP and not HTTP Basic/Digest replay: YaCy's Jetty
defaults to Digest auth on the wire (verified empirically: 401s
include ``WWW-Authenticate: Digest``).  Injecting a Basic
credential doesn't authenticate.  Implementing Digest in the proxy
would need a nonce-fetch round-trip on every cold request.
X-Real-IP spoofing uses a code path YaCy explicitly supports
(``RequestHeader.client()`` reads X-Real-IP), is a one-line proxy
change, and aligns with how YaCy itself documents reverse-proxy
deployments (with nginx ``proxy_set_header X-Real-IP $remote_addr``).
"""

from __future__ import annotations

import http.client
import logging
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"

# Hop-by-hop + framing headers we rebuild at the proxy seam.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

# Trust headers a hostile client could try to forge.  Always
# stripped from inbound requests.  The OpenHost router strips
# client-supplied versions itself before stamping its own, but
# defense in depth — don't depend on the router's behavior.
#
# X-Real-IP: stripped because we set it ourselves to either
#   127.0.0.1 (owner → localhost-admin bypass) or the real client IP
#   (anon → public visitor).  A forged client-supplied X-Real-IP
#   would let any anonymous visitor claim localhost-admin.
# Authorization: stripped to prevent any leak/forge attempts; we
#   don't use it ourselves.
# Referer: YaCy's localhost-admin bypass requires Referer to be
#   empty or also-localhost.  Stripping ensures the bypass works.
ALWAYS_STRIP_HEADERS = frozenset(
    h.lower()
    for h in (
        OWNER_HEADER_NAME,
        USER_HEADER_NAME,
        "Authorization",
        "X-Real-IP",
        "X-Real-Ip",
        "Referer",
    )
)

CLIENT_READ_TIMEOUT_SECONDS = 60

# 32 MiB cap.  YaCy file uploads (bulk crawl URL lists, dump
# imports) can be large; 32 MiB is enough for typical admin
# operations and prevents memory exhaustion on hostile input.
MAX_BODY_BYTES = 32 * 1024 * 1024

HEALTHCHECK_PATH = "/_healthz"

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


class AuthProxyHandler(BaseHTTPRequestHandler):
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8093

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _serve_healthz(self) -> None:
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "3")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(b"ok\n")
        except OSError:
            pass

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        path_only = self.path.split("?", 1)[0]
        if path_only == HEALTHCHECK_PATH:
            self._serve_healthz()
            return

        self._proxy()

    def _proxy(self) -> None:
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
        cleaned_headers.append(("X-Forwarded-Proto", "https"))

        # X-Real-IP injection.
        #   * Owner: lie and say the request came from localhost.
        #     YaCy + adminAccountForLocalhost=true gives admin rights.
        #   * Anon: pass through the real client IP from
        #     X-Forwarded-For so YaCy can apply normal access rules
        #     and log searches with the correct remote IP.
        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        if is_owner:
            real_ip = "127.0.0.1"
        else:
            # X-Forwarded-For is "client, proxy1, proxy2"; we want
            # the leftmost (original client).
            xff = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            real_ip = xff or self.client_address[0]
        cleaned_headers.append(("X-Real-IP", real_ip))

        path_only = self.path.split("?", 1)[0]
        log.info(
            "DIAG path=%s is_owner=%s x_real_ip=%s",
            path_only,
            is_owner,
            real_ip,
        )

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    log.info(
                        "short read: expected %d bytes, got %d",
                        length,
                        len(body),
                    )
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=120
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=True,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            try:
                payload = upstream.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001
                    log.debug("upstream.close() raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > MAX_BODY_BYTES:
                log.warning(
                    "upstream response exceeded %d bytes; returning 502",
                    MAX_BODY_BYTES,
                )
                self._safe_send_error(502, "upstream response too large")
                return

            reason = upstream.reason or ""
            # Diagnostic logging on 401 to debug Digest-vs-Basic mismatch.
            if upstream.status == 401:
                www_auth = next(
                    (v for k, v in upstream.getheaders() if k.lower() == "www-authenticate"),
                    "(none)",
                )
                log.warning(
                    "DIAG 401 from upstream for %s: WWW-Authenticate=%r",
                    self.path,
                    www_auth,
                )
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    # Strip WWW-Authenticate from upstream so anonymous
                    # browsers that wander onto an admin URL don't get
                    # the browser's ugly Basic-auth modal.  They'll see
                    # an OpenHost 302-to-/login instead (already
                    # handled by the router for non-public_paths).
                    if key.lower() == "www-authenticate":
                        continue
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 8093)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (X-Real-IP localhost-spoof mode)",
        listen_port,
        upstream_host,
        upstream_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
