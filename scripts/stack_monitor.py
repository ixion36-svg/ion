#!/usr/bin/env python3
"""Full-stack integration monitor for a local ION development estate.

Probes every integration ION talks to, from outside ION, so the result is
independent of whatever ION's own integrations page believes. Run it once
for a snapshot, or with ``--watch`` to keep a live view.

Each row reports three separate things, because they fail independently and
conflating them is how a broken estate looks healthy:

``container``
    Docker says the process is running. Says nothing about readiness.
``reachable``
    The port answered. Says nothing about authentication.
``ready``
    The service answered the way a caller needs it to -- authenticated,
    and past its own startup checks.

A service can be up, reachable, and still not ready for ten minutes
(OpenCTI and Kibana both do this), so "container running" is never reported
as health.

Credentials come from the environment where one is needed, defaulting to
the values in docker-compose.dev.yml. Nothing here writes to any service.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

ES_USER = os.environ.get("ION_ES_USER", "elastic")
ES_PASS = os.environ.get("ION_ES_PASSWORD", "testpassword123")
ARKIME_USER = os.environ.get("ION_ARKIME_USER", "arkime")
ARKIME_PASS = os.environ.get("ION_ARKIME_PASSWORD", "arkime")

TIMEOUT = 6

# DFIR-IRIS ships a self-signed certificate on a local estate, so its health
# probe cannot verify. That context is NOT the default for this module: it is
# opt-in per probe (``insecure_tls``) and refused for any host that is not
# loopback. Applying it to every HTTPS request would mean a probe later
# pointed at a real host silently stopped verifying, which is exactly the
# MITM exposure the relaxation is meant to be a narrow exception to.
_LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]")

_INSECURE_LOOPBACK = ssl.create_default_context()
_INSECURE_LOOPBACK.check_hostname = False
_INSECURE_LOOPBACK.verify_mode = ssl.CERT_NONE


def _tls_context(url: str, insecure: bool):
    """Verified by default; unverified only for an opt-in loopback probe."""
    if not insecure:
        return None  # urlopen's default: full verification.
    host = urllib.parse.urlsplit(url).hostname or ""
    if host not in _LOOPBACK:
        raise ValueError(
            f"insecure_tls requested for non-loopback host {host!r}; refusing "
            "to skip certificate verification off this machine"
        )
    return _INSECURE_LOOPBACK


@dataclass
class Probe:
    name: str
    container: Optional[str]
    url: Optional[str] = None
    auth: Optional[tuple] = None
    #: Returns (ready, detail) from the decoded body.
    check: Optional[Callable[[str], tuple]] = None
    note: str = ""
    #: A command whose exit status decides readiness, for non-HTTP services.
    exec_cmd: Optional[list] = None
    #: Skip certificate verification. Only honoured for loopback hosts; see
    #: _tls_context. Set solely for the self-signed IRIS dev certificate.
    insecure_tls: bool = False


@dataclass
class Result:
    name: str
    container_state: str
    reachable: bool
    ready: bool
    detail: str
    note: str = ""
    history: list = field(default_factory=list)


def _container_state(name: Optional[str]) -> str:
    if not name:
        return "n/a"
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
             name],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        return "unknown"
    if out.returncode != 0:
        return "absent"
    status, _, health = out.stdout.strip().partition("|")
    return f"{status}/{health}" if health else status


def _http(url: str, auth: Optional[tuple], insecure: bool = False) -> tuple:
    # Not "application/json": GitLab 404s an HTML page requested as JSON,
    # which looked like GitLab being broken rather than the probe asking for
    # the wrong representation.
    req = urllib.request.Request(url, headers={"Accept": "*/*"})
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        ctx = _tls_context(url, insecure)
    except ValueError as exc:
        return False, 0, str(exc)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
            # Read it all: Kibana's status document is ~22 KB, and a
            # truncated read produced "unterminated string", which reads as
            # a sick Kibana rather than a short buffer.
            return True, resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        # Reached it; it refused. That is a different failure from "down",
        # and the usual cause on this estate is credentials.
        return True, exc.code, exc.read(4000).decode("utf-8", "replace")
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as exc:
        return False, 0, str(getattr(exc, "reason", exc))


# ── Readiness checks, one per service ────────────────────────────────────

def es_ready(body: str) -> tuple:
    d = json.loads(body)
    status = d.get("status")
    # Yellow on a single node is replica count, not a fault.
    return status in ("green", "yellow"), (
        f"{status}, {d.get('number_of_nodes')} node(s), "
        f"{d.get('active_shards')} shards"
    )


def kibana_ready(body: str) -> tuple:
    d = json.loads(body)
    level = (d.get("status") or {}).get("overall", {}).get("level")
    return level == "available", f"overall={level}"


def opencti_ready(body: str) -> tuple:
    # The platform serves its SPA shell once it is genuinely up; while it is
    # still building the schema the root refuses or returns nothing useful.
    ready = "opencti" in body.lower() or "<!doctype html" in body.lower()
    return ready, "platform serving" if ready else f"{len(body)}B, not the app yet"


def gitlab_ready(body: str) -> tuple:
    return "GitLab" in body or "sign_in" in body, "login page served"


def iris_ready(body: str) -> tuple:
    return "IRIS" in body or "login" in body.lower(), "login page served"


def arkime_ready(body: str) -> tuple:
    """/api/user returns the authenticated account, so a 200 here proves the
    credentials ION uses actually work."""
    d = json.loads(body)
    user = d.get("userId") or d.get("userName") or "?"
    return bool(d), f"authenticated as '{user}'"


def tide_ready(body: str) -> tuple:
    return len(body) > 0, "responding"


def ollama_ready(body: str) -> tuple:
    # `ollama list` prints a header row then one line per model.
    rows = [r for r in body.strip().split("\n")[1:] if r.strip()]
    names = [r.split()[0] for r in rows]
    # Reachable with no models is a real state: Bob cannot answer, but the
    # daemon is fine, so it is reported rather than called a failure.
    return True, (f"{len(names)} model(s): " + ", ".join(names[:3])
                  if names else "daemon up, 0 models pulled")


def keycloak_ready(body: str) -> tuple:
    """The realm's discovery document is what ION actually consumes.

    Checking the admin console instead would go green while the realm ION
    validates tokens against did not exist.
    """
    d = json.loads(body)
    issuer = d.get("issuer", "")
    realm = issuer.rsplit("/", 1)[-1] if issuer else "?"
    has_jwks = bool(d.get("jwks_uri"))
    return has_jwks, f"realm '{realm}', jwks published" if has_jwks else "no jwks_uri"


def ion_ready(body: str) -> tuple:
    d = json.loads(body)
    ok = d.get("status") == "ok"
    return ok, f"{d.get('version')} on {d.get('database')}"


def minio_ready(body: str) -> tuple:
    return True, "live"


def rabbit_ready(body: str) -> tuple:
    d = json.loads(body)
    return d.get("status") == "ok", f"status={d.get('status')}"


PROBES = [
    Probe("Elasticsearch", "ion-elasticsearch",
          "http://127.0.0.1:9200/_cluster/health", (ES_USER, ES_PASS), es_ready,
          "alert source of record"),
    Probe("Kibana", "ion-kibana",
          "http://127.0.0.1:5601/api/status", (ES_USER, ES_PASS), kibana_ready,
          "case + note mirror"),
    # /health requires health_access_key and returns 401 without it, which
    # says nothing about the platform. The root serves the app once the
    # GraphQL schema is built, which is what a caller actually needs.
    Probe("OpenCTI", "ion-opencti",
          "http://127.0.0.1:8080/", None, opencti_ready,
          "observable enrichment"),
    # Plain HTTP on this estate: the published port terminates no TLS, so
    # no certificate exception is needed here after all.
    Probe("DFIR-IRIS", "iris-app",
          "http://127.0.0.1:8100/login", None, iris_ready,
          "case escalation"),
    # /api/user, not /eshealth.json: the latter needs no authentication, so
    # it went green while ION -- which calls /api/user -- was getting 401
    # against a username that does not exist. A health probe that skips the
    # auth the real caller uses is not probing the same thing.
    Probe("Arkime", "arkime",
          "http://127.0.0.1:8005/api/user", (ARKIME_USER, ARKIME_PASS),
          arkime_ready, "PCAP retrieval"),
    # TIDE 6.0.2 runs behind its own nginx, which terminates TLS on 443;
    # tide-app itself no longer publishes a port, so the container to watch
    # is the proxy. The certificate is CN=tide.local with no SAN, which no
    # modern client will verify, hence the loopback exception -- see
    # _tls_context, which refuses it for anything but a loopback host.
    Probe("TIDE", "tide-nginx",
          "https://127.0.0.1/", None, tide_ready,
          "detection inventory", insecure_tls=True),
    Probe("GitLab", "ion-gitlab",
          "http://127.0.0.1:8929/users/sign_in", None, gitlab_ready,
          "detection-as-code"),
    Probe("Ollama", "ion-ollama", None, None, ollama_ready,
          "Bob's model host",
          # No curl in this image; the bundled client speaks to the daemon.
          exec_cmd=["docker", "exec", "ion-ollama", "ollama", "list"]),
    Probe("Keycloak", "ion-keycloak",
          "http://127.0.0.1:8090/realms/ion/.well-known/openid-configuration",
          None, keycloak_ready, "SSO / token issuer"),
    # ION itself, last of the SOC-facing rows: if this is down the rest is
    # academic, and if it is up while an integration is not, the gap between
    # this monitor and ION's own integrations page is the interesting part.
    Probe("ION", None, "http://127.0.0.1:8011/api/health", None, ion_ready,
          "the app under test (0.99.9 + review fixes)"),
    Probe("PostgreSQL", "ion-postgres", None, None, None,
          "ION's own store",
          exec_cmd=["docker", "exec", "ion-postgres", "pg_isready", "-U", "ion"]),
    Probe("Redis", "ion-redis", None, None, None, "OpenCTI dependency",
          exec_cmd=["docker", "exec", "ion-redis", "redis-cli", "ping"]),
    Probe("MinIO", "ion-minio",
          "http://127.0.0.1:9000/minio/health/live", None, minio_ready,
          "OpenCTI dependency"),
    Probe("RabbitMQ", "ion-rabbitmq",
          "http://127.0.0.1:15672/api/health/checks/alarms",
          ("guest", "guest"), rabbit_ready, "OpenCTI dependency"),
]


def run_probe(p: Probe) -> Result:
    state = _container_state(p.container)

    if p.exec_cmd:
        try:
            out = subprocess.run(p.exec_cmd, capture_output=True, text=True,
                                 timeout=TIMEOUT + 4)
            reachable = out.returncode == 0
            detail = (out.stdout or out.stderr).strip().split("\n")[0][:70]
            ready = reachable
            if reachable and p.check:
                try:
                    ready, detail = p.check(out.stdout)
                except Exception as exc:
                    ready, detail = False, f"unparseable: {exc}"
        except Exception as exc:
            reachable, ready, detail = False, False, str(exc)[:70]
        return Result(p.name, state, reachable, ready, detail, p.note)

    reachable, code, body = _http(p.url, p.auth, p.insecure_tls)
    if not reachable:
        return Result(p.name, state, False, False, body[:70], p.note)

    if code >= 400:
        hint = " (credentials?)" if code in (401, 403) else ""
        return Result(p.name, state, True, False, f"HTTP {code}{hint}", p.note)

    try:
        ready, detail = p.check(body) if p.check else (True, f"HTTP {code}")
    except Exception as exc:
        ready, detail = False, f"HTTP {code}, unparseable: {exc}"
    return Result(p.name, state, True, ready, detail, p.note)


# Only colour a real terminal: piped output otherwise carries literal
# escape sequences, which is worse than plain text.
if sys.stdout.isatty():
    GREEN, YELLOW, RED, DIM, BOLD, RESET = (
        "\033[32m", "\033[33m", "\033[31m",
        "\033[2m", "\033[1m", "\033[0m",
    )
else:
    GREEN = YELLOW = RED = DIM = BOLD = RESET = ""


def render(results: list, elapsed: float) -> str:
    ready = sum(1 for r in results if r.ready)
    reachable = sum(1 for r in results if r.reachable and not r.ready)
    down = sum(1 for r in results if not r.reachable)

    lines = [
        f"{BOLD}ION full-stack integration monitor{RESET}  "
        f"{DIM}{time.strftime('%H:%M:%S')} · {elapsed:.1f}s sweep{RESET}",
        f"  {GREEN}{ready} ready{RESET} · {YELLOW}{reachable} up, not ready"
        f"{RESET} · {RED}{down} unreachable{RESET}",
        "",
        f"  {'SERVICE':<17}{'CONTAINER':<18}{'STATE':<13}DETAIL",
        f"  {'─' * 74}",
    ]
    for r in results:
        if r.ready:
            mark, colour, state = "✓", GREEN, "ready"
        elif r.reachable:
            mark, colour, state = "!", YELLOW, "not ready"
        else:
            mark, colour, state = "✗", RED, "unreachable"
        lines.append(
            f"  {colour}{mark}{RESET} {r.name:<15}{DIM}{r.container_state:<18}"
            f"{RESET}{colour}{state:<13}{RESET}{r.detail[:44]}"
        )
        if r.note:
            lines.append(f"    {DIM}{'':<13}{r.note}{RESET}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--watch", action="store_true",
                    help="keep sweeping until every service is ready or Ctrl-C")
    ap.add_argument("--interval", type=int, default=15)
    ap.add_argument("--json", action="store_true", help="machine-readable")
    args = ap.parse_args()

    while True:
        started = time.perf_counter()
        results = [run_probe(p) for p in PROBES]
        elapsed = time.perf_counter() - started

        if args.json:
            print(json.dumps(
                {"as_of": time.strftime("%Y-%m-%dT%H:%M:%S"),
                 "services": [r.__dict__ for r in results]}, indent=2))
        else:
            if args.watch:
                print("\033[2J\033[H", end="")
            print(render(results, elapsed))

        if not args.watch:
            # Non-zero when anything is not ready, so this can gate a script.
            return 0 if all(r.ready for r in results) else 1

        if all(r.ready for r in results):
            print(f"\n  {GREEN}every service ready{RESET}")
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    # The Windows console defaults to cp1252, which cannot encode the status
    # marks or the rule below the header, so printing raises rather than
    # degrading. Ask for UTF-8 explicitly; on a console that refuses, fall
    # back to replacing the few non-ASCII glyphs rather than failing.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
