#!/usr/bin/env python3
"""Local-only stock SSO container acceptance; never publishes or prints tokens."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "ops/deploy/compose/config.yaml"
CLIENT = "snaplink-console-tenant-a"
SECRET = "checkout-local-only"
STATE = "/var/lib/snaplink"


def docker(*args: str) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120)
    if result.returncode:
        # App logs can contain a one-shot bootstrap password; do not dump them.
        raise RuntimeError(f"docker {args[0]} failed (exit {result.returncode})")
    return result.stdout.strip()


def request(base: str, path: str, form: dict[str, str] | None = None) -> tuple[dict, dict]:
    headers = {}
    data = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Authorization"] = "Basic " + base64.b64encode(f"{CLIENT}:{SECRET}".encode()).decode()
        data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(base + path, data=data, headers=headers)
    # Ignore host proxy configuration for this loopback-only acceptance run.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=10) as response:
        return json.load(response), dict(response.headers)


def wait_ready(container: str) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if docker("inspect", "--format", "{{.State.Running}}", container) != "true":
            raise RuntimeError("SSO exited before readiness; inspect its private container logs")
        result = subprocess.run(["docker", "exec", container, "/healthcheck"],
                                capture_output=True, timeout=10)
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("SSO did not become ready within 90 seconds")


def require_no_store(headers: dict) -> None:
    lowered = {key.lower(): value for key, value in headers.items()}
    if lowered.get("cache-control") != "no-store" or lowered.get("pragma") != "no-cache":
        raise RuntimeError("credential response lacks no-store/no-cache")


def mint(base: str) -> str:
    body, headers = request(base, "/token", {
        "grant_type": "client_credentials", "scope": "billing:checkout:create",
        "resource": "stripe-adapter-api",
    })
    require_no_store(headers)
    token = body.get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("client_credentials did not return an access token")
    return token


def check_active(base: str, token: str, active: bool) -> None:
    body, headers = request(base, "/token/introspect", {"token": token})
    require_no_store(headers)
    if body.get("active") is not active or (not active and body != {"active": False}):
        raise RuntimeError("introspection state differs from expected live/revoked state")


def run(image: str) -> None:
    suffix = uuid.uuid4().hex[:12]
    name, volume = f"snaplink-smoke-{suffix}", f"snaplink-smoke-state-{suffix}"
    docker("volume", "create", volume)
    try:
        docker("run", "--rm", "--network=none", "--read-only", "--user=0:0",
               "--mount", f"type=volume,src={volume},dst=/state", "busybox:1.37", "sh", "-c",
               "chown 65532:65532 /state && chmod 0700 /state")
        docker("run", "--rm", image, "version")
        docker("run", "--detach", "--name", name, "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges", "--publish", "127.0.0.1::8080",
               "--mount", f"type=bind,src={CONFIG},dst=/etc/sso/config.yaml,readonly",
               "--mount", f"type=volume,src={volume},dst={STATE}", image,
               "--config=/etc/sso/config.yaml", "--grpc-listen=")
        wait_ready(name)
        address = docker("port", name, "8080/tcp").splitlines()[0]
        if not address.startswith("127.0.0.1:"):
            raise RuntimeError("container is not bound exclusively to loopback")
        base = "http://" + address
        discovery, _ = request(base, "/.well-known/openid-configuration")
        if discovery.get("issuer") != "http://localhost:8080":
            raise RuntimeError("development issuer/discovery mismatch")
        jwks, _ = request(base, "/.well-known/jwks.json")
        live, revoked = mint(base), mint(base)
        check_active(base, live, True)
        _, headers = request(base, "/token/revoke", {"token": revoked})
        require_no_store(headers)
        check_active(base, revoked, False)
        docker("restart", name)
        wait_ready(name)
        # Docker may allocate a different ephemeral host port on restart.
        base = "http://" + docker("port", name, "8080/tcp").splitlines()[0]
        after, _ = request(base, "/.well-known/jwks.json")
        if after != jwks:
            raise RuntimeError("signing key changed after restart")
        check_active(base, live, True)
        check_active(base, revoked, False)
        mint(base)
        print("container-smoke: PASS (nonroot/read-only, discovery, token, no-store, restart, durable revocation)")
    finally:
        subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=30)
        subprocess.run(["docker", "volume", "rm", volume], capture_output=True, timeout=30)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="locally loaded stock sso-server image")
    args = parser.parse_args()
    try:
        run(args.image)
    except (RuntimeError, subprocess.TimeoutExpired, urllib.error.URLError, ValueError) as exc:
        print(f"container-smoke: FAIL ({type(exc).__name__}: {exc})")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
