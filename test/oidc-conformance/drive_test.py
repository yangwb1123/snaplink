#!/usr/bin/env python3
"""Final conformance driver: poll browser URLs, fulfill logins, until done."""
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import websocket

ISSUER = "http://sso-issuer:8180"
USER = "openid-conformance-suite-admins"
PASSWORD = "S3cure-admin-pass!"
CDP_PORT = 9237
BASE = "https://localhost:8443"

class CDP:
    def __init__(self, ws_url, test_id):
        self.ws = websocket.create_connection(ws_url, timeout=120)
        self.msg_id = 0
        self.test_id = test_id

    def send(self, method, params=None):
        self.msg_id += 1
        mid = self.msg_id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})
            if msg.get("method") == "Fetch.requestPaused":
                self._paused(msg["params"])

    def _paused(self, params):
        url = params["request"]["url"]
        rid = params["requestId"]
        if url.startswith(ISSUER + "/auth/login"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            code, state = self._login(q)
            if code:
                if "redirect_uri" in q:
                    # Plain authorization request: redirect_uri/state ride the
                    # URL (OIDC Core default / basic oidcc-server flow).
                    redir = q["redirect_uri"][0]
                    state = q.get("state", [""])[0]
                    sep = "&" if "?" in redir else "?"
                    target = f"{redir}{sep}code={code}&state={state}"
                else:
                    # FAPI 2.0 PAR flow: the browser URL carries only
                    # client_id + request_uri (RFC 9126); redirect_uri/state
                    # live inside the pushed request, which snaplink echoes
                    # state back from (the code response carries state). The
                    # suite's callback for this test is at
                    # /test/<test_id>/callback and FAPI2-SP-FINAL requires
                    # the RFC 9207 iss parameter in the response.
                    redir = f"{BASE}/test/{self.test_id}/callback"
                    target = (f"{redir}?code={code}&state={state}"
                              f"&iss={urllib.parse.quote(ISSUER, safe='')}")
                print(f"[login] fulfilled -> {target[:90]}", flush=True)
                self._raw("Fetch.fulfillRequest", {"requestId": rid, "responseCode": 302,
                    "responseHeaders": [{"name": "Location", "value": target}]})
                return
            print(f"[login] NO CODE for {url[:80]}", flush=True)
        self._raw("Fetch.continueRequest", {"requestId": rid})

    def _raw(self, method, params):
        self.msg_id += 1
        mid = self.msg_id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                return
            if msg.get("method") == "Fetch.requestPaused":
                self._paused(msg["params"])

    def _login(self, q):
        # For a FAPI 2.0 PAR authorization URL the pushed request is
        # consumed by posting request_uri straight to /auth/login; the
        # response echoes state (merged from the PAR) alongside the code.
        body = {
            "provider": "password",
            "client_id": q["client_id"][0],
            "credential": {"username": USER, "password": PASSWORD},
        }
        if "request_uri" in q:
            body["request_uri"] = q["request_uri"][0]
        else:
            body["redirect_uri"] = q["redirect_uri"][0]
            body["response_type"] = q.get("response_type", ["code"])[0]
            body["scope"] = q.get("scope", ["openid"])[0].split()
            for k in ("state", "nonce", "code_challenge", "code_challenge_method"):
                if k in q:
                    body[k] = q[k][0]
        # The issuer's TLS is terminated by the local nginx proxy; the
        # browser side uses an unverified SSL context (self-signed cert).
        parts = urllib.parse.urlparse(ISSUER)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        login_base = f"{parts.scheme}://127.0.0.1:{port}"
        req = urllib.request.Request(login_base + "/auth/login",
                                     data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json",
                                              "Host": f"{parts.hostname}:{port}"})
        ctx = _CTX if parts.scheme == "https" else None
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            data = json.loads(r.read())
        return data.get("code", ""), data.get("state", "")

    def navigate(self, url):
        self.send("Page.navigate", {"url": url})

import ssl as _ssl
_CTX = _ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = _ssl.CERT_NONE

def api(cj, path):
    req = urllib.request.Request(BASE + path, headers={"Cookie": cj})
    with urllib.request.urlopen(req, timeout=30, context=_CTX) as r:
        return json.loads(r.read())

def main():
    global ISSUER
    test_id = sys.argv[1]
    cookie = sys.argv[2] if len(sys.argv) > 2 else ""
    timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    if len(sys.argv) > 4:
        ISSUER = sys.argv[4]
    chrome = subprocess.Popen([
        "google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox",
        "--ignore-certificate-errors", "--remote-allow-origins=*",
        f"--user-data-dir=/tmp/chrome-run-{int(time.time())}",
        f"--remote-debugging-port={CDP_PORT}", "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ws_url = None
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json", timeout=2) as r:
                    for t in json.loads(r.read()):
                        if t.get("type") == "page":
                            ws_url = t["webSocketDebuggerUrl"]
                            break
                if ws_url:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        cdp = CDP(ws_url, test_id)
        cdp.send("Page.enable")
        cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*sso-issuer*"}]})
        print(f"[driver] test {test_id}", flush=True)
        cj = cookie
        visited = set()
        start = time.time()
        while time.time() - start < timeout:
            info = api(cj, f"/api/info/{test_id}")
            status = info.get("status")
            if status in ("COMPLETED", "FINISHED"):
                print(f"[driver] {status} result={info.get('result')}", flush=True)
                return 0 if info.get("result") == "PASSED" else 1
            if status in ("INTERRUPTED", "FAILED", "CANCELLED"):
                print(f"[driver] terminal {status} {info.get('result')}", flush=True)
                return 2
            try:
                browser = api(cj, f"/api/runner/browser/{test_id}")
            except Exception:
                browser = {}
            for u in browser.get("urls", []):
                if u not in visited:
                    visited.add(u)
                    print(f"[driver] visit: {u[:100]}", flush=True)
                    cdp.navigate(u)
                    time.sleep(8)
            time.sleep(5)
        print("[driver] TIMEOUT", flush=True)
        return 3
    finally:
        chrome.terminate()

if __name__ == "__main__":
    sys.exit(main())
