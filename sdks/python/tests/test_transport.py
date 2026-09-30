import json
import sys
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

sys.path.insert(0, str(Path(__file__).parents[1]))

from snaplink_sso import SSOClient, SSOError
from snaplink_sso.client import HttpRequest, HttpResponse, UrllibTransport
from snaplink_sso.hosted_login import MemoryStateStore, Snaplink


class _Handler(BaseHTTPRequestHandler):
    calls: list = []

    def log_message(self, *_args):
        pass

    def _respond(self, status, payload):
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        self.__class__.calls.append((self.path, dict(self.headers), b""))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/me")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._respond(200, {"sub": "alice"})

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        self.__class__.calls.append((self.path, dict(self.headers), body))
        if self.path == "/token":
            self._respond(200, {"access_token": "access-1", "token_type": "Bearer", "expires_in": 900})
            return
        self._respond(200, {"context": {"product_id": "pro", "tenant_id": "tenant-1"}})


class _RecordingTransport:
    """A transport double: it records requests instead of opening a socket."""

    def __init__(self, status=200, payload=None):
        self.requests: list = []
        self._status = status
        self._payload = payload if payload is not None else {"access_token": "access-1", "token_type": "Bearer"}

    def send(self, request):
        self.requests.append(request)
        return HttpResponse(status=self._status, body=json.dumps(self._payload).encode())


class TransportInjectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _Handler.calls = []
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def base_url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def test_the_default_transport_speaks_the_same_protocol(self):
        transport = UrllibTransport()
        response = transport.send(HttpRequest(method="GET", url=self.base_url() + "/me", headers={}))
        self.assertEqual(response["status"], 200)
        self.assertEqual(json.loads(response["body"])["sub"], "alice")

    def test_an_injected_transport_receives_every_request(self):
        transport = _RecordingTransport()
        client = SSOClient(self.base_url(), client_id="web", transport=transport)

        client.post_token({"grant_type": "client_credentials"})

        self.assertEqual(len(transport.requests), 1)
        request = transport.requests[0]
        self.assertEqual(request["method"], "POST")
        self.assertTrue(request["url"].endswith("/token"))
        self.assertEqual(request["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertIn(b"grant_type=client_credentials", request["body"])
        self.assertEqual(_Handler.calls, [], "the real network must not be touched")

    def test_an_injected_transport_sees_the_bearer_of_a_protected_call(self):
        transport = _RecordingTransport()
        client = SSOClient(self.base_url(), client_id="web", transport=transport)
        client._token = "access-9"

        client.get_user_info()

        self.assertEqual(transport.requests[0]["headers"]["Authorization"], "Bearer access-9")

    def test_an_error_status_surfaces_the_wire_code_through_the_seam(self):
        transport = _RecordingTransport(
            status=400, payload={"error": "invalid_client", "error_description": "unknown client"}
        )
        client = SSOClient(self.base_url(), client_id="web", transport=transport)

        with self.assertRaises(SSOError) as raised:
            client.post_token({"grant_type": "client_credentials"})

        self.assertEqual(raised.exception.status, 400)
        self.assertEqual(raised.exception.error, "invalid_client")

    def test_hosted_login_routes_the_code_exchange_through_the_seam(self):
        transport = _RecordingTransport(
            payload={"access_token": "access-2", "token_type": "Bearer", "expires_in": 900}
        )
        sdk = Snaplink(MemoryStateStore(), transport=transport)
        options = {
            "base_url": "https://sso.example.test",
            "client_id": "spa-client",
            "redirect_uri": "https://app.example.test/auth/callback",
        }
        import urllib.parse

        started = sdk.login(options)
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(started.redirect_url).query))
        result = sdk.login({
            **options,
            "callback_url": options["redirect_uri"] + "?code=code-1&state="
            + urllib.parse.quote(query["state"])
            + "&iss=https%3A%2F%2Fsso.example.test",
        })

        self.assertEqual(result.tokens["access_token"], "access-2")
        self.assertEqual(len(transport.requests), 1)
        self.assertIn(b"code_verifier=", transport.requests[0]["body"])

    def test_the_default_transport_refuses_to_follow_a_redirect(self):
        client = SSOClient(self.base_url(), client_id="web")

        with self.assertRaises(SSOError) as raised:
            client._request("GET", "/redirect")

        self.assertEqual(raised.exception.status, 302)
        self.assertNotIn(
            "/me", [call[0] for call in _Handler.calls], "a redirect must never be replayed"
        )


if __name__ == "__main__":
    unittest.main()
