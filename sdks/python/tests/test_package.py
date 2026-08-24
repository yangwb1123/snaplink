import json
import sys
import urllib.parse
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

sys.path.insert(0, str(Path(__file__).parents[1]))

from snaplink_sso import SSOClient


class _Handler(BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *_args):
        pass

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        self.__class__.calls.append((self.path, dict(self.headers), body))
        if self.path == "/auth/login":
            payload = {"access_token": "access-1", "token_type": "Bearer"}
        else:
            payload = {"sub": "alice", "email": "alice@example.test"}
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        self.__class__.calls.append((self.path, dict(self.headers), b""))
        encoded = b'{"sub":"alice"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class PackageTest(unittest.TestCase):
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

    def test_login_and_userinfo(self):
        client = SSOClient(f"http://127.0.0.1:{self.server.server_port}", client_id="web")
        token = client.login("alice", "secret")
        self.assertEqual(token["access_token"], "access-1")
        self.assertEqual(client.get_user_info()["sub"], "alice")
        self.assertEqual(_Handler.calls[-1][1]["Authorization"], "Bearer access-1")

    def test_confidential_token_uses_basic(self):
        client = SSOClient(
            f"http://127.0.0.1:{self.server.server_port}",
            client_id="backend",
            client_secret="secret",
        )
        client.post_token({"grant_type": "client_credentials", "client_secret": "body-secret"})
        path, headers, body = _Handler.calls[-1]
        self.assertEqual(path, "/token")
        self.assertEqual(headers["Authorization"], "Basic YmFja2VuZDpzZWNyZXQ=")
        self.assertEqual(
            urllib.parse.parse_qs(body.decode(), keep_blank_values=True),
            {"grant_type": ["client_credentials"]},
        )


if __name__ == "__main__":
    unittest.main()
