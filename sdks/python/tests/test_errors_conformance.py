import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from snaplink_sso import AsyncSSOClient, SSOClient, SSOError
from snaplink_sso.client import UNCLASSIFIED_ERROR, HttpResponse

FIXTURE = (
    Path(__file__).parents[3] / "ops" / "build" / "sdk-conformance" / "errors.json"
)


def load_fixture():
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["cases"], "the shared error fixture must carry cases"
    assert document["shape"]["fallback"]["code"], "the fixture must pin a fallback code"
    return document


class _CannedTransport:
    def __init__(self, status, body):
        self._response = HttpResponse(status=status, body=body)

    def send(self, _request):
        return self._response


class _CannedAsyncTransport(_CannedTransport):
    async def send(self, _request):
        return self._response


class ErrorTaxonomyTest(unittest.IsolatedAsyncioTestCase):
    """The error taxonomy is a cross-language contract; the fixture is the source."""

    def client(self, status, body):
        return SSOClient(
            "https://sso.example.test",
            client_id="spa-client",
            transport=_CannedTransport(status, body),
        )

    def async_client(self, status, body):
        return AsyncSSOClient(
            "https://sso.example.test",
            client_id="spa-client",
            transport=_CannedAsyncTransport(status, body),
        )

    async def call(self, client, method, *args, **kwargs):
        if isinstance(client, AsyncSSOClient):
            return await getattr(client, method)(*args, **kwargs)
        return getattr(client, method)(*args, **kwargs)

    async def test_every_fixture_code_survives_verbatim(self):
        for case in load_fixture()["cases"]:
            if not case["status"]:
                continue
            body = json.dumps({"error": case["code"], "error_description": "any wording"}).encode()
            for client in (self.client(case["status"], body), self.async_client(case["status"], body)):
                with self.assertRaises(SSOError) as raised:
                    await self.call(client, "post_token", {"grant_type": "refresh_token"})
                self.assertEqual(raised.exception.error, case["code"])
                self.assertEqual(raised.exception.status, case["status"])
                self.assertEqual(raised.exception.error_description, "any wording")

    async def test_a_response_without_a_code_is_never_invented(self):
        fallback = load_fixture()["shape"]["fallback"]["code"]
        for body in (b"{}", b'{"error_description":"no code"}', b"not json", b""):
            for client in (self.client(500, body), self.async_client(500, body)):
                with self.assertRaises(SSOError) as raised:
                    await self.call(client, "post_token", {"grant_type": "refresh_token"})
                self.assertEqual(raised.exception.error, fallback)
                self.assertEqual(raised.exception.error, UNCLASSIFIED_ERROR)
                self.assertNotEqual(raised.exception.error, "invalid_grant")
                self.assertEqual(raised.exception.status, 500)

    async def test_a_local_validation_failure_keeps_the_zero_status(self):
        client = SSOClient("https://sso.example.test", transport=_CannedTransport(500, b"{}"))
        with self.assertRaises(SSOError) as raised:
            client.login("alice", "secret")
        self.assertEqual(raised.exception.status, 0)
        self.assertEqual(raised.exception.error, "invalid_request")
        self.assertNotEqual(raised.exception.error, UNCLASSIFIED_ERROR)


if __name__ == "__main__":
    unittest.main()
