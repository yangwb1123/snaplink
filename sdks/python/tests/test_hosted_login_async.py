import asyncio
import json
import sys
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from snaplink_sso import AsyncSnaplink, AsyncSSOClient, SSOError
from snaplink_sso.client import HttpResponse
from snaplink_sso.hosted_login import MemoryStateStore, Snaplink


class _RecordingAsyncTransport:
    def __init__(self, payloads):
        self.requests = []
        self._payloads = list(payloads)

    async def send(self, request):
        self.requests.append(request)
        return HttpResponse(status=200, body=json.dumps(self._payloads.pop(0)).encode())


class _RecordingSyncClient:
    def __init__(self, _base_url, *, client_id, get_access_token, **kwargs):
        self.client_id = client_id
        self.get_access_token = get_access_token
        self.transport = kwargs.get("transport")
        self.requests = []

    def post_token(self, body):
        self.requests.append(body)
        if body["grant_type"] == "refresh_token":
            return {"access_token": "access-2", "expires_in": 900, "token_type": "Bearer"}
        return {
            "access_token": "access-1",
            "expires_in": 900,
            "refresh_token": "refresh-1",
            "token_type": "Bearer",
        }

    def post_logout(self, _body):
        self.requests.append({"logout": True})
        return {}

    def post_activation_prepare(self, body):
        self.requests.append(body)
        return {"activation_ticket": "ticket-1", "expires_in": 300, "product_id": "pro"}

    def post_my_activation_claim(self, body):
        self.requests.append(body)
        return {"context": {"product_id": "pro", "tenant_id": "tenant-1"}}

    def get_my_account_context(self, query):
        self.requests.append(query)
        return {"context": {"product_id": "pro", "tenant_id": "tenant-1"}}


class _RecordingAsyncClient(_RecordingSyncClient):
    async def post_token(self, body):
        return _RecordingSyncClient.post_token(self, body)

    async def post_logout(self, body):
        return _RecordingSyncClient.post_logout(self, body)

    async def post_activation_prepare(self, body):
        return _RecordingSyncClient.post_activation_prepare(self, body)

    async def post_my_activation_claim(self, body):
        return _RecordingSyncClient.post_my_activation_claim(self, body)

    async def get_my_account_context(self, query):
        return _RecordingSyncClient.get_my_account_context(self, query)


OPTIONS = {
    "base_url": "https://sso.example.test",
    "client_id": "spa-client",
    "redirect_uri": "https://app.example.test/auth/callback",
}


def callback_url(login_url):
    state = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(login_url).query))["state"]
    return (
        OPTIONS["redirect_uri"]
        + "?code=code-1&state="
        + urllib.parse.quote(state)
        + "&iss=https%3A%2F%2Fsso.example.test"
    )


class AsyncHostedLoginTest(unittest.IsolatedAsyncioTestCase):
    async def test_redirect_then_callback_exchanges_pkce_without_a_secret(self):
        client = _RecordingAsyncClient
        sdk = AsyncSnaplink(MemoryStateStore(), client_factory=client)

        started = await sdk.login(OPTIONS)
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(started.redirect_url).query))
        self.assertEqual(query["code_challenge_method"], "S256")
        self.assertRegex(query["code_challenge"], r"^[A-Za-z0-9_-]{43}$")

        result = await sdk.login({**OPTIONS, "callback_url": callback_url(started.redirect_url)})

        self.assertTrue(result.complete)
        self.assertEqual(result.tokens["access_token"], "access-1")
        self.assertTrue(sdk.is_logged_in)
        token_request = sdk.api.requests[0]
        self.assertEqual(token_request["grant_type"], "authorization_code")
        self.assertRegex(token_request["code_verifier"], r"^[A-Za-z0-9_-]{43,128}$")
        self.assertNotIn("client_secret", token_request)

    async def test_state_mismatch_is_rejected_before_any_request(self):
        sdk = AsyncSnaplink(MemoryStateStore(), client_factory=_RecordingAsyncClient)
        await sdk.login(OPTIONS)

        with self.assertRaises(SSOError) as raised:
            await sdk.login({
                **OPTIONS,
                "callback_params": {
                    "code": "code-1",
                    "state": "wrong",
                    "iss": "https://sso.example.test",
                },
            })

        self.assertEqual(raised.exception.error, "invalid_request")
        self.assertEqual(sdk.api.requests, [], "no exchange may be attempted")

    async def test_refresh_preserves_an_unrotated_token_and_clear_is_local(self):
        sdk = AsyncSnaplink(MemoryStateStore(), client_factory=_RecordingAsyncClient)
        started = await sdk.login(OPTIONS)
        await sdk.login({**OPTIONS, "callback_url": callback_url(started.redirect_url)})

        tokens = await sdk.refresh()

        self.assertEqual(tokens["access_token"], "access-2")
        self.assertEqual(tokens["refresh_token"], "refresh-1")
        self.assertEqual(
            sdk.api.requests[-1],
            {
                "grant_type": "refresh_token",
                "client_id": "spa-client",
                "refresh_token": "refresh-1",
            },
        )
        sdk.clear()
        self.assertFalse(sdk.is_logged_in)

    async def test_refresh_without_a_session_is_terminal(self):
        sdk = AsyncSnaplink(MemoryStateStore(), client_factory=_RecordingAsyncClient)
        with self.assertRaises(SSOError) as raised:
            await sdk.refresh()
        self.assertEqual(raised.exception.error, "login_required")

    async def test_logout_revokes_then_clears_even_when_the_server_call_fails(self):
        class _Failing(_RecordingAsyncClient):
            async def post_logout(self, _body):
                raise SSOError(500, "server_error", "unavailable")

        sdk = AsyncSnaplink(MemoryStateStore(), client_factory=_Failing)
        started = await sdk.login(OPTIONS)
        await sdk.login({**OPTIONS, "callback_url": callback_url(started.redirect_url)})

        with self.assertRaises(SSOError):
            await sdk.logout()

        self.assertFalse(sdk.is_logged_in)

    async def test_activation_ticket_is_claimed_after_the_code_exchange(self):
        sdk = AsyncSnaplink(MemoryStateStore(), client_factory=_RecordingAsyncClient)
        await sdk.setup({**OPTIONS, "product_id": "pro", "license_key": "paid-secret"})
        started = await sdk.login(OPTIONS)
        result = await sdk.login({**OPTIONS, "callback_url": callback_url(started.redirect_url)})

        self.assertEqual(result.tokens["access_token"], "access-1")
        claim = [item for item in sdk.api.requests if item.get("activation_ticket") == "ticket-1"]
        self.assertEqual(len(claim), 1)
        self.assertEqual(sdk.account_context["tenant_id"], "tenant-1")

    async def test_the_injected_async_transport_receives_the_exchange(self):
        transport = _RecordingAsyncTransport([{"access_token": "access-9", "token_type": "Bearer"}])
        sdk = AsyncSnaplink(MemoryStateStore(), transport=transport)
        started = await sdk.login(OPTIONS)

        await sdk.login({**OPTIONS, "callback_url": callback_url(started.redirect_url)})

        self.assertEqual(len(transport.requests), 1)
        self.assertIn(b"code_verifier=", transport.requests[0]["body"])
        self.assertEqual(sdk.access_token, "access-9")

    async def test_the_event_loop_keeps_running_during_a_request(self):
        """The await point must actually yield, or the facade blocks the loop."""

        ticks = 0

        async def ticker():
            nonlocal ticks
            for _ in range(5):
                await asyncio.sleep(0)
                ticks += 1

        sdk = AsyncSnaplink(MemoryStateStore(), client_factory=_RecordingAsyncClient)
        started = await sdk.login(OPTIONS)
        task = asyncio.create_task(ticker())
        await sdk.login({**OPTIONS, "callback_url": callback_url(started.redirect_url)})
        await task
        self.assertGreater(ticks, 0)


class SyncAsyncParityTest(unittest.TestCase):
    def test_both_surfaces_send_the_same_wire_requests(self):
        """A drift guard: the two facades must not diverge on the wire."""

        def shape(requests):
            return [
                {key: ("<random>" if key == "code_verifier" else value) for key, value in request.items()}
                for request in requests
            ]

        async def collect():
            sdk = AsyncSnaplink(MemoryStateStore(), client_factory=_RecordingAsyncClient)
            started = await sdk.login(OPTIONS)
            await sdk.login({**OPTIONS, "callback_url": callback_url(started.redirect_url)})
            await sdk.refresh()
            return sdk.api.requests, started

        async_requests, async_start = asyncio.run(collect())
        sync_sdk = Snaplink(MemoryStateStore(), client_factory=_RecordingSyncClient)
        sync_start = sync_sdk.login(OPTIONS)
        sync_sdk.login({**OPTIONS, "callback_url": callback_url(sync_start.redirect_url)})
        sync_sdk.refresh()
        sync_requests = sync_sdk.api.requests

        self.assertEqual(shape(async_requests), shape(sync_requests))
        for requests, start in ((async_requests, async_start), (sync_requests, sync_start)):
            verifier = requests[0]["code_verifier"]
            advertised = dict(
                urllib.parse.parse_qsl(urllib.parse.urlsplit(start.redirect_url).query)
            )["code_challenge"]
            self.assertEqual(_challenge(verifier), advertised)


def _challenge(verifier: str) -> str:
    import base64
    import hashlib

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


if __name__ == "__main__":
    unittest.main()
