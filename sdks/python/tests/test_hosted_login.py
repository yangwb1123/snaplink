import unittest
import urllib.parse

from snaplink_sso import MemoryStateStore, SSOError, Snaplink


class FakeClient:
    last_body = None
    activation_body = None
    claim_body = None
    claim_token = None

    def __init__(self, _base_url, *, client_id, get_access_token):
        self.client_id = client_id
        self.get_access_token = get_access_token

    def post_token(self, body):
        FakeClient.last_body = body
        return {"access_token": "access-1", "expires_in": 900, "token_type": "Bearer"}

    def post_logout(self, _body):
        return {}

    def post_activation_prepare(self, body):
        FakeClient.activation_body = body
        return {"activation_ticket": "ticket-1", "expires_in": 300, "product_id": "pro"}

    def post_my_activation_claim(self, body):
        FakeClient.claim_body = body
        FakeClient.claim_token = self.get_access_token()
        return {"context": {"product_id": "pro", "tenant_id": "tenant-1"}}

    def get_my_account_context(self, _query):
        return {"context": {"product_id": "pro", "tenant_id": "tenant-1"}}


class HostedLoginTest(unittest.TestCase):
    def test_redirect_then_callback_exchanges_pkce(self):
        sdk = Snaplink(MemoryStateStore(), client_factory=FakeClient)
        initial = sdk.login({
            "base_url": "https://sso.example.test",
            "client_id": "spa-client",
            "redirect_uri": "https://app.example.test/auth/callback",
            "return_to": "https://app.example.test/dashboard",
        })
        login_url = urllib.parse.urlsplit(initial.redirect_url)
        query = dict(urllib.parse.parse_qsl(login_url.query))
        self.assertEqual(login_url.path, "/login/")
        self.assertEqual(query["response_type"], "code")
        self.assertEqual(query["code_challenge_method"], "S256")

        result = sdk.login({
            "base_url": "https://sso.example.test",
            "client_id": "spa-client",
            "redirect_uri": "https://app.example.test/auth/callback",
            "callback_url": "https://app.example.test/auth/callback?code=code-1&state="
            + urllib.parse.quote(query["state"])
            + "&iss=https%3A%2F%2Fsso.example.test",
        })
        self.assertEqual(result.tokens["access_token"], "access-1")
        self.assertEqual(result.return_to, "https://app.example.test/dashboard")
        self.assertEqual(FakeClient.last_body["grant_type"], "authorization_code")
        self.assertRegex(FakeClient.last_body["code_verifier"], r"^[A-Za-z0-9_-]{43,128}$")
        self.assertNotIn("client_secret", FakeClient.last_body)

    def test_state_mismatch_is_rejected(self):
        sdk = Snaplink(MemoryStateStore(), client_factory=FakeClient)
        sdk.login({
            "base_url": "https://sso.example.test",
            "client_id": "spa-client",
            "redirect_uri": "https://app.example.test/auth/callback",
        })
        with self.assertRaises(SSOError) as raised:
            sdk.login({
                "base_url": "https://sso.example.test",
                "client_id": "spa-client",
                "redirect_uri": "https://app.example.test/auth/callback",
                "callback_params": {
                    "code": "code-1",
                    "state": "wrong",
                    "iss": "https://sso.example.test",
                },
            })
        self.assertEqual(raised.exception.error, "invalid_request")

    def test_setup_claims_ticket_after_login_without_persisting_key(self):
        store = MemoryStateStore()
        sdk = Snaplink(store, client_factory=FakeClient)
        sdk.setup({
            "base_url": "https://sso.example.test",
            "client_id": "spa-client",
            "product_id": "pro",
            "license_key": "paid-secret",
        })
        self.assertEqual(FakeClient.activation_body["license_key"], "paid-secret")
        self.assertNotIn("paid-secret", "".join(store._values.values()))
        initial = sdk.login({
            "base_url": "https://sso.example.test",
            "client_id": "spa-client",
            "redirect_uri": "https://app.example.test/auth/callback",
        })
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(initial.redirect_url).query))
        result = sdk.login({
            "base_url": "https://sso.example.test",
            "client_id": "spa-client",
            "redirect_uri": "https://app.example.test/auth/callback",
            "callback_url": "https://app.example.test/auth/callback?code=code-setup&state="
            + urllib.parse.quote(query["state"])
            + "&iss=https%3A%2F%2Fsso.example.test",
        })
        self.assertEqual(result.tokens["access_token"], "access-1")
        self.assertEqual(FakeClient.claim_body["activation_ticket"], "ticket-1")
        self.assertEqual(FakeClient.claim_token, "access-1")
        self.assertEqual(sdk.get_account_context()["tenant_id"], "tenant-1")


if __name__ == "__main__":
    unittest.main()
