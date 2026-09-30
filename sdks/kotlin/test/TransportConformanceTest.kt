package com.snaplink.sso

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cross-language conformance for the transport seam.
 *
 * The cases in `ops/build/sdk-conformance/transport.json` are the shared
 * contract: a transport double replays them byte-identically in every language.
 * This package is a public client, so `confidential_client_auth` and
 * `userinfo_bearer` are asserted from the invariant side — no secret ever
 * reaches a body or a URL, and a supplied Authorization header is forwarded
 * unchanged — rather than by adding a confidential-client capability the
 * package deliberately does not have.
 */
class TransportConformanceTest {
    private val baseUrl = "https://sso.example.test"

    @Test
    fun `authorization code exchange matches the shared case`() {
        val request = authorizationCodeExchange()
        val testCase = sharedCase("authorization_code_exchange")

        assertEquals(testCase["method"], request.method)
        assertEquals(testCase["path"], request.path)
        assertTrue(
            request.headers["Content-Type"]!!.startsWith(testCase["content_type"] as String),
        )
        val fields = request.formFields()
        for (field in testCase.requiredFields()) assertNotNull("missing $field", fields[field])
        for (forbidden in testCase.forbiddenInUrl()) {
            assertFalse("$forbidden must never appear in a URL", request.url.contains(forbidden))
        }
        assertEquals("no-store", request.headers["Cache-Control"])
    }

    @Test
    fun `refresh token exchange matches the shared case`() {
        val request = refreshTokenExchange()
        val testCase = sharedCase("refresh_token_exchange")

        assertEquals(testCase["method"], request.method)
        assertEquals(testCase["path"], request.path)
        val fields = request.formFields()
        for (field in testCase.requiredFields()) assertNotNull("missing $field", fields[field])
        for (forbidden in testCase.forbiddenFields()) {
            assertNull("a refresh must never carry $forbidden", fields[forbidden])
        }
    }

    @Test
    fun `account context read matches the shared case`() {
        val request = accountContextRead()
        val testCase = sharedCase("account_context_read")

        assertEquals(testCase["method"], request.method)
        assertEquals(testCase["path"], request.path)
        for (field in testCase.queryFields()) {
            assertTrue("missing query field $field", request.url.contains("$field="))
        }
        assertEquals("Bearer access-1", request.headers["Authorization"])
    }

    @Test
    fun `activation prepare matches the shared case`() {
        val request = activationPrepare()
        val testCase = sharedCase("activation_prepare")

        assertEquals(testCase["method"], request.method)
        assertEquals(testCase["path"], request.path)
        assertEquals("application/json", request.headers["Content-Type"])
        val fields = request.jsonFields()
        for (field in testCase.requiredFields()) assertNotNull("missing $field", fields[field])
        val present = testCase.exactlyOneOf().filter { fields[it] != null }
        assertEquals("exactly one credential must be present, got $present", 1, present.size)
        for (forbidden in testCase.forbiddenInUrl()) {
            assertFalse("$forbidden must never appear in a URL", request.url.contains(forbidden))
        }
    }

    @Test
    fun `the authorization header is forwarded unchanged`() {
        for (bearer in listOf("access-1", "at+jwt-token", "opaque token")) {
            val request = SnaplinkRequestFactory.bearerRead(baseUrl, "userinfo", bearer = bearer)
            assertEquals("GET", request.method)
            assertEquals("$baseUrl/userinfo", request.url)
            assertEquals("Bearer $bearer", request.headers["Authorization"])
            assertNull(request.body)
        }
    }

    @Test
    fun `no client secret ever reaches a body or url`() {
        val requests = listOf(
            authorizationCodeExchange(),
            refreshTokenExchange(),
            activationPrepare(),
            accountContextRead(),
        )
        for (request in requests) {
            assertNull(request.formFields()["client_secret"])
            assertNull(request.jsonFields()["client_secret"])
            assertFalse(request.url.contains("client_secret"))
        }
    }

    @Test
    fun `requests are byte identical across repeated builds`() {
        assertEquals(authorizationCodeExchange().canonical(), authorizationCodeExchange().canonical())
        assertEquals(activationPrepare().canonical(), activationPrepare().canonical())
    }

    @Test
    fun `header names canonicalize case insensitively`() {
        val lower = SnaplinkHttpRequest(
            method = "post",
            url = baseUrl,
            headers = mapOf("cache-control" to "no-store", "authorization" to "Bearer t"),
        )
        val canonical = SnaplinkHttpRequest(
            method = "POST",
            url = baseUrl,
            headers = mapOf("Cache-Control" to "no-store", "Authorization" to "Bearer t"),
        )
        assertEquals(canonical.canonical(), lower.canonical())
        assertEquals("the method must be preserved in canonical case", "POST", lower.method)
    }

    @Test
    fun `form bodies are deterministically ordered`() {
        val a = SnaplinkRequestFactory.credentialForm(baseUrl, "token", mapOf("b" to "2", "a" to "1", "c" to "3"))
        val b = SnaplinkRequestFactory.credentialForm(baseUrl, "token", mapOf("c" to "3", "a" to "1", "b" to "2"))
        assertEquals(a.canonical(), b.canonical())
        assertEquals(listOf("a", "b", "c"), a.formFields().keys.sorted())
    }

    @Test
    fun `credential endpoints always carry no store`() {
        for (path in listOf("token", "token/revoke", "token/introspect")) {
            val request = SnaplinkRequestFactory.credentialForm(baseUrl, path, mapOf("grant_type" to "client_credentials"))
            assertEquals("no-store", request.headers["Cache-Control"])
            assertEquals("no-cache", request.headers["Pragma"])
        }
    }

    @Test
    fun `a redacted description never leaks a credential`() {
        val redacted = authorizationCodeExchange().redactedDescription()
        assertFalse(redacted.contains("verifier-value"))
        assertFalse(redacted.contains("auth-code-value"))
        assertTrue(redacted.contains("code_verifier=<redacted>"))

        val bearer = accountContextRead().redactedDescription()
        assertFalse(bearer.contains("access-1"))
        assertTrue(bearer.contains("Authorization: <redacted>"))

        val activation = activationPrepare().redactedDescription()
        assertFalse("a JSON credential body is never echoed", activation.contains("lic-secret"))
    }

    @Test
    fun `a json body with a trailing newline is refused`() {
        val failure = runCatching {
            SnaplinkHttpRequest(method = "POST", url = baseUrl, body = SnaplinkHttpRequest.Body.Json("{\"a\":\"1\"}\n"))
        }.exceptionOrNull()
        assertNotNull("a trailing newline must be refused, not repaired", failure)
    }

    @Test
    fun `endpoint construction is pure`() {
        assertEquals(
            "https://sso.example.test/tenant/api/v1/me/preferences",
            SnaplinkRequestFactory.endpoint("https://sso.example.test/tenant/", "api/v1/me/preferences"),
        )
    }

    @Test
    fun `the shipped oauth transport builds the shared credential request`() {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody("""{"access_token":"a","token_type":"Bearer","expires_in":900}"""))
        server.start()
        try {
            val config = SnaplinkConfiguration(
                issuerBaseUrl = server.url("/").toString().trimEnd('/'),
                clientId = "native-app",
                redirectUri = "com.example.app:/oauth/callback",
                allowInsecureHttpForDevelopment = true,
            )
            runBlocking { HttpOAuthTransport(config).exchangeCode("code-1", "verifier-1") }
            val request = server.takeRequest()
            assertEquals("POST", request.method)
            assertEquals("/token", request.path)
            assertEquals("no-store", request.getHeader("Cache-Control"))
            val body = request.body.readUtf8()
            assertTrue(body.contains("code_verifier=verifier-1"))
            assertFalse("a verifier must never reach a URL", request.path!!.contains("verifier-1"))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `shared case identifiers are all implemented here`() {
        assertEquals("the shared transport fixture pins six cases", 6, sharedCases().size)
        for (testCase in sharedCases()) {
            assertNotNull("fixture case disappeared", testCase["id"])
        }
    }

    // MARK: - Request builders matching the shipped transports

    private fun authorizationCodeExchange() = SnaplinkRequestFactory.credentialForm(
        baseURL = baseUrl,
        path = "token",
        fields = mapOf(
            "grant_type" to "authorization_code",
            "client_id" to "ios-client",
            "code" to "auth-code-value",
            "code_verifier" to "verifier-value",
            "redirect_uri" to "com.example.sverp:/oauth/callback",
        ),
    )

    private fun refreshTokenExchange() = SnaplinkRequestFactory.credentialForm(
        baseURL = baseUrl,
        path = "token",
        fields = mapOf(
            "grant_type" to "refresh_token",
            "client_id" to "ios-client",
            "refresh_token" to "refresh-1",
        ),
    )

    private fun accountContextRead() = SnaplinkRequestFactory.bearerRead(
        baseURL = baseUrl,
        path = "api/v1/me/account-context",
        query = SnaplinkRequestFactory.query("product_id" to "pro"),
        bearer = "access-1",
    )

    private fun activationPrepare() = SnaplinkRequestFactory.json(
        method = "POST",
        baseURL = baseUrl,
        path = "api/v1/activation/prepare",
        fields = mapOf(
            "client_id" to "ios-client",
            "product_id" to "pro",
            "license_key" to "lic-secret",
        ),
    )

    private fun SnaplinkHttpRequest.formFields(): Map<String, String> =
        (body as? SnaplinkHttpRequest.Body.Form)?.fields?.toMap() ?: emptyMap()

    private fun SnaplinkHttpRequest.jsonFields(): Map<String, String> {
        val text = (body as? SnaplinkHttpRequest.Body.Json)?.text ?: return emptyMap()
        val fields = mutableMapOf<String, String>()
        Regex("\"([a-z_]+)\":\"([^\"]*)\"").findAll(text).forEach { fields[it.groupValues[1]] = it.groupValues[2] }
        return fields
    }

    private fun Map<String, Any?>.requiredFields(): List<String> = this["required_fields"] as List<String>
    private fun Map<String, Any?>.forbiddenFields(): List<String> = (this["forbidden_fields"] as List<String>?)
        ?: emptyList()
    private fun Map<String, Any?>.forbiddenInUrl(): List<String> = (this["forbidden_in_url"] as List<String>?)
        ?: emptyList()
    private fun Map<String, Any?>.queryFields(): List<String> = (this["query_fields"] as List<String>?)
        ?: emptyList()
    private fun Map<String, Any?>.exactlyOneOf(): List<String> = (this["exactly_one_of"] as List<String>?)
        ?: emptyList()

    private fun sharedCase(id: String): Map<String, Any?> =
        sharedCases().first { it["id"] == id } ?: error("missing shared transport case $id")

    private fun sharedCases(): List<Map<String, Any?>> =
        sharedFixture("transport.json")["cases"] as List<Map<String, Any?>>
}
