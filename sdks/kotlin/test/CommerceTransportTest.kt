package com.snaplink.sso

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Wire-contract tests for the commerce and self-service routes.
 *
 * The endpoint runs against a real OkHttp stack through MockWebServer, so the
 * assertions cover what actually goes on the wire rather than what an
 * in-memory double would accept.
 */
class CommerceTransportTest {
    private lateinit var server: MockWebServer
    private lateinit var transport: HttpCommerceTransport

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        transport = HttpCommerceTransport(configuration())
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `prepare activation sends the credential only in the json body`() = runBlocking {
        server.enqueue(jsonResponse("""{"activation_ticket":"ticket-1","product_id":"pro","expires_in":300}"""))
        val preparation = transport.prepareActivation(
            SnaplinkActivationPrepareRequest(
                clientId = "android-client",
                productId = "pro",
                licenseKey = "lic-secret",
                invitationCode = null,
                tenantHint = null,
                locale = "en-US",
                appVersion = null,
            ),
        )
        assertEquals("ticket-1", preparation.ticket)
        assertEquals(300, preparation.expiresInSeconds)

        val request = server.takeRequest()
        assertEquals("POST", request.method)
        assertEquals("/api/v1/activation/prepare", request.path)
        assertEquals("no-store", request.getHeader("Cache-Control"))
        assertEquals("no-cache", request.getHeader("Pragma"))
        assertNull(request.getHeader("Authorization"))
        val body = request.body.readUtf8()
        assertTrue(body.contains("\"license_key\":\"lic-secret\""))
        assertFalse("the credential must never reach a URL", request.path!!.contains("lic-secret"))
        assertFalse(body.contains("invitation_code"))
    }

    @Test
    fun `prepare activation rejects a ticket bound to another product`() {
        server.enqueue(jsonResponse("""{"activation_ticket":"t","product_id":"other","expires_in":300}"""))
        val failure = runCatching {
            runBlocking {
                transport.prepareActivation(
                    SnaplinkActivationPrepareRequest("android-client", "pro", "lic", null, null, null, null),
                )
            }
        }.exceptionOrNull()
        assertTrue(failure is SnaplinkAuthException)
        assertEquals("invalid_response", (failure as SnaplinkAuthException).errorCode)
    }

    @Test
    fun `claim activation sends the ticket with the bearer`() = runBlocking {
        server.enqueue(jsonResponse(accountContextBody()))
        val context = transport.claimActivation("ticket-1", "pro", "access-1")
        assertEquals("tenant-1", context.tenantId)

        val request = server.takeRequest()
        assertEquals("/api/v1/me/activation/claim", request.path)
        assertEquals("Bearer access-1", request.getHeader("Authorization"))
        val body = request.body.readUtf8()
        assertTrue(body.contains("\"activation_ticket\":\"ticket-1\""))
        assertTrue(body.contains("\"product_id\":\"pro\""))
    }

    @Test
    fun `account context is a bearer read scoped to the product`() = runBlocking {
        server.enqueue(jsonResponse(accountContextBody()))
        transport.accountContext("pro", "access-1")

        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertEquals("/api/v1/me/account-context?product_id=pro", request.path)
        assertEquals("Bearer access-1", request.getHeader("Authorization"))
        assertEquals("no-store", request.getHeader("Cache-Control"))
    }

    @Test
    fun `account context rejects an incomplete projection`() {
        server.enqueue(jsonResponse("""{"context":{"product_id":"pro","tenant_id":""}}"""))
        val failure = runCatching { runBlocking { transport.accountContext("pro", "access-1") } }.exceptionOrNull()
        assertTrue(failure is SnaplinkAuthException)
        assertEquals("invalid_response", (failure as SnaplinkAuthException).errorCode)
    }

    @Test
    fun `a backend outage surfaces the server error code`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(503)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"error":"activation_unavailable","error_description":"activation backend down"}"""),
        )
        val failure = runCatching { runBlocking { transport.accountContext("pro", "access-1") } }.exceptionOrNull()
        assertTrue(failure is SnaplinkAuthException)
        val error = failure as SnaplinkAuthException
        assertEquals("activation_unavailable", error.errorCode)
        assertEquals(503, error.httpStatus)
        assertEquals(SnaplinkErrorRecovery.RETRY_WITH_BACKOFF, error.classification.recovery)
    }

    @Test
    fun `preferences round trip uses the authenticated self-service route`() = runBlocking {
        server.enqueue(jsonResponse("""{"locale":"zh-CN","theme_mode":"dark"}"""))
        val stored = SnaplinkPresentationPreferencesCodec.fromStored(transport.myPreferences("access-1"))
        assertEquals("zh-CN", stored.locale)
        assertEquals(SnaplinkThemeMode.DARK, stored.themeMode)

        val read = server.takeRequest()
        assertEquals("GET", read.method)
        assertEquals("/me/preferences", read.path)
        assertEquals("Bearer access-1", read.getHeader("Authorization"))

        server.enqueue(jsonResponse("""{"status":"ok"}"""))
        transport.putMyPreferences(mapOf("locale" to "en-US"), "access-1")
        val write = server.takeRequest()
        assertEquals("PUT", write.method)
        assertEquals("/me/preferences", write.path)
        assertEquals("Bearer access-1", write.getHeader("Authorization"))
        assertTrue(write.body.readUtf8().contains("\"locale\":\"en-US\""))
    }

    @Test
    fun `a preferences update with an unexpected status is reported`() {
        server.enqueue(jsonResponse("""{"status":"partial"}"""))
        val failure = runCatching { runBlocking { transport.putMyPreferences(mapOf("locale" to "en-US"), "access-1") } }
            .exceptionOrNull()
        assertTrue(failure is SnaplinkAuthException)
        assertEquals("invalid_response", (failure as SnaplinkAuthException).errorCode)
    }

    @Test
    fun `no request carries a cookie`() = runBlocking {
        server.enqueue(jsonResponse(accountContextBody()))
        transport.accountContext("pro", "access-1")
        val request = server.takeRequest()
        assertNull("the transport must never send cookies", request.getHeader("Cookie"))
    }

    @Test
    fun `the decoded context classifies like the shared contract`() = runBlocking {
        server.enqueue(jsonResponse(accountContextBody()))
        val context = transport.accountContext("pro", "access-1")
        // Evaluate inside the projection's window: before 2026-01-01 this
        // entitlement is not yet effective, which is a different case.
        val inside = java.time.Instant.parse("2026-06-01T00:00:00Z")
        val state = context.licenseStateAt(inside)
        assertEquals(SnaplinkLicenseStateKind.ACTIVE, state.kind)
        assertNotNull(state.entitlement)
        assertTrue(state.entitlement!!.has(SnaplinkFeature.SCIM, inside))
        assertEquals(
            SnaplinkLicenseStateKind.INACTIVE,
            context.licenseStateAt(java.time.Instant.parse("2025-01-01T00:00:00Z")).kind,
        )
    }

    private fun configuration(): SnaplinkConfiguration =
        SnaplinkConfiguration(
            issuerBaseUrl = server.url("/").toString().trimEnd('/'),
            clientId = "android-client",
            redirectUri = "com.example.sverp:/oauth/callback",
            // MockWebServer is loopback HTTP; the SDK only permits that behind
            // the explicit development flag.
            allowInsecureHttpForDevelopment = true,
        )

    private fun jsonResponse(body: String): MockResponse = MockResponse()
        .setResponseCode(200)
        .setHeader("Content-Type", "application/json")
        .setBody(body)

    private fun accountContextBody(): String = """
        {"context":{"product_id":"pro","tenant_id":"tenant-1","entitlement":{
          "tenant_id":"tenant-1","subscription_id":"sub-1","plan":{"id":"pro","version":1},
          "revision":1,"active":true,"features":{"scim":true},"limits":{"users":{"soft":5,"hard":10}},
          "effective_at":"2026-01-01T00:00:00Z","generated_at":"2026-01-01T00:00:00Z"}}}
    """.trimIndent()
}
