package com.snaplink.sso

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

/**
 * Client-level behaviour for activation, the account context, and preferences.
 *
 * The commerce transport is a double here so the assertions are about the
 * client's sequencing and storage discipline; the wire shape is covered
 * separately by [CommerceTransportTest] against a real OkHttp stack.
 */
class CommerceClientTest {
    @Test
    fun `setup sends only the credential and stores the ticket`() = runBlocking {
        val fixture = fixture()
        val preparation = fixture.client.setup(
            SnaplinkSetupOptions(productId = "pro", licenseKey = "lic-secret", locale = "en-US"),
        )
        assertEquals("ticket-1", preparation.ticket)
        assertEquals(1, fixture.commerce.prepareCount)
        assertEquals("lic-secret", fixture.commerce.lastPreparedFields?.get("license_key"))
        assertNull("an absent credential must not be sent", fixture.commerce.lastPreparedFields?.get("invitation_code"))
        assertEquals("en-US", fixture.commerce.lastPreparedFields?.get("locale"))

        val stored = fixture.store.decodedPayloads().single()
        assertTrue("the ticket is stored", stored.contains("ticket-1"))
        assertFalse("the license key is never persisted", stored.contains("lic-secret"))
    }

    @Test
    fun `setup rejects a missing or ambiguous credential before the network`() = runBlocking {
        val fixture = fixture()
        for (options in listOf(
            SnaplinkSetupOptions(productId = "pro"),
            SnaplinkSetupOptions(productId = "pro", licenseKey = "lic", invitationCode = "invite"),
            SnaplinkSetupOptions(productId = "   ", licenseKey = "lic"),
        )) {
            val failure = runCatching { fixture.client.setup(options) }.exceptionOrNull()
            assertTrue(failure is SnaplinkAuthException)
            assertEquals("invalid_request", (failure as SnaplinkAuthException).errorCode)
        }
        assertEquals("no request may be sent for an invalid setup", 0, fixture.commerce.prepareCount)
    }

    @Test
    fun `the callback claims a pending activation with the new bearer`() = runBlocking {
        val fixture = fixture()
        fixture.client.setup(SnaplinkSetupOptions(productId = "pro", licenseKey = "lic"))
        completeLogin(fixture)

        assertEquals(1, fixture.commerce.claimCount)
        assertEquals("ticket-1", fixture.commerce.lastClaimTicket)
        assertEquals("access-initial", fixture.commerce.lastClaimBearer)
        assertFalse("the ticket must not outlive its claim", fixture.store.decodedPayloads().any { it.contains("ticket-1") })
    }

    @Test
    fun `an expired ticket is dropped without a claim`() = runBlocking {
        val fixture = fixture()
        fixture.commerce.expiresInSeconds = 30
        fixture.client.setup(SnaplinkSetupOptions(productId = "pro", licenseKey = "lic"))
        fixture.clock.addAndGet(60_000)
        completeLogin(fixture)
        assertEquals(0, fixture.commerce.claimCount)
    }

    @Test
    fun `a failed claim keeps the session and clears the ticket`() = runBlocking {
        val fixture = fixture()
        fixture.client.setup(SnaplinkSetupOptions(productId = "pro", licenseKey = "lic"))
        fixture.commerce.failClaim = true

        val failure = runCatching { completeLogin(fixture) }.exceptionOrNull()
        assertTrue(failure is SnaplinkAuthException)
        assertEquals("activation_invalid", (failure as SnaplinkAuthException).errorCode)
        assertEquals(
            "a rejected claim must leave the user signed in",
            "access-initial",
            fixture.client.accessToken(),
        )
        assertFalse(fixture.store.decodedPayloads().any { it.contains("ticket-1") })
    }

    @Test
    fun `account context uses the current bearer and requires login`() = runBlocking {
        val fixture = fixture()
        val beforeLogin = runCatching { fixture.client.accountContext("pro") }.exceptionOrNull()
        assertTrue(beforeLogin is SnaplinkAuthException)
        assertEquals("login_required", (beforeLogin as SnaplinkAuthException).errorCode)

        completeLogin(fixture)
        val context = fixture.client.accountContext("pro")
        assertEquals("tenant-1", context.tenantId)
        assertEquals(SnaplinkLicenseStateKind.ACTIVE, context.licenseStateAt(Instant.EPOCH).kind)
        assertEquals(1, fixture.commerce.contextCount)
        assertEquals("access-initial", fixture.commerce.lastContextBearer)
    }

    @Test
    fun `logout drops a pending activation`() = runBlocking {
        val fixture = fixture()
        completeLogin(fixture)
        fixture.client.setup(SnaplinkSetupOptions(productId = "pro", licenseKey = "lic"))
        assertTrue(fixture.store.decodedPayloads().any { it.contains("ticket-1") })

        fixture.client.logout()

        assertFalse(fixture.store.decodedPayloads().any { it.contains("ticket-1") })
        assertFalse(fixture.store.payloads().any { it.contains("access-initial") })
    }

    @Test
    fun `current session restores the persisted session without refreshing`() = runBlocking {
        val fixture = fixture()
        completeLogin(fixture)
        val beforeRefresh = fixture.transport.refreshCount.get()
        val session = fixture.client.currentSession()
        assertEquals("access-initial", session.accessToken)
        assertEquals(beforeRefresh, fixture.transport.refreshCount.get())
    }

    @Test
    fun `preferences are read and merged through the bearer`() = runBlocking {
        val fixture = fixture()
        completeLogin(fixture)
        fixture.commerce.storedPreferences = """{"locale":"zh-CN","theme_mode":"dark"}"""

        val stored = fixture.client.presentationPreferences()
        assertEquals("zh-CN", stored.locale)
        assertEquals(SnaplinkThemeMode.DARK, stored.themeMode)
        assertEquals("access-initial", fixture.commerce.lastContextBearer)

        fixture.client.updatePresentationPreferences(
            SnaplinkPresentationPreferencesPatch(locale = "en-US", themeMode = SnaplinkThemeMode.AUTO),
        )
        assertEquals(
            mapOf("locale" to "en-US", "theme_mode" to "auto"),
            fixture.commerce.lastPreferenceFields,
        )
    }

    @Test
    fun `an invalid preference is refused before the network`() = runBlocking {
        val fixture = fixture()
        completeLogin(fixture)
        val writesBefore = fixture.commerce.preferenceWriteCount

        val failure = runCatching {
            fixture.client.updatePresentationPreferences(
                SnaplinkPresentationPreferencesPatch(locale = "not a locale"),
            )
        }.exceptionOrNull()
        assertTrue(failure is SnaplinkPreferenceException)
        assertEquals(writesBefore, fixture.commerce.preferenceWriteCount)
    }

    @Test
    fun `a client built without a commerce transport fails loudly`() = runBlocking {
        val config = SnaplinkConfiguration(
            issuerBaseUrl = "https://sso.example.test",
            clientId = "native-app",
            redirectUri = "com.example.sverp:/oauth/callback",
        )
        val transport = CountingOAuthTransport()
        val client = SnaplinkAuthClient(config, RecordingStore(), transport, { 1_000_000L })
        // setup needs no session, so it reaches the missing transport directly;
        // a session-gated call would report login_required first and hide it.
        val failure = runCatching {
            client.setup(SnaplinkSetupOptions(productId = "pro", licenseKey = "lic"))
        }.exceptionOrNull()
        assertTrue(failure is SnaplinkAuthException)
        assertEquals("unsupported_operation", (failure as SnaplinkAuthException).errorCode)
    }

    private suspend fun completeLogin(fixture: Fixture) {
        val authorization = fixture.client.beginAuthorization()
        val state = query(authorization.toString())["state"]!!
        fixture.client.handleAuthorizationCallback(callbackUri(state))
    }

    private fun callbackUri(state: String): URI = URI.create(
        "com.example.sverp:/oauth/callback?code=auth-code&state=$state&iss=https%3A%2F%2Fsso.example.test",
    )

    private fun query(raw: String): Map<String, String> = URI(raw).rawQuery.orEmpty()
        .split('&')
        .filter(String::isNotEmpty)
        .associate { field ->
            val parts = field.split('=', limit = 2)
            java.net.URLDecoder.decode(parts[0], "UTF-8") to
                java.net.URLDecoder.decode(parts.getOrElse(1) { "" }, "UTF-8")
        }

    private fun fixture(): Fixture {
        val clock = AtomicLong(1_700_000_000_000L)
        val store = RecordingStore()
        val transport = CountingOAuthTransport()
        val commerce = FakeCommerceTransport()
        val config = SnaplinkConfiguration(
            issuerBaseUrl = "https://sso.example.test",
            clientId = "native-app",
            redirectUri = "com.example.sverp:/oauth/callback",
        )
        val client = SnaplinkAuthClient(config, store, transport, clock::get, commerce)
        return Fixture(client, transport, commerce, clock, store)
    }

    private data class Fixture(
        val client: SnaplinkAuthClient,
        val transport: CountingOAuthTransport,
        val commerce: FakeCommerceTransport,
        val clock: AtomicLong,
        val store: RecordingStore,
    )

    private class RecordingStore : SnaplinkSecureStore {
        private val values = mutableMapOf<String, String>()
        override fun read(key: String): String? = values[key]
        override fun write(key: String, value: String) { values[key] = value }
        override fun delete(key: String) { values.remove(key) }
        fun payloads(): List<String> = values.values.toList()

        /**
         * The stored records decoded, so a test can assert what a record holds
         * rather than matching its opaque base64 form.
         */
        fun decodedPayloads(): List<String> = values.values.map { value ->
            String(java.util.Base64.getUrlDecoder().decode(value), Charsets.UTF_8)
        }
    }

    private class CountingOAuthTransport : OAuthTransport {
        val refreshCount = AtomicLong()
        override suspend fun exchangeCode(code: String, verifier: String) =
            OAuthTokenResponse("access-initial", "Bearer", 900, "refresh-1", "openid")

        override suspend fun refresh(refreshToken: String): OAuthTokenResponse {
            refreshCount.incrementAndGet()
            return OAuthTokenResponse("access-refreshed", "Bearer", 900, "refresh-2", "openid")
        }

        override suspend fun revoke(token: String, tokenTypeHint: String) = Unit
    }

    private class FakeCommerceTransport : SnaplinkCommerceTransport {
        var prepareCount = 0
        var claimCount = 0
        var contextCount = 0
        var preferenceWriteCount = 0
        var expiresInSeconds = 300L
        var failClaim = false
        var storedPreferences = "{}"
        var lastPreparedFields: Map<String, String>? = null
        var lastClaimTicket: String? = null
        var lastClaimBearer: String? = null
        var lastContextBearer: String? = null
        var lastPreferenceFields: Map<String, String> = emptyMap()

        override suspend fun prepareActivation(
            request: SnaplinkActivationPrepareRequest,
        ): SnaplinkActivationPreparation {
            prepareCount++
            lastPreparedFields = request.jsonFields()
            return SnaplinkActivationPreparation("ticket-1", request.productId, expiresInSeconds)
        }

        override suspend fun claimActivation(
            ticket: String,
            productId: String,
            bearer: String,
        ): SnaplinkAccountContext {
            claimCount++
            lastClaimTicket = ticket
            lastClaimBearer = bearer
            if (failClaim) throw SnaplinkAuthException("activation_invalid", "ticket expired")
            return context(productId)
        }

        override suspend fun accountContext(productId: String, bearer: String): SnaplinkAccountContext {
            contextCount++
            lastContextBearer = bearer
            return context(productId)
        }

        override suspend fun myPreferences(bearer: String): String {
            lastContextBearer = bearer
            return storedPreferences
        }

        override suspend fun putMyPreferences(fields: Map<String, String>, bearer: String) {
            preferenceWriteCount++
            lastContextBearer = bearer
            lastPreferenceFields = fields
        }

        private fun context(productId: String) = SnaplinkAccountContext(
            productId = productId,
            tenantId = "tenant-1",
            entitlement = SnaplinkEntitlement(
                tenantId = "tenant-1",
                subscriptionId = "sub-1",
                plan = SnaplinkPlanRef("pro", 1),
                revision = 1,
                active = true,
                features = mapOf("core_sso" to true),
                effectiveAt = Instant.EPOCH,
                generatedAt = Instant.EPOCH,
            ),
        )
    }
}
