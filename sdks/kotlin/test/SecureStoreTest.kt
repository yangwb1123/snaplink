package com.snaplink.sso

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.net.URI
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * The caller-injectable store seam.
 *
 * Every test here goes through the *public* [SnaplinkSecureStore] type, so the
 * contracts asserted here are the ones an application can rely on: records are
 * opaque and verbatim, records are keyed per configuration, and a store that
 * cannot answer fails the client closed instead of reporting no session.
 */
class SecureStoreTest {
    @Test
    fun `the public constructor writes the transaction into the supplied store`() = runBlocking {
        val store = RecordingStore(SnaplinkMemorySecureStore())
        val client = SnaplinkAuthClient(store, configuration("native-app"))

        val url = client.beginAuthorization()

        val record = store.keys().single()
        assertFalse("the storage key must not leak the client id", record.contains("native-app"))
        val transaction = decodeTransaction(store.read(record)!!)
        assertEquals(1, transaction.version)
        assertEquals("https://sso.example.test", transaction.issuer)
        assertEquals("native-app", transaction.clientId)
        assertEquals("com.example.sverp:/oauth/callback", transaction.redirectUri)
        assertEquals(query(url.toString()).getValue("state"), transaction.state)
        assertTrue("the verifier must be stored for the code exchange", transaction.verifier.length >= 43)
    }

    @Test
    fun `a login through an injected store writes only the decoded records`() = runBlocking {
        val store = RecordingStore(SnaplinkMemorySecureStore())
        val commerce = ClaimCommerceTransport()
        val client = SnaplinkAuthClient(
            configuration("native-app"),
            store,
            FakeTransport("access-initial"),
            { LIVE_CLOCK.get() },
            commerce,
        )
        client.setup(SnaplinkSetupOptions(productId = "pro", licenseKey = "lic-secret"))
        assertEquals("the pending ticket is held before login", 1, store.keys().size)

        login(client)

        val record = store.keys().single()
        val tokens = decodeTokenSet(store.read(record)!!)
        assertEquals("access-initial", tokens.accessToken)
        assertEquals("refresh-1", tokens.refreshToken)
        assertTrue("the activation ticket must not outlive its claim", store.payloads().none { it.contains("ticket-1") })
        assertTrue("a credential must never be persisted", store.payloads().none { it.contains("lic-secret") })
        assertEquals(1, commerce.claimCount)
    }

    @Test
    fun `a second client reads the session the first one persisted`() = runBlocking {
        val store = SnaplinkMemorySecureStore()
        val configuration = configuration("native-app")
        login(SnaplinkAuthClient(configuration, store, FakeTransport("access-initial"), { System.currentTimeMillis() }))

        // A separate client over the same store and the real transports: a live
        // record is served from storage, so this cannot reach the network.
        val restarted = SnaplinkAuthClient(store, configuration)
        assertTrue("a persisted session must be visible to a new client", restarted.isLoggedIn())
        assertEquals("access-initial", restarted.accessToken())
        assertEquals("access-initial", restarted.currentSession().accessToken)
    }

    @Test
    fun `records are isolated per configuration`() = runBlocking {
        val store = RecordingStore(SnaplinkMemorySecureStore())
        val clock = AtomicLong(System.currentTimeMillis())
        val first = SnaplinkAuthClient(configuration("app-a"), store, FakeTransport("access-a"), clock::get)
        val second = SnaplinkAuthClient(configuration("app-b"), store, FakeTransport("access-b"), clock::get)

        login(first)
        assertEquals("another client must not inherit a session", false, second.isLoggedIn())
        login(second)

        assertEquals("one token record per configuration", 2, store.keys().size)
        assertEquals("access-a", first.accessToken())
        assertEquals("access-b", second.accessToken())
    }

    @Test
    fun `the memory store round-trips and treats an absent key as absent`() {
        val store = SnaplinkMemorySecureStore()
        assertNull("an unknown key reads as absent", store.read("absent"))
        store.delete("absent")
        store.write("present", "value")
        assertEquals("value", store.read("present"))
        store.write("present", "replacement")
        assertEquals("a write replaces the previous record", "replacement", store.read("present"))
        store.delete("present")
        assertNull(store.read("present"))
    }

    @Test
    fun `a store failure fails closed instead of reporting no session`() = runBlocking {
        val failing = FailingStore()
        val client = SnaplinkAuthClient(failing, configuration("native-app"))

        failing.failWrite = true
        val writeFailure = runCatching { client.beginAuthorization() }.exceptionOrNull()
        assertNotNull("a write failure must not be swallowed", writeFailure)
        assertEquals("secure_storage_error", (writeFailure as SnaplinkAuthException).errorCode)
        assertEquals("a failed write stores nothing", 0, failing.writes)

        failing.failWrite = false
        failing.failRead = true
        assertEquals("secure_storage_error", storageFailure { client.isLoggedIn() })
        assertEquals("secure_storage_error", storageFailure { client.accessToken() })
    }

    @Test
    fun `a read failure after a successful login is reported, not treated as signed out`() = runBlocking {
        val store = FailingStore()
        val client = SnaplinkAuthClient(configuration("native-app"), store, FakeTransport("access-initial"), { LIVE_CLOCK.get() })
        login(client)
        assertTrue(client.isLoggedIn())

        store.failRead = true
        assertEquals(
            "an unreadable record must not read as login_required",
            "secure_storage_error",
            storageFailure { client.accessToken() },
        )
    }

    @Test
    fun `a corrupt record is refused after injection`() = runBlocking {
        val store = RecordingStore(SnaplinkMemorySecureStore())
        val configuration = configuration("native-app")
        val client = SnaplinkAuthClient(configuration, store, FakeTransport("access-initial"), { LIVE_CLOCK.get() })
        login(client)

        val tokenKey = store.keys().single()
        store.write(tokenKey, encodeVersion(STORAGE_VERSION_FOR_TEST + 1))

        assertEquals(
            "a record written by a future format must fail closed",
            "secure_storage_error",
            storageFailure { client.accessToken() },
        )
        assertEquals("secure_storage_error", storageFailure { client.isLoggedIn() })
    }

    private suspend fun storageFailure(block: suspend () -> Unit): String {
        val failure = runCatching { block() }.exceptionOrNull()
        assertNotNull("expected a fail-closed error", failure)
        assertTrue("expected SnaplinkAuthException, got $failure", failure is SnaplinkAuthException)
        return (failure as SnaplinkAuthException).errorCode
    }

    private suspend fun login(client: SnaplinkAuthClient) {
        val authorization = client.beginAuthorization()
        val state = query(authorization.toString()).getValue("state")
        client.handleAuthorizationCallback(
            URI("com.example.sverp:/oauth/callback?code=auth-code&state=$state&iss=https%3A%2F%2Fsso.example.test"),
        )
    }

    private fun configuration(clientId: String) = SnaplinkConfiguration(
        issuerBaseUrl = "https://sso.example.test",
        clientId = clientId,
        redirectUri = "com.example.sverp:/oauth/callback",
    )

    private fun query(raw: String): Map<String, String> = URI(raw).rawQuery.orEmpty()
        .split('&')
        .filter(String::isNotEmpty)
        .associate { field ->
            val parts = field.split('=', limit = 2)
            java.net.URLDecoder.decode(parts[0], "UTF-8") to
                java.net.URLDecoder.decode(parts.getOrElse(1) { "" }, "UTF-8")
        }

    private fun decodeTransaction(record: String): Transaction = recordStream(record).use { input ->
        Transaction(
            version = input.readInt(),
            issuer = input.readUTF(),
            clientId = input.readUTF(),
            redirectUri = input.readUTF(),
            state = input.readUTF(),
            verifier = input.readUTF(),
            createdAtMillis = input.readLong(),
        )
    }

    private fun decodeTokenSet(record: String): TokenSet = recordStream(record).use { input ->
        TokenSet(
            version = input.readInt(),
            accessToken = input.readUTF(),
            refreshToken = if (input.readBoolean()) input.readUTF() else null,
            expiresAtEpochSeconds = input.readLong(),
        )
    }

    private fun recordStream(record: String): DataInputStream {
        val bytes = Base64.getUrlDecoder().decode(record)
        return DataInputStream(ByteArrayInputStream(bytes))
    }

    private fun encodeVersion(version: Int): String {
        val bytes = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(bytes).use { it.writeInt(version) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes.toByteArray())
    }

    private data class Transaction(
        val version: Int,
        val issuer: String,
        val clientId: String,
        val redirectUri: String,
        val state: String,
        val verifier: String,
        val createdAtMillis: Long,
    )

    private data class TokenSet(
        val version: Int,
        val accessToken: String,
        val refreshToken: String?,
        val expiresAtEpochSeconds: Long,
    )

    /** A public-seam store that also exposes what the client wrote. */
    private class RecordingStore(private val delegate: SnaplinkSecureStore) : SnaplinkSecureStore {
        private val seen = LinkedHashMap<String, String>()

        override fun read(key: String): String? {
            val value = delegate.read(key)
            if (value == null) seen.remove(key) else seen[key] = value
            return value
        }

        override fun write(key: String, value: String) {
            delegate.write(key, value)
            seen[key] = value
        }

        override fun delete(key: String) {
            delegate.delete(key)
            seen.remove(key)
        }

        fun keys(): Set<String> = seen.keys.toSet()
        fun payloads(): List<String> = seen.values.toList()
    }

    /** A store that fails the way a Keystore or disk failure does. */
    private class FailingStore : SnaplinkSecureStore {
        private val values = mutableMapOf<String, String>()
        var failRead = false
        var failWrite = false
        var failDelete = false
        var writes = 0

        override fun read(key: String): String? {
            if (failRead) throw SnaplinkAuthException("secure_storage_error", "read failed")
            return values[key]
        }

        override fun write(key: String, value: String) {
            if (failWrite) throw SnaplinkAuthException("secure_storage_error", "write failed")
            writes++
            values[key] = value
        }

        override fun delete(key: String) {
            if (failDelete) throw SnaplinkAuthException("secure_storage_error", "delete failed")
            values.remove(key)
        }
    }

    private class FakeTransport(private val accessToken: String) : OAuthTransport {
        var exchangeCount = 0
            private set

        override suspend fun exchangeCode(code: String, verifier: String): OAuthTokenResponse {
            exchangeCount++
            return OAuthTokenResponse(accessToken, "Bearer", 900, "refresh-1", "openid")
        }

        override suspend fun refresh(refreshToken: String): OAuthTokenResponse =
            OAuthTokenResponse("access-refreshed", "Bearer", 900, "refresh-2", "openid")

        override suspend fun revoke(token: String, tokenTypeHint: String) = Unit
    }

    private class ClaimCommerceTransport : SnaplinkCommerceTransport {
        var claimCount = 0

        override suspend fun prepareActivation(request: SnaplinkActivationPrepareRequest) =
            SnaplinkActivationPreparation("ticket-1", request.productId, 300)

        override suspend fun claimActivation(ticket: String, productId: String, bearer: String): SnaplinkAccountContext {
            claimCount++
            return context(productId)
        }

        override suspend fun accountContext(productId: String, bearer: String): SnaplinkAccountContext = context(productId)

        override suspend fun myPreferences(bearer: String): String = "{}"

        override suspend fun putMyPreferences(fields: Map<String, String>, bearer: String) = Unit

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
                effectiveAt = java.time.Instant.EPOCH,
                generatedAt = java.time.Instant.EPOCH,
            ),
        )
    }

    private companion object {
        /**
         * A live clock: records minted against a frozen epoch would be expired by
         * the time a real-clock client reads them.
         */
        val LIVE_CLOCK = AtomicLong(System.currentTimeMillis())
        const val STORAGE_VERSION_FOR_TEST = 1
    }
}