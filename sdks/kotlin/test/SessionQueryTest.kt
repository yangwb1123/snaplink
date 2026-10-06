package com.snaplink.sso

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.URI
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * The logged-in query.
 *
 * The contract under test is that [SnaplinkAuthClient.isLoggedIn] is a local,
 * read-only observation: it never issues a request, never writes or deletes,
 * and never answers false for a reason the caller would mistake for "signed
 * out" when the truth is "the SDK could not read its own storage".
 */
class SessionQueryTest {
    @Test
    fun `is false before login and issues no request`() = runBlocking {
        val setup = fixture()

        assertFalse(setup.client.isLoggedIn())

        assertEquals("no exchange may be made", 0, setup.transport.exchangeCount.get())
        assertEquals("no refresh may be made", 0, setup.transport.refreshCount.get())
        assertEquals("no revocation may be made", 0, setup.transport.revokeCount.get())
    }

    @Test
    fun `is true for a stored session with a live token`() = runBlocking {
        val setup = fixture()
        login(setup)

        assertTrue(setup.client.isLoggedIn())
        assertEquals("a live session needs no round trip", 0, setup.transport.refreshCount.get())
        assertEquals("login performs exactly one exchange", 1L, setup.transport.exchangeCount.get())
    }

    @Test
    fun `is false once the stored token is expired and leaves the record alone`() = runBlocking {
        val setup = fixture()
        login(setup)
        val before = setup.store.snapshot()

        setup.clock.set(setup.clock.get() + 900_000)

        assertFalse("an expired access token is not a session", setup.client.isLoggedIn())
        assertEquals("a query must not delete an expired record", before, setup.store.snapshot())
        assertEquals(0, setup.transport.refreshCount.get())
    }

    @Test
    fun `is false inside the refresh skew that accessToken would have to renew`() = runBlocking {
        val setup = fixture()
        setup.transport.expiresInSeconds = 30
        login(setup)

        assertFalse("a token inside the skew is not usable without a round trip", setup.client.isLoggedIn())
        // The shared boundary: exactly here accessToken() reaches the network.
        assertEquals("access-refreshed", setup.client.accessToken())
        assertEquals(1, setup.transport.refreshCount.get())
    }

    @Test
    fun `is true just outside the skew boundary`() = runBlocking {
        val setup = fixture()
        setup.transport.expiresInSeconds = 61
        login(setup)

        assertTrue(setup.client.isLoggedIn())
        assertEquals("a token outside the skew is served from storage", 0, setup.transport.refreshCount.get())
    }

    @Test
    fun `raises a storage error rather than answering false`() = runBlocking {
        val setup = fixture()
        login(setup)
        val tokenKey = setup.store.keys().single()
        setup.store.write(tokenKey, record(STORAGE_VERSION_FOR_TEST + 1))

        assertEquals("secure_storage_error", storageFailure { setup.client.isLoggedIn() })
        assertEquals("secure_storage_error", storageFailure { setup.client.accessToken() })
    }

    @Test
    fun `a store that cannot be read is an error, not a signed-out client`() = runBlocking {
        val setup = fixture()
        login(setup)

        setup.store.failRead = true

        assertEquals("secure_storage_error", storageFailure { setup.client.isLoggedIn() })
    }

    @Test
    fun `is false after clear and after logout`() = runBlocking {
        val cleared = fixture()
        login(cleared)
        cleared.client.clear()
        assertFalse(cleared.client.isLoggedIn())
        assertEquals("clear is local only", 0, cleared.transport.revokeCount.get())

        val loggedOut = fixture()
        login(loggedOut)
        loggedOut.client.logout()
        assertFalse(loggedOut.client.isLoggedIn())
        assertEquals("logout still revokes once", 1, loggedOut.transport.revokeCount.get())
    }

    @Test
    fun `never writes, deletes, or mutates the store`() = runBlocking {
        val setup = fixture()
        login(setup)
        val before = setup.store.snapshot()
        val writesBefore = setup.store.writes
        val deletesBefore = setup.store.deletes

        repeat(3) { assertTrue(setup.client.isLoggedIn()) }

        assertEquals(before, setup.store.snapshot())
        assertEquals("a query must never write", writesBefore, setup.store.writes)
        assertEquals("a query must never delete", deletesBefore, setup.store.deletes)
    }

    @Test
    fun `a logout in flight is observed as not logged in`() = runBlocking {
        val setup = fixture()
        login(setup)
        setup.store.pauseDelete()
        // Dispatchers.Default, not this coroutine's context: the store seam is a
        // blocking, non-suspending API, so the gate below has to be awaited on a
        // thread of its own. Inheriting this event loop instead would park the
        // single thread this test is suspended on, and `releaseDelete()` could
        // never run - the test would deadlock against itself rather than
        // observe anything. Default has at least two threads by construction.
        val logout = async(Dispatchers.Default) { setup.client.logout() }
        setup.store.deleteStarted.await()

        assertFalse("an in-flight logout is not a session", setup.client.isLoggedIn())

        setup.store.releaseDelete()
        withTimeout(5_000) { logout.await() }
        assertFalse(setup.client.isLoggedIn())
    }

    private suspend fun storageFailure(block: suspend () -> Any?): String {
        val failure = runCatching { block() }.exceptionOrNull()
        assertNotNull("expected a fail-closed error", failure)
        assertTrue("expected SnaplinkAuthException, got $failure", failure is SnaplinkAuthException)
        return (failure as SnaplinkAuthException).errorCode
    }

    private suspend fun login(setup: Fixture) {
        val authorization = setup.client.beginAuthorization()
        val state = query(authorization.toString()).getValue("state")
        setup.client.handleAuthorizationCallback(
            URI("com.example.sverp:/oauth/callback?code=auth-code&state=$state&iss=https%3A%2F%2Fsso.example.test"),
        )
    }

    private fun fixture(): Fixture {
        val clock = AtomicLong(1_700_000_000_000L)
        val transport = FakeTransport()
        val store = RecordingStore()
        val configuration = SnaplinkConfiguration(
            issuerBaseUrl = "https://sso.example.test",
            clientId = "native-app",
            redirectUri = "com.example.sverp:/oauth/callback",
        )
        val client = SnaplinkAuthClient(configuration, store, transport, clock::get)
        return Fixture(client, transport, clock, store)
    }

    private fun query(raw: String): Map<String, String> = URI(raw).rawQuery.orEmpty()
        .split('&')
        .filter(String::isNotEmpty)
        .associate { field ->
            val parts = field.split('=', limit = 2)
            java.net.URLDecoder.decode(parts[0], "UTF-8") to
                java.net.URLDecoder.decode(parts.getOrElse(1) { "" }, "UTF-8")
        }

    private fun record(version: Int): String {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { it.writeInt(version) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes.toByteArray())
    }

    private data class Fixture(
        val client: SnaplinkAuthClient,
        val transport: FakeTransport,
        val clock: AtomicLong,
        val store: RecordingStore,
    )

    /**
     * A store that counts mutations, so a query that quietly refreshes or
     * deletes cannot pass.
     */
    private class RecordingStore : SnaplinkSecureStore {
        private val values = LinkedHashMap<String, String>()
        var failRead = false
        var writes = 0
            private set
        var deletes = 0
            private set
        private var deleteGate: CompletableDeferred<Unit>? = null
        var deleteStarted = CompletableDeferred<Unit>()
            private set

        override fun read(key: String): String? {
            if (failRead) throw SnaplinkAuthException("secure_storage_error", "read failed")
            return values[key]
        }

        override fun write(key: String, value: String) {
            writes++
            values[key] = value
        }

        override fun delete(key: String) {
            deletes++
            deleteStarted.complete(Unit)
            // The store seam is a blocking API, so a test that wants to observe
            // an in-flight delete has to block somewhere. The client calls this
            // off the caller's event loop (see logout()), and the test's
            // coroutine is suspended by the time this runs, so parking here
            // cannot starve the code that releases the gate.
            deleteGate?.let { gate -> runBlocking { gate.await() } }
            values.remove(key)
        }

        fun keys(): Set<String> = values.keys.toSet()
        fun snapshot(): Map<String, String> = LinkedHashMap(values)

        fun pauseDelete() {
            deleteStarted = CompletableDeferred()
            deleteGate = CompletableDeferred()
        }

        fun releaseDelete() {
            deleteGate?.complete(Unit)
        }
    }

    private class FakeTransport : OAuthTransport {
        val exchangeCount = AtomicLong()
        val refreshCount = AtomicLong()
        val revokeCount = AtomicLong()
        var expiresInSeconds = 900L

        override suspend fun exchangeCode(code: String, verifier: String): OAuthTokenResponse {
            exchangeCount.incrementAndGet()
            return OAuthTokenResponse("access-initial", "Bearer", expiresInSeconds, "refresh-1", "openid")
        }

        override suspend fun refresh(refreshToken: String): OAuthTokenResponse {
            refreshCount.incrementAndGet()
            return OAuthTokenResponse("access-refreshed", "Bearer", 900, "refresh-2", "openid")
        }

        override suspend fun revoke(token: String, tokenTypeHint: String) {
            revokeCount.incrementAndGet()
        }
    }

    private companion object {
        const val STORAGE_VERSION_FOR_TEST = 1
    }
}