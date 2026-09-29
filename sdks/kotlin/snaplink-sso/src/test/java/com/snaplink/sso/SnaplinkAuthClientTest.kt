package com.snaplink.sso

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger

public class SnaplinkAuthClientTest {
    @Test
    public fun authorizationUrlUsesS256AndDoesNotExposeVerifier(): Unit = runBlocking {
        val setup = fixture()
        val url = setup.client.beginAuthorization().toString()
        val query = query(url)
        val challenge = query.getValue("code_challenge")
        val expectedShape = Regex("^[A-Za-z0-9_-]{43}$")
        val independentPkce = OAuthProtocol.createPkce()
        assertEquals(
            independentPkce.challenge,
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(independentPkce.verifier.toByteArray(StandardCharsets.US_ASCII)),
            ),
        )
        assertTrue(expectedShape.matches(challenge))
        assertEquals("S256", query["code_challenge_method"])
        assertEquals("code", query["response_type"])
        assertEquals("login consent", query["prompt"])
        assertEquals("0", query["max_age"])
        assertEquals("user@example.test", query["login_hint"])
        assertEquals("urn:example:mfa", query["acr_values"])
        assertEquals("en-US zh-CN", query["ui_locales"])
        assertFalse(url.contains("code_verifier"))
        assertFalse(url.contains("client_secret"))
        assertEquals("https://login.example.test/login/", url.substringBefore('?'))
    }

    @Test
    public fun callbackValidatesStateIssuerAndRedirectBeforeExchanging(): Unit = runBlocking {
        val setup = fixture()
        val authorization = setup.client.beginAuthorization()
        val state = query(authorization.toString()).getValue("state")
        val badState = URI("com.example.sverp:/oauth/callback?code=one&state=wrong&iss=https%3A%2F%2Fsso.example.test")
        val error = runCatching { setup.client.handleAuthorizationCallback(badState) }.exceptionOrNull()
        assertEquals("invalid_request", (error as SnaplinkAuthException).errorCode)
        assertEquals(0, setup.transport.exchangeCount.get())

        val nextAuthorization = setup.client.beginAuthorization()
        val nextState = query(nextAuthorization.toString()).getValue("state")
        val badIssuer = URI("com.example.sverp:/oauth/callback?code=one&state=$nextState&iss=https%3A%2F%2Fevil.example.test")
        val issuerError = runCatching { setup.client.handleAuthorizationCallback(badIssuer) }.exceptionOrNull()
        assertEquals("invalid_request", (issuerError as SnaplinkAuthException).errorCode)
        assertEquals(0, setup.transport.exchangeCount.get())

        val finalAuthorization = setup.client.beginAuthorization()
        val finalState = query(finalAuthorization.toString()).getValue("state")
        val badRedirect = URI("com.attacker.app:/oauth/callback?code=one&state=$finalState&iss=https%3A%2F%2Fsso.example.test")
        val redirectError = runCatching { setup.client.handleAuthorizationCallback(badRedirect) }.exceptionOrNull()
        assertEquals("invalid_request", (redirectError as SnaplinkAuthException).errorCode)
        assertEquals(0, setup.transport.exchangeCount.get())
    }

    @Test
    public fun callbackErrorUsesFormDecodingAndBoundedDiagnostics(): Unit = runBlocking {
        val setup = fixture()
        val authorizationUrl = setup.client.beginAuthorization()
        val state = query(authorizationUrl.toString()).getValue("state")
        val callback = URI(
            "com.example.sverp:/oauth/callback?error=${"e".repeat(80)}&error_description=login+cancelled%2Bhere${"x".repeat(600)}&state=$state&iss=https%3A%2F%2Fsso.example.test",
        )
        val error = runCatching { setup.client.handleAuthorizationCallback(callback) }.exceptionOrNull() as SnaplinkAuthException
        assertEquals(64, error.errorCode.length)
        assertEquals(512, error.message?.length)
        assertTrue(error.message.orEmpty().startsWith("login cancelled+here"))
        assertEquals(0, setup.transport.exchangeCount.get())
    }

    @Test
    public fun callbackExchangesCodeAndPersistsAccessToken(): Unit = runBlocking {
        val setup = fixture()
        val authorizationUrl = setup.client.beginAuthorization()
        val state = query(authorizationUrl.toString()).getValue("state")
        val callback = URI("com.example.sverp:/oauth/callback?code=auth-code&state=$state&iss=https%3A%2F%2Fsso.example.test")
        val session = setup.client.handleAuthorizationCallback(callback)
        assertEquals("access-initial", session.accessToken)
        assertEquals("auth-code", setup.transport.lastCode)
        assertTrue((setup.transport.lastVerifier?.length ?: 0) >= 43)
        assertEquals("access-initial", setup.client.accessToken())
    }

    @Test
    public fun expiredSessionRefreshesOnceForConcurrentCallers(): Unit = runBlocking {
        val setup = fixture()
        setup.transport.initialResponse = OAuthTokenResponse("access-old", "Bearer", 1, "refresh-1", "openid")
        val authorizationUrl = setup.client.beginAuthorization()
        val state = query(authorizationUrl.toString()).getValue("state")
        setup.client.handleAuthorizationCallback(
            URI("com.example.sverp:/oauth/callback?code=auth-code&state=$state&iss=https%3A%2F%2Fsso.example.test"),
        )
        setup.clock.set(1_001_000)
        val first = async { setup.client.accessToken() }
        val second = async { setup.client.accessToken() }
        assertEquals("access-refreshed", first.await())
        assertEquals("access-refreshed", second.await())
        assertEquals(1, setup.transport.refreshCount.get())
    }

    @Test
    public fun logoutClearsLocalTokensEvenWhenRevocationFails(): Unit = runBlocking {
        val setup = fixture()
        val authorizationUrl = setup.client.beginAuthorization()
        val state = query(authorizationUrl.toString()).getValue("state")
        setup.client.handleAuthorizationCallback(
            URI("com.example.sverp:/oauth/callback?code=auth-code&state=$state&iss=https%3A%2F%2Fsso.example.test"),
        )
        setup.transport.failRevoke = true
        assertTrue(runCatching { setup.client.logout() }.isFailure)
        val error = runCatching { setup.client.accessToken() }.exceptionOrNull()
        assertEquals("login_required", (error as SnaplinkAuthException).errorCode)
    }

    @Test
    public fun logoutCannotBeUndoneByAnInFlightAuthorizationExchange(): Unit = runBlocking {
        val setup = fixture()
        val authorizationUrl = setup.client.beginAuthorization()
        val state = query(authorizationUrl.toString()).getValue("state")
        setup.transport.pauseExchange()
        val callback = async {
            runCatching {
                setup.client.handleAuthorizationCallback(
                    URI("com.example.sverp:/oauth/callback?code=auth-code&state=$state&iss=https%3A%2F%2Fsso.example.test"),
                )
            }
        }
        setup.transport.exchangeStarted.await()
        val logout = async { setup.client.logout() }
        delay(20)
        setup.transport.releaseExchange()
        assertTrue(callback.await().isFailure)
        logout.await()
        val accessError = runCatching { setup.client.accessToken() }.exceptionOrNull()
        assertEquals("login_required", (accessError as SnaplinkAuthException).errorCode)
    }

    @Test
    public fun failedSecureDeleteLeavesClientLoggedOutInMemory() = runBlocking {
        val setup = fixture()
        val authorizationUrl = setup.client.beginAuthorization()
        val state = query(authorizationUrl.toString()).getValue("state")
        setup.client.handleAuthorizationCallback(
            URI("com.example.sverp:/oauth/callback?code=auth-code&state=$state&iss=https%3A%2F%2Fsso.example.test"),
        )
        setup.store.failDelete = true
        assertTrue(runCatching { setup.client.logout() }.isFailure)
        setup.store.failDelete = false
        val error = runCatching { setup.client.accessToken() }.exceptionOrNull()
        assertEquals("login_required", (error as SnaplinkAuthException).errorCode)
    }

    @Test
    public fun omittedOptionalAuthParametersRemoveStaleLoginPageValues() {
        val config = SnaplinkConfiguration(
            issuerBaseUrl = "https://sso.example.test",
            loginPageUrl = "https://login.example.test/login/?prompt=old&max_age=99&login_hint=old&acr_values=old&ui_locales=old",
            clientId = "native-app",
            redirectUri = "com.example.sverp:/oauth/callback",
        )
        val query = query(OAuthProtocol.buildAuthorizationUri(config, "state", "challenge").toString())
        assertFalse(query.containsKey("prompt"))
        assertFalse(query.containsKey("max_age"))
        assertFalse(query.containsKey("login_hint"))
        assertFalse(query.containsKey("acr_values"))
        assertFalse(query.containsKey("ui_locales"))
    }

    @Test
    public fun invalidHttpAndCallbackConfigurationFailClosed() {
        val httpConfig = runCatching {
            SnaplinkConfiguration(
                issuerBaseUrl = "http://sso.example.test",
                clientId = "native-app",
                redirectUri = "com.example.sverp:/oauth/callback",
            )
        }.exceptionOrNull()
        assertEquals("invalid_request", (httpConfig as SnaplinkAuthException).errorCode)

        val callback = runCatching {
            SnaplinkConfiguration(
                issuerBaseUrl = "https://sso.example.test",
                clientId = "native-app",
                redirectUri = "https://app.example.test/callback?state=untrusted",
            )
        }.exceptionOrNull()
        assertEquals("invalid_request", (callback as SnaplinkAuthException).errorCode)

        val negativeMaxAge = runCatching {
            SnaplinkConfiguration(
                issuerBaseUrl = "https://sso.example.test",
                clientId = "native-app",
                redirectUri = "com.example.sverp:/oauth/callback",
                maxAge = -1,
            )
        }.exceptionOrNull()
        assertEquals("invalid_request", (negativeMaxAge as SnaplinkAuthException).errorCode)
    }

    private fun fixture(): Fixture {
        val clock = java.util.concurrent.atomic.AtomicLong(1_000_000)
        val transport = FakeTransport()
        val config = SnaplinkConfiguration(
            issuerBaseUrl = "https://sso.example.test",
            loginPageUrl = "https://login.example.test/login/?theme=dark&code_challenge=stale&prompt=old&max_age=99&login_hint=old&acr_values=old&ui_locales=old",
            clientId = "native-app",
            redirectUri = "com.example.sverp:/oauth/callback",
            resources = listOf("https://api.example.test"),
            prompt = "login consent",
            loginHint = "user@example.test",
            acrValues = "urn:example:mfa",
            uiLocales = "en-US zh-CN",
            maxAge = 0,
        )
        val store = MemorySecureStore()
        val client = SnaplinkAuthClient(config, store, transport, clock::get)
        return Fixture(client, transport, clock, store)
    }

    private fun query(raw: String): Map<String, String> = URI(raw).rawQuery.orEmpty()
        .split('&')
        .filter(String::isNotEmpty)
        .associate { part ->
            val separator = part.indexOf('=')
            val key = if (separator < 0) part else part.substring(0, separator)
            val value = if (separator < 0) "" else part.substring(separator + 1)
            URLDecoder.decode(key, StandardCharsets.UTF_8.name()) to URLDecoder.decode(value, StandardCharsets.UTF_8.name())
        }

    private data class Fixture(
        val client: SnaplinkAuthClient,
        val transport: FakeTransport,
        val clock: java.util.concurrent.atomic.AtomicLong,
        val store: MemorySecureStore,
    )

    private class MemorySecureStore : SnaplinkSecureStore {
        private val values = mutableMapOf<String, String>()
        var failDelete = false
        override fun read(key: String): String? = values[key]
        override fun write(key: String, value: String) { values[key] = value }
        override fun delete(key: String) {
            if (failDelete) throw SnaplinkAuthException("secure_storage_error", "delete failed")
            values.remove(key)
        }
    }

    private class FakeTransport : OAuthTransport {
        val exchangeCount = AtomicInteger()
        val refreshCount = AtomicInteger()
        var initialResponse = OAuthTokenResponse("access-initial", "Bearer", 900, "refresh-1", "openid")
        var lastCode: String? = null
        var lastVerifier: String? = null
        var failRevoke = false
        var exchangeGate: CompletableDeferred<Unit>? = null
        var exchangeStarted = CompletableDeferred<Unit>()

        fun pauseExchange() {
            exchangeStarted = CompletableDeferred()
            exchangeGate = CompletableDeferred()
        }

        fun releaseExchange() { exchangeGate?.complete(Unit) }

        override suspend fun exchangeCode(code: String, verifier: String): OAuthTokenResponse {
            exchangeCount.incrementAndGet()
            lastCode = code
            lastVerifier = verifier
            exchangeStarted.complete(Unit)
            exchangeGate?.await()
            assertTrue(verifier.length >= 43)
            return initialResponse
        }

        override suspend fun refresh(refreshToken: String): OAuthTokenResponse {
            refreshCount.incrementAndGet()
            delay(40)
            assertEquals("refresh-1", refreshToken)
            return OAuthTokenResponse("access-refreshed", "Bearer", 900, "refresh-2", "openid")
        }

        override suspend fun revoke(token: String, tokenTypeHint: String) {
            assertEquals("refresh-1", token)
            assertEquals("refresh_token", tokenTypeHint)
            if (failRevoke) throw SnaplinkAuthException("network_error", "unavailable")
        }
    }
}
