package com.snaplink.sso

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class TransportInjectionTest {
    @Test
    fun `public constructor injects HTTP without giving the caller OAuth state management`() = runBlocking {
        val fixture = InjectedClientFixture()
        fixture.login()
        val request = fixture.requests.single()
        val fields = (request.body as SnaplinkHttpRequest.Body.Form).fields.toMap()
        assertEquals("/token", request.path)
        assertEquals("POST", request.method)
        assertEquals("no-store", request.headers["Cache-Control"])
        assertEquals("no-cache", request.headers["Pragma"])
        assertEquals("authorization_code", fields["grant_type"])
        assertTrue(fields.getValue("code_verifier").length >= 43)
        assertFalse(fields.containsKey("client_secret"))
        assertFalse(request.url.contains(fields.getValue("code_verifier")))
        assertTrue(fixture.client.isLoggedIn())
    }

    @Test
    fun `invalid callbacks never reach the injected transport`() = runBlocking {
        val fixture = InjectedClientFixture()
        val error = runCatching { fixture.login(stateOverride = "wrong-state") }.exceptionOrNull()
        assertEquals("invalid_request", (error as SnaplinkAuthException).errorCode)
        assertTrue(fixture.requests.isEmpty())
    }

    @Test
    fun `injected refresh is single flight and carries no PKCE verifier`() = runBlocking {
        val started = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val refreshes = AtomicInteger()
        val fixture = InjectedClientFixture()
        fixture.handler = { request ->
            val fields = (request.body as SnaplinkHttpRequest.Body.Form).fields.toMap()
            if (fields["grant_type"] == "refresh_token") {
                refreshes.incrementAndGet()
                assertFalse(fields.containsKey("code_verifier"))
                started.complete(Unit)
                release.await()
                tokenResponse("renewed")
            } else {
                tokenResponse("initial", expires = 1)
            }
        }
        fixture.login()
        val first = async(Dispatchers.Default) { fixture.client.accessToken() }
        started.await()
        val second = async(Dispatchers.Default) { fixture.client.accessToken() }
        release.complete(Unit)
        assertEquals("renewed", first.await())
        assertEquals("renewed", second.await())
        assertEquals(1, refreshes.get())
    }

    @Test
    fun `activation and preference requests share the injected transport`() = runBlocking {
        val fixture = InjectedClientFixture()
        fixture.handler = { request ->
            when (request.path) {
                "/token" -> tokenResponse()
                "/api/v1/activation/prepare" -> SnaplinkHttpResponse(200, """{"activation_ticket":"ticket","product_id":"pro","expires_in":300}""")
                "/api/v1/me/activation/claim", "/api/v1/me/account-context" -> SnaplinkHttpResponse(200, """{"context":{"product_id":"pro","tenant_id":"tenant"}}""")
                "/me/preferences" -> SnaplinkHttpResponse(200, if (request.method == "GET") """{"locale":"zh-CN","theme_mode":"dark"}""" else """{"status":"ok"}""")
                else -> error("unexpected SDK route")
            }
        }
        fixture.client.setup(SnaplinkSetupOptions("pro", licenseKey = "private-license"))
        fixture.login()
        assertEquals("tenant", fixture.client.accountContext("pro").tenantId)
        assertEquals("zh-CN", fixture.client.presentationPreferences().locale)
        fixture.client.updatePresentationPreferences(SnaplinkPresentationPreferencesPatch(locale = "en-US"))
        fixture.client.updatePresentationPreferences(SnaplinkPresentationPreferencesPatch())
        assertEquals(7, fixture.requests.size)
        assertEquals("{}", (fixture.requests.last().body as SnaplinkHttpRequest.Body.Json).text)
        for (request in fixture.requests) {
            assertEquals("no-store", request.headers["Cache-Control"])
            assertFalse(request.url.contains("private-license"))
            assertFalse(request.redactedDescription().contains("private-license"))
        }
    }

    @Test
    fun `invalid injected token responses never create a usable session`() = runBlocking {
        val bodies = listOf(
            "{}",
            """{"access_token":"","token_type":"Bearer","expires_in":900}""",
            """{"access_token":"a","token_type":"MAC","expires_in":900}""",
            """{"access_token":"a","token_type":"Bearer","expires_in":0}""",
        )
        for (body in bodies) {
            val fixture = InjectedClientFixture()
            fixture.handler = { SnaplinkHttpResponse(200, body) }
            val error = runCatching { fixture.login() }.exceptionOrNull() as SnaplinkAuthException
            assertEquals("invalid_response", error.errorCode)
            assertFalse(fixture.client.isLoggedIn())
        }
    }

    @Test
    fun `injected response status and UTF8 byte limits are enforced`() = runBlocking {
        val responses = listOf(
            SnaplinkHttpResponse(0), SnaplinkHttpResponse(600),
            SnaplinkHttpResponse(200, "x".repeat(65_537)),
            SnaplinkHttpResponse(200, "é".repeat(32_769)),
        )
        for (response in responses) {
            val fixture = InjectedClientFixture()
            fixture.handler = { response }
            val error = runCatching { fixture.login() }.exceptionOrNull() as SnaplinkAuthException
            assertEquals("invalid_response", error.errorCode)
            assertFalse(fixture.client.isLoggedIn())
        }
    }

    @Test
    fun `network errors are safe and coroutine cancellation is not rewritten`() = runBlocking {
        val fixture = InjectedClientFixture()
        fixture.handler = { throw IOException("sensitive request detail") }
        val error = runCatching { fixture.login() }.exceptionOrNull() as SnaplinkAuthException
        assertEquals("network_error", error.errorCode)
        assertFalse(error.message.orEmpty().contains("sensitive"))
        fixture.handler = { throw CancellationException("cancelled") }
        assertTrue(runCatching { fixture.login() }.exceptionOrNull() is CancellationException)
    }

    @Test
    fun `revocation errors still leave the public client logged out`() = runBlocking {
        val fixture = InjectedClientFixture()
        fixture.login()
        fixture.handler = { SnaplinkHttpResponse(503, """{"error":"temporarily_unavailable"}""") }
        assertTrue(runCatching { fixture.client.logout() }.isFailure)
        assertFalse(fixture.client.isLoggedIn())
        val request = fixture.requests.last()
        assertEquals("/token/revoke", request.path)
        assertFalse(request.redactedDescription().contains("refresh-private"))
        assertTrue(request.redactedDescription().contains("token=<redacted>"))
    }

    @Test
    fun `canonical form bytes match the wire and diagnostic bodies are redacted`() {
        val request = SnaplinkRequestFactory.credentialForm(
            "https://sso.example.test", "token", mapOf("code" to "a+b/中", "code_verifier" to "private-verifier"),
        )
        val wire = Buffer().also { request.toOkHttp().body!!.writeTo(it) }.readUtf8()
        assertEquals(wire, request.canonical().substringAfter("\n\n"))
        assertFalse(request.body.toString().contains("private-verifier"))
        assertFalse(SnaplinkHttpRequest.Body.Json("private-json").toString().contains("private-json"))
        assertFalse(SnaplinkHttpResponse(200, "private-response").toString().contains("private-response"))
        assertEquals("client_id=%E4%B8%AD%2B", SnaplinkRequestFactory.query("client_id" to "中+"))
    }

    @Test
    fun `the shipped adapter strips cookies and refuses redirects from a supplied client`() = runBlocking {
        val server = MockWebServer()
        val jarCalls = AtomicInteger()
        val client = OkHttpClient.Builder().followRedirects(true).cookieJar(object : CookieJar {
            override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) = Unit
            override fun loadForRequest(url: HttpUrl): List<Cookie> {
                jarCalls.incrementAndGet()
                return listOf(Cookie.Builder().name("browser").value("private-cookie").domain(url.host).build())
            }
        }).build()
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "/trap"))
        server.start()
        try {
            val response = SnaplinkOkHttpTransport(client).execute(
                SnaplinkRequestFactory.bearerRead(server.url("/").toString(), "userinfo", bearer = "access"),
            )
            assertEquals(302, response.status)
            assertEquals(1, server.requestCount)
            assertEquals(null, server.takeRequest(2, TimeUnit.SECONDS)!!.getHeader("Cookie"))
            assertEquals(0, jarCalls.get())
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `the shipped adapter preserves shorter caller timeouts`() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setHeadersDelay(1, TimeUnit.SECONDS).setBody("{}"))
        server.start()
        try {
            val adapter = SnaplinkOkHttpTransport(OkHttpClient.Builder().callTimeout(100, TimeUnit.MILLISECONDS).build())
            val error = runCatching {
                SnaplinkHttp.read(adapter, SnaplinkRequestFactory.bearerRead(server.url("/").toString(), "userinfo", bearer = "access"))
            }.exceptionOrNull() as SnaplinkAuthException
            assertEquals("network_error", error.errorCode)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `empty JSON updates are valid PUT requests on the real transport`() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody("{}"))
        server.start()
        try {
            val response = SnaplinkOkHttpTransport().execute(SnaplinkRequestFactory.json(
                "PUT", server.url("/").toString(), "me/preferences", bearer = "access",
            ))
            assertEquals(200, response.status)
            val request = server.takeRequest(2, TimeUnit.SECONDS)!!
            assertEquals("PUT", request.method)
            assertEquals("{}", request.body.readUtf8())
            assertEquals("Bearer access", request.getHeader("Authorization"))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `the shipped adapter bounds oversized network responses`() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody("x".repeat(65_537)))
        server.start()
        try {
            val error = runCatching {
                SnaplinkOkHttpTransport().execute(SnaplinkRequestFactory.bearerRead(server.url("/").toString(), "userinfo", bearer = "access"))
            }.exceptionOrNull() as SnaplinkAuthException
            assertEquals("invalid_response", error.errorCode)
        } finally {
            server.shutdown()
        }
    }
}

internal fun tokenResponse(access: String = "access-private", expires: Long = 900) = SnaplinkHttpResponse(
    200, """{"access_token":"$access","token_type":"Bearer","expires_in":$expires,"refresh_token":"refresh-private"}""",
)

/** Exercises only public constructors; no module-internal OAuth response type is supplied. */
internal class InjectedClientFixture(clientId: String = "native-app") {
    val config = SnaplinkConfiguration("https://sso.example.test", clientId, "com.example.app:/oauth/callback")
    val requests = CopyOnWriteArrayList<SnaplinkHttpRequest>()
    var handler: suspend (SnaplinkHttpRequest) -> SnaplinkHttpResponse = { request ->
        if (request.path == "/token/revoke") SnaplinkHttpResponse(200) else tokenResponse()
    }
    val client = SnaplinkAuthClient(SnaplinkMemorySecureStore(), config, SnaplinkHttpTransport { request ->
        requests.add(request)
        handler(request)
    })

    suspend fun login(stateOverride: String? = null): SnaplinkSession {
        val url = client.beginAuthorization()
        val query = url.rawQuery.split('&').associate {
            val parts = it.split('=', limit = 2)
            URLDecoder.decode(parts[0], "UTF-8") to URLDecoder.decode(parts[1], "UTF-8")
        }
        val state = stateOverride ?: query.getValue("state")
        return client.handleAuthorizationCallback(
            URI("${config.redirectUri}?code=public-code&state=$state&iss=${URLEncoder.encode(config.issuerBaseUrl, "UTF-8")}"),
        )
    }
}
