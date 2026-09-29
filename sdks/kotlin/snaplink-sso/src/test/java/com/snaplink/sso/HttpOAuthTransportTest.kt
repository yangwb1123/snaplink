package com.snaplink.sso

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

public class HttpOAuthTransportTest {
    @Test
    public fun tokenRequestIsFormEncodedAndDoesNotSendCookies(): Unit = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse().setHeader("Content-Type", "application/json")
                .setBody("""{"access_token":"access-1","token_type":"Bearer","expires_in":900,"refresh_token":"refresh-1"}"""),
        )
        server.start()
        try {
            val config = configuration(server.url("/").toString())
            val transport = HttpOAuthTransport(config)
            val response = transport.exchangeCode("code+/=", "verifier+with space")
            val request = server.takeRequest()
            val body = decodeForm(request.body.readUtf8())
            assertEquals("POST", request.method)
            assertEquals("/token", request.path)
            assertEquals("authorization_code", body["grant_type"])
            assertEquals("native-app", body["client_id"])
            assertEquals("code+/=", body["code"])
            assertEquals("verifier+with space", body["code_verifier"])
            assertEquals(config.redirectUri, body["redirect_uri"])
            assertNull(request.getHeader("Cookie"))
            assertEquals("no-store", request.getHeader("Cache-Control"))
            assertEquals("access-1", response.accessToken)
            assertEquals("refresh-1", response.refreshToken)
        } finally {
            server.shutdown()
        }
    }

    @Test
    public fun malformedOAuthErrorIsMappedWithoutTrustingNestedFields(): Unit = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(400).setBody("""{"error":{"detail":"invalid"}}"""))
        server.start()
        try {
            val transport = HttpOAuthTransport(configuration(server.url("/").toString()))
            val error = runCatching { transport.refresh("refresh-token") }.exceptionOrNull()
            assertTrue(error is SnaplinkAuthException)
            assertEquals("http_error", (error as SnaplinkAuthException).errorCode)
            assertEquals(400, error.httpStatus)
        } finally {
            server.shutdown()
        }
    }

    @Test
    public fun refreshOmitsPkceVerifierAndRejectsRedirects(): Unit = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "https://evil.example.test/token"))
        server.start()
        try {
            val transport = HttpOAuthTransport(configuration(server.url("/").toString()))
            val error = runCatching { transport.refresh("refresh-token") }.exceptionOrNull()
            assertTrue(error is SnaplinkAuthException)
            val request = server.takeRequest()
            val body = decodeForm(request.body.readUtf8())
            assertEquals("refresh_token", body["grant_type"])
            assertEquals("refresh-token", body["refresh_token"])
            assertFalse(body.containsKey("code_verifier"))
        } finally {
            server.shutdown()
        }
    }

    private fun configuration(baseUrl: String) = SnaplinkConfiguration(
        issuerBaseUrl = baseUrl.trimEnd('/'),
        clientId = "native-app",
        redirectUri = "com.example.app:/oauth/callback",
        allowInsecureHttpForDevelopment = true,
    )

    private fun decodeForm(raw: String): Map<String, String> = raw.split('&').associate { field ->
        val parts = field.split('=', limit = 2)
        URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name()) to
            URLDecoder.decode(parts.getOrElse(1) { "" }, StandardCharsets.UTF_8.name())
    }
}
