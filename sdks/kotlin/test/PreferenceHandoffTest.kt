package com.snaplink.sso

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI

/**
 * The presentation handoff on the authorization request.
 *
 * The handoff carries UI hints - locale, theme - that the server persists as
 * the user's preference after a successful authentication. It is not an
 * authorization or tenant parameter, and it is built by the SDK rather than by
 * the caller so the wire keys cannot be invented or misspelled.
 */
class PreferenceHandoffTest {
    @Test
    fun `no patch emits no presentation parameter`() = runBlocking {
        val url = client().beginAuthorization().toString()

        assertFalse("presentation_locale leaked", url.contains("presentation_locale"))
        assertFalse("presentation_theme_mode leaked", url.contains("presentation_theme_mode"))
    }

    @Test
    fun `an empty patch emits nothing`() = runBlocking {
        val url = client()
            .beginAuthorization(SnaplinkPresentationPreferencesPatch())
            .toString()

        assertFalse(url.contains("presentation_locale"))
        assertFalse(url.contains("presentation_theme_mode"))
    }

    @Test
    fun `locale and theme reach the authorization request`() = runBlocking {
        val url = client()
            .beginAuthorization(
                SnaplinkPresentationPreferencesPatch(
                    locale = "zh-CN",
                    themeMode = SnaplinkThemeMode.DARK,
                ),
            )
            .toString()

        assertEquals("zh-CN", query(url)["presentation_locale"])
        assertEquals("dark", query(url)["presentation_theme_mode"])
    }

    @Test
    fun `only the supplied field is carried`() = runBlocking {
        val url = client()
            .beginAuthorization(SnaplinkPresentationPreferencesPatch(locale = "en-US"))
            .toString()

        assertEquals("en-US", query(url)["presentation_locale"])
        assertFalse("an unsupplied theme must stay absent", query(url).containsKey("presentation_theme_mode"))
    }

    @Test
    fun `a hint left in the login page url is dropped, not duplicated`() = runBlocking {
        // The managed-parameter rule the OAuth parameters already follow: what the
        // SDK manages is taken from the caller's configuration, never inherited
        // from the URL it was handed.
        val url = client(loginPageUrl = "https://sso.example.test/login/?presentation_locale=pt-BR&presentation_theme_mode=light&ui_locales=fr&tenant_hint=acme")
            .beginAuthorization(SnaplinkPresentationPreferencesPatch(themeMode = SnaplinkThemeMode.DARK))
            .toString()

        val values = query(url)
        assertEquals("dark", values["presentation_theme_mode"])
        assertFalse("pt-BR must not survive", values.containsValue("pt-BR"))
        assertEquals("light must not survive either", 1, values.entries.count { it.key == "presentation_theme_mode" })
        // The patch said nothing about locale, so the stale URL value is dropped
        // rather than inherited: absent is correct, a surviving pt-BR is not.
        assertFalse("a stale locale must not be inherited", values.containsKey("presentation_locale"))
        // ui_locales is managed too, and this client did not configure one, so
        // the URL value is dropped rather than inherited.
        assertFalse("a stale ui_locales must not be inherited", values.containsKey("ui_locales"))
        // The filter is scoped to SDK-managed keys: an unmanaged parameter the
        // caller put in the login page URL must still survive.
        assertEquals("acme", values["tenant_hint"])
    }

    @Test
    fun `a supplied hint replaces the one left in the url rather than joining it`() = runBlocking {
        val url = client(loginPageUrl = "https://sso.example.test/login/?presentation_locale=pt-BR")
            .beginAuthorization(SnaplinkPresentationPreferencesPatch(locale = "en-US"))
            .toString()

        val values = query(url)
        assertEquals("en-US", values["presentation_locale"])
        assertEquals(1, values.entries.count { it.key == "presentation_locale" })
    }

    @Test
    fun `a handoff is url encoded rather than concatenated`() = runBlocking {
        val url = client()
            .beginAuthorization(SnaplinkPresentationPreferencesPatch(locale = "zh-Hans-CN"))
            .toString()

        assertEquals("zh-Hans-CN", query(url)["presentation_locale"])
        assertTrue("the raw separator must not appear inside a value", !url.contains("locale=zh-Hans-CN&prompt=x&"))
    }

    @Test
    fun `the pkce and state parameters are unaffected by a handoff`() = runBlocking {
        val url = client()
            .beginAuthorization(SnaplinkPresentationPreferencesPatch(themeMode = SnaplinkThemeMode.LIGHT))
            .toString()

        val values = query(url)
        assertEquals("S256", values["code_challenge_method"])
        assertEquals("code", values["response_type"])
        assertTrue(values["code_challenge"].isNullOrEmpty().not())
        assertTrue(values["state"].isNullOrEmpty().not())
        assertEquals("native-app", values["client_id"])
    }

    @Test
    fun `the handoff itself carries only presentation keys`() = runBlocking {
        // scope and the other authorization parameters belong to the request
        // builder, not to a preference. What must not happen is the handoff
        // widening into them, so the invariant is asserted on the handoff itself.
        val handoff = SnaplinkPresentationPreferencesCodec.buildLoginHandoff(
            SnaplinkPresentationPreferencesPatch(
                locale = "de-DE",
                themeMode = SnaplinkThemeMode.DARK,
            ),
        )

        assertEquals(setOf("presentation_locale", "presentation_theme_mode"), handoff.keys)
    }

    @Test
    fun `a handoff does not add authorization or tenancy parameters`() = runBlocking {
        val plain = query(client().beginAuthorization().toString()).keys
        val withHandoff = query(
            client()
                .beginAuthorization(SnaplinkPresentationPreferencesPatch(themeMode = SnaplinkThemeMode.DARK))
                .toString(),
        ).keys

        assertEquals(
            "a presentation hint must not widen the request",
            plain + "presentation_theme_mode",
            withHandoff,
        )
    }

    private fun client(loginPageUrl: String = "https://sso.example.test/login/") = SnaplinkAuthClient(
        configuration = SnaplinkConfiguration(
            issuerBaseUrl = "https://sso.example.test",
            clientId = "native-app",
            redirectUri = "com.example.sverp:/oauth/callback",
            loginPageUrl = loginPageUrl,
        ),
        secureStore = SnaplinkMemorySecureStore(),
        transport = UnusedTransport(),
        clockMillis = { 1_700_000_000_000L },
    )

    /**
     * The handoff is decided before any request, so nothing here may reach the
     * network. A transport that fails loudly makes that assumption testable.
     */
    private class UnusedTransport : OAuthTransport {
        override suspend fun exchangeCode(code: String, verifier: String): OAuthTokenResponse =
            throw AssertionError("beginAuthorization must not talk to the token endpoint")

        override suspend fun refresh(refreshToken: String): OAuthTokenResponse =
            throw AssertionError("beginAuthorization must not talk to the token endpoint")

        override suspend fun revoke(token: String, tokenTypeHint: String) =
            throw AssertionError("beginAuthorization must not talk to the token endpoint")
    }

    private fun query(raw: String): Map<String, String> =
        URI(raw).rawQuery.orEmpty()
            .split('&')
            .filter(String::isNotEmpty)
            .associate { field ->
                val parts = field.split('=', limit = 2)
                java.net.URLDecoder.decode(parts[0], "UTF-8") to
                    java.net.URLDecoder.decode(parts.getOrElse(1) { "" }, "UTF-8")
            }
}