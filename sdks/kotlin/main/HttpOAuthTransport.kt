package com.snaplink.sso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

internal class HttpOAuthTransport(
    private val config: SnaplinkConfiguration,
    private val http: SnaplinkHttpTransport = SnaplinkOkHttpTransport(),
) : OAuthTransport {
    override suspend fun exchangeCode(code: String, verifier: String): OAuthTokenResponse = requestToken(
        listOf(
            "grant_type" to "authorization_code",
            "client_id" to config.clientId,
            "code" to code,
            "code_verifier" to verifier,
            "redirect_uri" to config.redirectUri,
        ),
    )

    override suspend fun refresh(refreshToken: String): OAuthTokenResponse = requestToken(
        listOf(
            "grant_type" to "refresh_token",
            "client_id" to config.clientId,
            "refresh_token" to refreshToken,
        ),
    )

    override suspend fun revoke(token: String, tokenTypeHint: String) {
        SnaplinkHttp.read(
            http,
            credentialRequest(
                "token/revoke",
                listOf(
                    "client_id" to config.clientId,
                    "token" to token,
                    "token_type_hint" to tokenTypeHint,
                ),
            ),
        )
    }

    private suspend fun requestToken(form: List<Pair<String, String>>): OAuthTokenResponse =
        decodeTokenResponse(SnaplinkHttp.read(http, credentialRequest("token", form)))

    private fun credentialRequest(path: String, fields: List<Pair<String, String>>) =
        SnaplinkRequestFactory.credentialForm(
            baseURL = config.issuerBaseUrl,
            path = path,
            fields = fields.toMap(),
        )

    private fun decodeTokenResponse(raw: String): OAuthTokenResponse {
        try {
            val wire = SnaplinkHttp.json.decodeFromString<TokenWire>(raw)
            if (wire.accessToken.isBlank() || !wire.tokenType.equals("Bearer", ignoreCase = true) ||
                wire.expiresInSeconds <= 0 || wire.expiresInSeconds > MAX_TOKEN_LIFETIME_SECONDS
            ) {
                throw SnaplinkAuthException("invalid_response", "Snaplink returned an invalid token response")
            }
            return OAuthTokenResponse(
                accessToken = wire.accessToken,
                tokenType = wire.tokenType,
                expiresInSeconds = wire.expiresInSeconds,
                refreshToken = wire.refreshToken?.takeIf(String::isNotBlank),
                scope = wire.scope?.takeIf(String::isNotBlank),
            )
        } catch (error: SnaplinkAuthException) {
            throw error
        } catch (error: Exception) {
            throw SnaplinkAuthException("invalid_response", "Snaplink returned an invalid token response", cause = error)
        }
    }

    @Serializable
    private data class TokenWire(
        @SerialName("access_token") val accessToken: String,
        @SerialName("token_type") val tokenType: String,
        @SerialName("expires_in") val expiresInSeconds: Long,
        @SerialName("refresh_token") val refreshToken: String? = null,
        val scope: String? = null,
    )

    private companion object {
        const val MAX_TOKEN_LIFETIME_SECONDS = 31_536_000L
    }
}
