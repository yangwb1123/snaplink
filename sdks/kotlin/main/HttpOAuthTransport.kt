package com.snaplink.sso

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.contentOrNull
import okhttp3.OkHttpClient
import java.io.IOException
import java.util.concurrent.TimeUnit

internal class HttpOAuthTransport(
    private val config: SnaplinkConfiguration,
    private val client: OkHttpClient = defaultClient(),
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
        withContext(Dispatchers.IO) {
            val response = post(
                credentialRequest(
                    "token/revoke",
                    listOf(
                        "client_id" to config.clientId,
                        "token" to token,
                        "token_type_hint" to tokenTypeHint,
                    ),
                ),
            )
            if (!response.isSuccessful) throw decodeError(response.code, response.body)
        }
    }

    private suspend fun requestToken(form: List<Pair<String, String>>): OAuthTokenResponse = withContext(Dispatchers.IO) {
        val response = post(credentialRequest("token", form))
        if (!response.isSuccessful) throw decodeError(response.code, response.body)
        decodeTokenResponse(response.body)
    }

    private fun post(request: SnaplinkHttpRequest): BoundedResponse = try {
        client.newCall(request.toOkHttp()).execute().use { response ->
            val body = response.body?.source()?.let(SnaplinkHttp::readBounded).orEmpty()
            BoundedResponse(response.code, response.isSuccessful, body)
        }
    } catch (error: IOException) {
        throw SnaplinkHttp.networkError(error)
    }

    /**
     * Builds a credential request through the normalized factory so the form
     * ordering, header canonicalization, and no-store policy are applied in one
     * place for every credential call.
     */
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

    private fun decodeError(status: Int, raw: String): SnaplinkAuthException =
        SnaplinkHttp.decodeError(status, raw)

    @Serializable
    private data class TokenWire(
        @SerialName("access_token") val accessToken: String,
        @SerialName("token_type") val tokenType: String,
        @SerialName("expires_in") val expiresInSeconds: Long,
        @SerialName("refresh_token") val refreshToken: String? = null,
        val scope: String? = null,
    )

    private data class BoundedResponse(val code: Int, val isSuccessful: Boolean, val body: String)

    private companion object {
        const val MAX_TOKEN_LIFETIME_SECONDS = 31_536_000L

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .cookieJar(okhttp3.CookieJar.NO_COOKIES)
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .callTimeout(15, TimeUnit.SECONDS)
            .build()
    }
}
