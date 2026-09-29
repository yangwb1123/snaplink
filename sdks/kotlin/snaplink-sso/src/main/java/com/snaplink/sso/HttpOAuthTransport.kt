package com.snaplink.sso

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okio.Buffer
import okio.BufferedSource
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
                "${config.issuerBaseUrl}/token/revoke",
                listOf(
                    "client_id" to config.clientId,
                    "token" to token,
                    "token_type_hint" to tokenTypeHint,
                ),
            )
            if (!response.isSuccessful) throw decodeError(response.code, response.body)
        }
    }

    private suspend fun requestToken(form: List<Pair<String, String>>): OAuthTokenResponse = withContext(Dispatchers.IO) {
        val response = post("${config.issuerBaseUrl}/token", form)
        if (!response.isSuccessful) throw decodeError(response.code, response.body)
        decodeTokenResponse(response.body)
    }

    private fun post(endpoint: String, values: List<Pair<String, String>>): BoundedResponse {
        val form = FormBody.Builder().apply { values.forEach { (key, value) -> add(key, value) } }.build()
        val request = Request.Builder()
            .url(endpoint)
            .header("Accept", "application/json")
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache")
            .post(form)
            .build()
        return try {
            client.newCall(request).execute().use { response ->
                val body = response.body?.source()?.let(::readBounded).orEmpty()
                BoundedResponse(response.code, response.isSuccessful, body)
            }
        } catch (error: IOException) {
            throw SnaplinkAuthException("network_error", "Snaplink request failed", cause = error)
        }
    }

    private fun readBounded(source: BufferedSource): String {
        val buffer = Buffer()
        while (!source.exhausted()) {
            source.read(buffer, minOf(4096L, MAX_RESPONSE_BYTES + 1L - buffer.size))
            if (buffer.size > MAX_RESPONSE_BYTES) {
                throw SnaplinkAuthException("invalid_response", "Snaplink response exceeded the SDK size limit")
            }
        }
        return buffer.readUtf8()
    }

    private fun decodeTokenResponse(raw: String): OAuthTokenResponse {
        try {
            val wire = json.decodeFromString<TokenWire>(raw)
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

    private fun decodeError(status: Int, raw: String): SnaplinkAuthException {
        val body = runCatching { json.parseToJsonElement(raw).jsonObject }.getOrNull()
        val code = (body?.get("error") as? JsonPrimitive)?.contentOrNull?.takeIf(String::isNotBlank) ?: "http_error"
        val description = (body?.get("error_description") as? JsonPrimitive)?.contentOrNull?.takeIf(String::isNotBlank)
            ?: "Snaplink request failed with HTTP $status"
        return SnaplinkAuthException(code, description.take(MAX_ERROR_TEXT), status)
    }

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
        const val MAX_RESPONSE_BYTES = 64 * 1024L
        const val MAX_ERROR_TEXT = 512
        const val MAX_TOKEN_LIFETIME_SECONDS = 31_536_000L
        val json = Json { ignoreUnknownKeys = true }

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
