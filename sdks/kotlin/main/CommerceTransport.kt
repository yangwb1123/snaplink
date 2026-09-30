package com.snaplink.sso

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import okhttp3.OkHttpClient
import java.io.IOException
import java.util.concurrent.TimeUnit

/** A prepared one-time activation, returned by the activation endpoint. */
public data class SnaplinkActivationPreparation(
    val ticket: String,
    val productId: String,
    val expiresInSeconds: Long,
)

/**
 * A paid-product or invitation activation prepared before hosted login.
 *
 * The credential is sent only in the HTTPS request body of
 * [SnaplinkAuthClient.setup]; the login transaction carries just the
 * short-lived ticket, which is claimed with the bearer after the code exchange.
 * Never place a license key or invitation code in a URL or in OAuth `state`.
 */
public data class SnaplinkSetupOptions(
    val productId: String,
    val licenseKey: String? = null,
    val invitationCode: String? = null,
    val tenantHint: String? = null,
    val locale: String? = null,
    val appVersion: String? = null,
)

internal data class SnaplinkActivationPrepareRequest(
    val clientId: String,
    val productId: String,
    val licenseKey: String?,
    val invitationCode: String?,
    val tenantHint: String?,
    val locale: String?,
    val appVersion: String?,
) {
    /**
     * Flattened JSON fields, omitting absent optionals so the request never
     * carries an empty credential field the server would read as a real one.
     */
    fun jsonFields(): Map<String, String> = buildMap {
        put("client_id", clientId)
        put("product_id", productId)
        licenseKey?.takeIf(String::isNotEmpty)?.let { put("license_key", it) }
        invitationCode?.takeIf(String::isNotEmpty)?.let { put("invitation_code", it) }
        tenantHint?.takeIf(String::isNotEmpty)?.let { put("tenant_hint", it) }
        locale?.takeIf(String::isNotEmpty)?.let { put("locale", it) }
        appVersion?.takeIf(String::isNotEmpty)?.let { put("app_version", it) }
    }
}

@Serializable
internal data class SnaplinkActivationPrepareResponse(
    @SerialName("activation_ticket") val activationTicket: String,
    @SerialName("product_id") val productId: String,
    @SerialName("expires_in") val expiresInSeconds: Long,
)

@Serializable
internal data class SnaplinkActivationContextResponse(
    val context: SnaplinkAccountContext,
)

@Serializable
internal data class SnaplinkPreferenceUpdateResponse(
    val status: String,
)

/** Activation and self-service calls the auth client needs. */
internal interface SnaplinkCommerceTransport {
    suspend fun prepareActivation(
        request: SnaplinkActivationPrepareRequest,
    ): SnaplinkActivationPreparation

    suspend fun claimActivation(
        ticket: String,
        productId: String,
        bearer: String,
    ): SnaplinkAccountContext

    suspend fun accountContext(productId: String, bearer: String): SnaplinkAccountContext

    suspend fun myPreferences(bearer: String): String

    suspend fun putMyPreferences(fields: Map<String, String>, bearer: String)
}

/**
 * OkHttp implementation over the commerce and self-service routes.
 *
 * The session is the same hardened one the OAuth transport uses: no cookies, no
 * redirects, a bounded read, and no-store headers on every request so a
 * credential or a bearer is never issued with a cacheable request.
 */
internal class HttpCommerceTransport(
    private val config: SnaplinkConfiguration,
    private val client: OkHttpClient = defaultClient(),
) : SnaplinkCommerceTransport {

    override suspend fun prepareActivation(
        request: SnaplinkActivationPrepareRequest,
    ): SnaplinkActivationPreparation {
        // The credential travels only in this JSON body: it must never reach an
        // authorization URL, OAuth state, or SDK storage.
        val body = jsonResponse(
            request = jsonRequest("api/v1/activation/prepare", request.jsonFields(), bearer = null),
        )
        val response = decode< SnaplinkActivationPrepareResponse >(body, "the activation endpoint returned an invalid ticket")
        val ticket = response.activationTicket.trim()
        if (ticket.isEmpty() || response.productId != request.productId || response.expiresInSeconds <= 0) {
            throw SnaplinkAuthException("invalid_response", "the activation endpoint returned an invalid ticket")
        }
        return SnaplinkActivationPreparation(ticket, response.productId, response.expiresInSeconds)
    }

    override suspend fun claimActivation(
        ticket: String,
        productId: String,
        bearer: String,
    ): SnaplinkAccountContext = decodeContext(
        jsonResponse(
            request = jsonRequest(
                path = "api/v1/me/activation/claim",
                fields = mapOf("activation_ticket" to ticket, "product_id" to productId),
                bearer = bearer,
            ),
        ),
    )

    override suspend fun accountContext(productId: String, bearer: String): SnaplinkAccountContext =
        decodeContext(
            read(
                SnaplinkRequestFactory.bearerRead(
                    baseURL = config.issuerBaseUrl,
                    path = "api/v1/me/account-context",
                    query = SnaplinkRequestFactory.query("product_id" to productId),
                    bearer = bearer,
                ),
            ),
        )

    override suspend fun myPreferences(bearer: String): String = read(
        SnaplinkRequestFactory.bearerRead(
            baseURL = config.issuerBaseUrl,
            path = "me/preferences",
            bearer = bearer,
        ),
    )

    override suspend fun putMyPreferences(fields: Map<String, String>, bearer: String) {
        val status = decode<SnaplinkPreferenceUpdateResponse>(
            jsonResponse(
                request = jsonRequest(path = "me/preferences", fields = fields, bearer = bearer, method = "PUT"),
            ),
            "Snaplink returned an unexpected preferences update status",
        ).status
        if (status != UPDATE_OK) {
            throw SnaplinkAuthException("invalid_response", "Snaplink returned an unexpected preferences update status")
        }
    }

    private fun jsonRequest(
        path: String,
        fields: Map<String, String>,
        bearer: String?,
        method: String = "POST",
    ): SnaplinkHttpRequest =
        SnaplinkRequestFactory.json(
            method = method,
            baseURL = config.issuerBaseUrl,
            path = path,
            fields = fields,
            bearer = bearer,
        )

    private suspend fun jsonResponse(request: SnaplinkHttpRequest): String = read(request)

    private fun read(request: SnaplinkHttpRequest): String = try {
        client.newCall(request.toOkHttp()).execute().use { response ->
            val body = response.body?.source()?.let(SnaplinkHttp::readBounded).orEmpty()
            if (!response.isSuccessful) throw SnaplinkHttp.decodeError(response.code, body)
            body
        }
    } catch (error: IOException) {
        throw SnaplinkHttp.networkError(error)
    }

    private fun decodeContext(raw: String): SnaplinkAccountContext {
        val context = decode< SnaplinkActivationContextResponse >(raw, "Snaplink returned an incomplete account context").context
        if (context.productId.isBlank() || context.tenantId.isBlank()) {
            throw SnaplinkAuthException("invalid_response", "Snaplink returned an incomplete account context")
        }
        return context
    }

    private inline fun <reified T> decode(raw: String, message: String): T = try {
        SnaplinkHttp.json.decodeFromString<T>(raw)
    } catch (error: Exception) {
        throw SnaplinkAuthException("invalid_response", message, cause = error)
    }

    private companion object {
        const val UPDATE_OK = "ok"

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
