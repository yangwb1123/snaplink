package com.snaplink.sso

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import okio.Buffer
import okio.BufferedSource
import java.io.IOException

/**
 * Shared response handling for the Snaplink transports.
 *
 * Transport policy lives here rather than in the client so it is substitutable
 * in one place: a bounded read, and a single oracle-safe error decode that never
 * echoes the request.
 */
internal object SnaplinkHttp {
    const val MAX_RESPONSE_BYTES = 64 * 1024L
    const val MAX_ERROR_TEXT = 512

    val json: Json = Json { ignoreUnknownKeys = true }

    /** Reads at most [MAX_RESPONSE_BYTES], failing closed past the cap. */
    fun readBounded(source: BufferedSource): String {
        val buffer = Buffer()
        while (!source.exhausted()) {
            source.read(buffer, minOf(4096L, MAX_RESPONSE_BYTES + 1L - buffer.size))
            if (buffer.size > MAX_RESPONSE_BYTES) {
                throw SnaplinkAuthException("invalid_response", "Snaplink response exceeded the SDK size limit")
            }
        }
        return buffer.readUtf8()
    }

    /**
     * Decodes a non-2xx body into an error.
     *
     * The server's code is carried verbatim; a description is never used to
     * derive behaviour.
     */
    fun decodeError(status: Int, raw: String): SnaplinkAuthException {
        val body = runCatching { json.parseToJsonElement(raw).jsonObject }.getOrNull()
        val code = (body?.get("error") as? JsonPrimitive)
            ?.takeIf { it.isString }
            ?.content
            ?.takeIf(String::isNotBlank)
            ?: "http_error"
        val description = (body?.get("error_description") as? JsonPrimitive)
            ?.takeIf { it.isString }
            ?.content
            ?.takeIf(String::isNotBlank)
            ?: "Snaplink request failed with HTTP $status"
        return SnaplinkAuthException(code, description.take(MAX_ERROR_TEXT), status)
    }

    /** The headers every credential- or authorization-bearing request carries. */
    fun noStoreHeaders(): Map<String, String> = mapOf(
        "Accept" to "application/json",
        "Cache-Control" to "no-store",
        "Pragma" to "no-cache",
    )

    /** Reports a transport-level failure without echoing the request. */
    fun networkError(error: IOException): SnaplinkAuthException =
        SnaplinkAuthException("network_error", "Snaplink request failed", cause = error)

    internal fun JsonObject.stringField(name: String): String? =
        (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
}
