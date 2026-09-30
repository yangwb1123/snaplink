package com.snaplink.sso

import okhttp3.FormBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer

/**
 * A normalized Snaplink HTTP request.
 *
 * This is the shape the cross-language transport contract compares: two SDKs
 * building the same call must produce byte-identical requests, so header names
 * are canonicalized, form fields are ordered, and a JSON body carries no
 * trailing newline. Building one performs no I/O, so the request shape is
 * testable without a transport.
 */
internal class SnaplinkHttpRequest(
    method: String,
    url: String,
    headers: Map<String, String> = emptyMap(),
    val body: Body? = null,
) {
    /** The method in canonical upper case, so a case-insensitive call agrees. */
    val method: String = method.uppercase()

    val url: String = url

    /** The request path without the query, so a case matches the shared fixture. */
    val path: String = url.substringBefore('?').let { withoutQuery ->
        val afterScheme = withoutQuery.substringAfter("://", withoutQuery)
        val firstSlash = afterScheme.indexOf('/')
        if (firstSlash < 0) "/" else afterScheme.substring(firstSlash)
    }

    /**
     * Header names in a fixed casing, matched case-insensitively, so two SDKs
     * that spell a header differently still produce the same canonical form.
     */
    val headers: Map<String, String> = headers.entries.associate { (name, value) ->
        canonicalName(name) to value
    }

    sealed interface Body {
        /** Already-encoded form fields, in the order they go on the wire. */
        data class Form(val fields: List<Pair<String, String>>) : Body

        /** UTF-8 JSON bytes with no trailing newline. */
        data class Json(val text: String) : Body
    }

    init {
        require(body !is Body.Json || !body.text.endsWith("\n")) {
            "the JSON body must not end with a newline"
        }
    }

    private fun canonicalName(name: String): String {
        val lowercased = name.lowercase()
        return KNOWN_HEADERS.firstOrNull { it.lowercase() == lowercased } ?: name
    }

    override fun toString(): String = "SnaplinkHttpRequest($method $url)"

    /**
     * A stable, byte-comparable rendering.
     *
     * Deliberately only the request line, sorted headers, and the body: two SDKs
     * agree on this string or they disagree about the call.
     */
    fun canonical(): String = buildString {
        append(method).append(' ').append(url).append('\n')
        for (name in headers.keys.sorted()) {
            append(name).append(": ").append(headers[name]).append('\n')
        }
        append('\n')
        when (val payload = body) {
            is Body.Form -> append(payload.fields.joinToString("&") { (key, value) -> "$key=${encodeComponent(key)}=${encodeComponent(value)}" })
            is Body.Json -> append(payload.text)
            null -> Unit
        }
    }

    /**
     * A rendering safe to put in a log: sensitive headers and credential form
     * fields are redacted, and nothing else is.
     *
     * A transport must never log a header whose name matches Authorization,
     * DPoP, or a cookie, nor the value of a credential form field, so the
     * redaction list lives with the request rather than in each call site.
     */
    fun redactedDescription(): String = buildString {
        append(method).append(' ').append(url).append('\n')
        for (name in headers.keys.sorted()) {
            val value = if (name.lowercase() in SENSITIVE_HEADERS) REDACTED else headers[name]
            append(name).append(": ").append(value).append('\n')
        }
        when (val payload = body) {
            is Body.Form -> {
                for ((key, value) in payload.fields.sortedBy { it.first }) {
                    val shown = if (key.lowercase() in SENSITIVE_FORM_FIELDS) REDACTED else value
                    append(key).append('=').append(shown).append('\n')
                }
            }
            is Body.Json -> append(REDACTED).append(" json body\n")
            null -> Unit
        }
    }

    /** Converts to an OkHttp request, applying the canonical header spelling. */
    fun toOkHttp(): Request {
        val builder = Request.Builder().url(url)
        for ((name, value) in headers) builder.header(name, value)
        when (val payload = body) {
            is Body.Form -> builder.post(formBody(payload.fields))
            is Body.Json -> builder.method(method, payload.text.toRequestBody(JSON_MEDIA_TYPE))
            null -> builder.method(method, null)
        }
        return builder.build()
    }

    internal companion object {
        const val REDACTED = "<redacted>"

        /** Header names with a fixed canonical spelling. */
        val KNOWN_HEADERS = listOf(
            "Accept",
            "Authorization",
            "Cache-Control",
            "Content-Type",
            "Pragma",
        )

        /** Header names that must never be logged, matched case-insensitively. */
        val SENSITIVE_HEADERS = setOf(
            "authorization",
            "proxy-authorization",
            "dpop",
            "cookie",
            "set-cookie",
        )

        /** Form fields whose values are credentials and must never be logged. */
        val SENSITIVE_FORM_FIELDS = setOf(
            "code",
            "code_verifier",
            "client_secret",
            "refresh_token",
            "password",
            "license_key",
            "invitation_code",
            "activation_ticket",
            "assertion",
        )

        /**
         * Builds a form body with deterministic field ordering.
         *
         * Sorted keys mean the same call produces the same bytes in every SDK
         * and on every run, so a recorded request replays identically.
         */
        fun formBody(fields: List<Pair<String, String>>): FormBody = FormBody.Builder().apply {
            for ((key, value) in fields) add(key, value)
        }.build()

        /** Percent-encodes one form component the way a form body does. */
        fun encodeComponent(value: String): String = value
            .toByteArray(Charsets.UTF_8)
            .joinToString("") { byte ->
                val ch = byte.toInt().toChar()
                if (ch.isLetterOrDigit() || ch in "-._~") ch.toString() else "%%%02X".format(byte)
            }
    }
}

/** The media type of a JSON request body. */
internal val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

/**
 * Builds Snaplink requests: a pure function of its inputs, performing no I/O.
 */
internal object SnaplinkRequestFactory {
    /** Joins a path onto the issuer base URL without I/O. */
    fun endpoint(baseURL: String, path: String): String =
        "${baseURL.trimEnd('/')}/${path.trim('/')}"

    /** A query string with deterministic ordering. */
    fun query(vararg pairs: Pair<String, String>): String = pairs
        .sortedBy { it.first }
        .joinToString("&") { (key, value) ->
            "${SnaplinkHttpRequest.encodeComponent(key)}=${SnaplinkHttpRequest.encodeComponent(value)}"
        }

    /**
     * A credential-endpoint request: form body, no-store, no cookies.
     *
     * `Cache-Control: no-store` is applied here rather than per call site so a
     * credential cannot be issued with a cacheable request by omission.
     */
    fun credentialForm(baseURL: String, path: String, fields: Map<String, String>): SnaplinkHttpRequest =
        SnaplinkHttpRequest(
            method = "POST",
            url = endpoint(baseURL, path),
            headers = SnaplinkHttp.noStoreHeaders() + ("Content-Type" to "application/x-www-form-urlencoded; charset=utf-8"),
            body = SnaplinkHttpRequest.Body.Form(fields.toSortedFieldList()),
        )

    /** A JSON request, optionally authenticated with a bearer token. */
    fun json(
        method: String,
        baseURL: String,
        path: String,
        fields: Map<String, String> = emptyMap(),
        bearer: String? = null,
    ): SnaplinkHttpRequest = SnaplinkHttpRequest(
        method = method,
        url = endpoint(baseURL, path),
        headers = SnaplinkHttp.noStoreHeaders() + ("Content-Type" to "application/json") +
            bearerHeader(bearer),
        body = if (fields.isEmpty()) null else SnaplinkHttpRequest.Body.Json(jsonText(fields)),
    )

    /** A bearer-authenticated read with no request body. */
    fun bearerRead(
        baseURL: String,
        path: String,
        query: String? = null,
        bearer: String,
    ): SnaplinkHttpRequest = SnaplinkHttpRequest(
        method = "GET",
        url = buildString {
            append(endpoint(baseURL, path))
            if (!query.isNullOrEmpty()) append('?').append(query)
        },
        headers = SnaplinkHttp.noStoreHeaders() + bearerHeader(bearer),
    )

    private fun bearerHeader(bearer: String?): Map<String, String> =
        if (bearer.isNullOrEmpty()) emptyMap() else mapOf("Authorization" to "Bearer $bearer")

    /** Deterministic JSON object text: sorted keys, no trailing newline. */
    fun jsonText(fields: Map<String, String>): String = buildString {
        append('{')
        fields.keys.sorted().forEachIndexed { index, key ->
            if (index > 0) append(',')
            append('"').append(escape(key)).append("\":\"").append(escape(fields[key] ?: "")).append('"')
        }
        append('}')
    }

    private fun escape(value: String): String = buildString {
        for (ch in value) {
            when (ch) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (ch < ' ') append("\\u%04x".format(ch.code)) else append(ch)
            }
        }
    }

    private fun Map<String, String>.toSortedFieldList(): List<Pair<String, String>> =
        keys.sorted().map { key -> key to (this[key] ?: "") }
}
