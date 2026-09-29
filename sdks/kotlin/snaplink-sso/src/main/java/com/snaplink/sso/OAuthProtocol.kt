package com.snaplink.sso

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale

internal data class PkcePair(val verifier: String, val challenge: String)
internal data class AuthorizationCallback(
    val code: String?,
    val state: String?,
    val issuer: String?,
    val error: String?,
    val errorDescription: String?,
)

internal object OAuthProtocol {
    private val random = SecureRandom()
    private val managedParameters = setOf(
        "client_id", "redirect_uri", "response_type", "response_mode", "scope", "state",
        "code_challenge", "code_challenge_method", "resource", "prompt", "max_age",
        "login_hint", "acr_values", "ui_locales",
    )

    fun createPkce(): PkcePair {
        val verifier = randomUrl(64)
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(StandardCharsets.US_ASCII))
        return PkcePair(verifier, Base64.getUrlEncoder().withoutPadding().encodeToString(digest))
    }

    fun randomUrl(byteCount: Int): String {
        val bytes = ByteArray(byteCount)
        random.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    fun buildAuthorizationUri(config: SnaplinkConfiguration, state: String, challenge: String): URI {
        val login = URI(config.loginPageUrl)
        val query = decodeQuery(login.rawQuery).filterNot { (name, _) ->
            name.lowercase(Locale.ROOT) in managedParameters
        }.toMutableList()
        query += "client_id" to config.clientId
        query += "redirect_uri" to config.redirectUri
        query += "response_type" to "code"
        query += "response_mode" to "query"
        query += "scope" to config.scopes.joinToString(" ")
        query += "state" to state
        query += "code_challenge" to challenge
        query += "code_challenge_method" to "S256"
        config.resources.forEach { query += "resource" to it }
        config.prompt?.takeIf(String::isNotEmpty)?.let { query += "prompt" to it }
        config.maxAge?.let { query += "max_age" to it.toString() }
        config.loginHint?.takeIf(String::isNotEmpty)?.let { query += "login_hint" to it }
        config.acrValues?.takeIf(String::isNotEmpty)?.let { query += "acr_values" to it }
        config.uiLocales?.takeIf(String::isNotEmpty)?.let { query += "ui_locales" to it }
        val encoded = query.joinToString("&") { (name, value) -> "${encode(name)}=${encode(value)}" }
        val originAndPath = buildString {
            append(login.scheme)
            append("://")
            append(login.rawAuthority)
            append(login.rawPath.orEmpty())
        }
        return URI("$originAndPath?$encoded")
    }

    fun parseCallback(config: SnaplinkConfiguration, callback: URI): AuthorizationCallback {
        if (callback.userInfo != null || callback.rawFragment != null) {
            throw SnaplinkAuthException("invalid_request", "authorization callback contains credentials or a fragment")
        }
        if (canonicalRedirect(callback) != canonicalRedirect(URI(config.redirectUri))) {
            throw SnaplinkAuthException("invalid_request", "callback URL does not match the registered redirectUri")
        }
        val params = decodeQuery(callback.rawQuery)
        fun single(name: String): String? {
            val matches = params.filter { it.first == name }.map { it.second }
            if (matches.size > 1) throw SnaplinkAuthException("invalid_request", "authorization callback has duplicate $name values")
            return matches.singleOrNull()
        }
        return AuthorizationCallback(
            code = single("code"),
            state = single("state"),
            issuer = single("iss"),
            error = single("error"),
            errorDescription = single("error_description"),
        )
    }

    fun canonicalIssuer(raw: String): String {
        val uri = URI(raw)
        if (uri.userInfo != null || uri.rawQuery != null || uri.rawFragment != null) return ""
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return ""
        val host = uri.host?.lowercase(Locale.ROOT) ?: return ""
        val port = when {
            uri.port < 0 -> ""
            scheme == "https" && uri.port == 443 -> ""
            scheme == "http" && uri.port == 80 -> ""
            else -> ":${uri.port}"
        }
        val path = uri.rawPath.orEmpty().trimEnd('/')
        return "$scheme://$host$port$path"
    }

    private fun canonicalRedirect(uri: URI): String {
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return ""
        val host = uri.host?.lowercase(Locale.ROOT)
        val authority = if (host == null) {
            uri.rawAuthority.orEmpty()
        } else {
            val port = when {
                uri.port < 0 -> ""
                scheme == "https" && uri.port == 443 -> ""
                else -> ":${uri.port}"
            }
            "$host$port"
        }
        return "$scheme:$authority${uri.rawPath.orEmpty()}"
    }

    private fun decodeQuery(raw: String?): List<Pair<String, String>> {
        if (raw.isNullOrEmpty()) return emptyList()
        return raw.split('&').map { item ->
            val equals = item.indexOf('=')
            val name = if (equals < 0) item else item.substring(0, equals)
            val value = if (equals < 0) "" else item.substring(equals + 1)
            decode(name) to decode(value)
        }
    }

    private fun encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8.name())

    private fun decode(value: String): String = try {
        URLDecoder.decode(value, StandardCharsets.UTF_8.name())
    } catch (error: IllegalArgumentException) {
        throw SnaplinkAuthException("invalid_request", "authorization callback has malformed query encoding", cause = error)
    }
}
