package com.snaplink.sso

import java.net.URI
import java.util.Locale

/** Public native OAuth client configuration. Client secrets are intentionally unsupported. */
public class SnaplinkConfiguration(
    issuerBaseUrl: String,
    public val clientId: String,
    redirectUri: String,
    loginPageUrl: String? = null,
    scopes: List<String> = listOf("openid", "profile", "email"),
    resources: List<String> = emptyList(),
    allowInsecureHttpForDevelopment: Boolean = false,
    public val transactionTtlSeconds: Long = 600,
    public val prompt: String? = null,
    public val loginHint: String? = null,
    public val acrValues: String? = null,
    public val uiLocales: String? = null,
    public val maxAge: Long? = null,
) {
    public val issuerBaseUrl: String = normalizeHttpUrl(
        issuerBaseUrl,
        "issuerBaseUrl",
        allowInsecureHttpForDevelopment,
    ).trimEnd('/')
    public val loginPageUrl: String = normalizeHttpUrl(
        loginPageUrl ?: "${this.issuerBaseUrl}/login/",
        "loginPageUrl",
        allowInsecureHttpForDevelopment,
        allowQuery = true,
    )
    public val redirectUri: String = normalizeRedirectUri(redirectUri)
    public val scopes: List<String> = scopes.ifEmpty { listOf("openid", "profile", "email") }.toList()
    public val resources: List<String> = resources.toList()

    init {
        if (clientId.isBlank() || clientId.any(Char::isWhitespace)) {
            throw SnaplinkAuthException("invalid_request", "clientId must be non-empty and whitespace-free")
        }
        if (this.scopes.any { it.isBlank() || it.any(Char::isWhitespace) }) {
            throw SnaplinkAuthException("invalid_request", "scope values must be non-empty and whitespace-free")
        }
        if (this.resources.any(String::isBlank)) {
            throw SnaplinkAuthException("invalid_request", "resource values must be non-empty")
        }
        if (transactionTtlSeconds !in 1..3600) {
            throw SnaplinkAuthException("invalid_request", "transactionTtlSeconds must be between 1 and 3600")
        }
        if (maxAge != null && maxAge < 0) {
            throw SnaplinkAuthException("invalid_request", "maxAge must be non-negative")
        }
        rejectSensitiveQuery(this.loginPageUrl, "loginPageUrl")
    }
}

private fun normalizeHttpUrl(
    raw: String,
    name: String,
    allowInsecureHttp: Boolean,
    allowQuery: Boolean = false,
): String {
    val uri = try {
        URI(raw.trim())
    } catch (error: Exception) {
        throw SnaplinkAuthException("invalid_request", "$name must be an absolute HTTP(S) URL", cause = error)
    }
    val scheme = uri.scheme?.lowercase(Locale.ROOT)
    val host = uri.host
    if (scheme !in setOf("https", "http") || host.isNullOrBlank() || uri.userInfo != null) {
        throw SnaplinkAuthException("invalid_request", "$name must be an absolute HTTP(S) URL without credentials")
    }
    if (scheme != "https" && !(allowInsecureHttp && isLoopback(host))) {
        throw SnaplinkAuthException("invalid_request", "$name must use HTTPS; HTTP is allowed only for explicit loopback development")
    }
    if ((!allowQuery && uri.rawQuery != null) || uri.rawFragment != null) {
        throw SnaplinkAuthException("invalid_request", "$name contains a forbidden query or fragment")
    }
    return uri.toASCIIString()
}

private fun normalizeRedirectUri(raw: String): String {
    val uri = try {
        URI(raw.trim())
    } catch (error: Exception) {
        throw SnaplinkAuthException("invalid_request", "redirectUri must be an absolute application callback URL", cause = error)
    }
    val scheme = uri.scheme?.lowercase(Locale.ROOT)
    val isHttp = scheme == "https" && !uri.host.isNullOrBlank()
    val isCustom = scheme != null && scheme !in setOf("http", "https", "file", "javascript", "data", "content", "intent")
    if (scheme.isNullOrBlank() || (!isHttp && !isCustom) || uri.userInfo != null || uri.rawQuery != null || uri.rawFragment != null) {
        throw SnaplinkAuthException("invalid_request", "redirectUri must be HTTPS or a registered custom scheme without query or fragment")
    }
    if (isCustom && uri.rawPath.isNullOrBlank() && uri.host.isNullOrBlank()) {
        throw SnaplinkAuthException("invalid_request", "custom redirectUri must identify an application callback")
    }
    return uri.toASCIIString()
}

private fun rejectSensitiveQuery(raw: String, name: String) {
    val query = URI(raw).rawQuery ?: return
    val sensitive = setOf("client_secret", "code_verifier")
    val names = query.split('&').map { item ->
        runCatching { java.net.URLDecoder.decode(item.substringBefore('='), Charsets.UTF_8.name()) }
            .getOrDefault(item.substringBefore('='))
            .lowercase(Locale.ROOT)
    }
    if (names.any(sensitive::contains)) {
        throw SnaplinkAuthException("invalid_request", "$name contains a credential parameter")
    }
}

private fun isLoopback(host: String): Boolean {
    val normalized = host.removePrefix("[").removeSuffix("]").lowercase(Locale.ROOT)
    return normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
}
