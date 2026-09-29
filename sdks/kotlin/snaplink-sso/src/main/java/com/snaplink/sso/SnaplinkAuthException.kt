package com.snaplink.sso

/** A fail-closed OAuth or SDK error. Token values are never included in its message. */
public class SnaplinkAuthException(
    public val errorCode: String,
    message: String,
    public val httpStatus: Int? = null,
    cause: Throwable? = null,
) : Exception(message, cause)

/** A successfully authenticated native public-client session. */
public data class SnaplinkSession(
    public val accessToken: String,
    public val expiresAtEpochSeconds: Long,
)

/** Internal boundary for app-private token and PKCE storage. */
internal interface SnaplinkSecureStore {
    fun read(key: String): String?
    fun write(key: String, value: String)
    fun delete(key: String)
}

internal data class OAuthTokenResponse(
    val accessToken: String,
    val tokenType: String,
    val expiresInSeconds: Long,
    val refreshToken: String?,
    val scope: String?,
)

internal interface OAuthTransport {
    suspend fun exchangeCode(code: String, verifier: String): OAuthTokenResponse
    suspend fun refresh(refreshToken: String): OAuthTokenResponse
    suspend fun revoke(token: String, tokenTypeHint: String)
}
