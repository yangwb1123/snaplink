package com.snaplink.sso

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.URI
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/** Hosted login, callback validation, secure token persistence, refresh, and revocation. */
public class SnaplinkAuthClient internal constructor(
    private val configuration: SnaplinkConfiguration,
    private val secureStore: SnaplinkSecureStore,
    private val transport: OAuthTransport,
    private val clockMillis: () -> Long,
) {
    private val sessionMutex = Mutex()
    private val pendingTransactionKey = storageKey("transaction")
    private val tokenSetKey = storageKey("tokens")
    private val storeLock = Any()
    private val sessionRevision = AtomicLong()
    private val authorizationRevision = AtomicLong()
    @Volatile private var logoutInProgress = false
    @Volatile private var loggedOut = false

    /** Uses AES-GCM encrypted app-private storage backed by Android Keystore. */
    public constructor(context: Context, configuration: SnaplinkConfiguration) : this(
        configuration,
        AndroidSecureStore(context.applicationContext),
        HttpOAuthTransport(configuration),
        System::currentTimeMillis,
    )

    /** Creates a one-use PKCE transaction and opens hosted login in a Custom Tab. */
    public suspend fun authorize(activity: Activity): URI {
        val authorizationUri = beginAuthorization()
        try {
            withContext(Dispatchers.Main.immediate) {
                CustomTabsIntent.Builder().build().launchUrl(activity, Uri.parse(authorizationUri.toString()))
            }
        } catch (error: ActivityNotFoundException) {
            throw SnaplinkAuthException("browser_unavailable", "system browser authorization could not be started", cause = error)
        }
        return authorizationUri
    }

    /** Persists a one-use state/verifier transaction and returns the browser URL. */
    public suspend fun beginAuthorization(): URI {
        if (logoutInProgress) throw SnaplinkAuthException("operation_in_progress", "logout is still in progress")
        val pkce = OAuthProtocol.createPkce()
        val transaction = LoginTransaction(
            issuer = configuration.issuerBaseUrl,
            clientId = configuration.clientId,
            redirectUri = configuration.redirectUri,
            state = OAuthProtocol.randomUrl(32),
            verifier = pkce.verifier,
            createdAtMillis = clockMillis(),
        )
        val url = OAuthProtocol.buildAuthorizationUri(configuration, transaction.state, pkce.challenge)
        withContext(Dispatchers.IO) {
            synchronized(storeLock) {
                if (logoutInProgress) throw SnaplinkAuthException("operation_in_progress", "logout is still in progress")
                secureStore.write(pendingTransactionKey, encodeTransaction(transaction))
                authorizationRevision.incrementAndGet()
            }
        }
        return url
    }

    /** Completes the app-link/custom-scheme callback. The transaction is consumed once. */
    public suspend fun handleAuthorizationCallback(callbackUri: URI): SnaplinkSession {
        if (logoutInProgress) throw SnaplinkAuthException("operation_in_progress", "logout is still in progress")
        val authorizationGeneration = authorizationRevision.get()
        val sessionGeneration = sessionRevision.get()
        val transaction = withContext(Dispatchers.IO) { takeTransaction() }
            ?: throw SnaplinkAuthException("invalid_request", "hosted-login transaction is missing or expired")
        validateTransaction(transaction)
        val callback = OAuthProtocol.parseCallback(configuration, callbackUri)
        if (callback.state.isNullOrEmpty() || callback.state != transaction.state) {
            throw SnaplinkAuthException("invalid_request", "authorization state did not match")
        }
        if (callback.issuer.isNullOrBlank() || OAuthProtocol.canonicalIssuer(callback.issuer) != OAuthProtocol.canonicalIssuer(transaction.issuer)) {
            throw SnaplinkAuthException("invalid_request", "authorization issuer did not match Snaplink")
        }
        callback.error?.takeIf(String::isNotBlank)?.let { code ->
            throw SnaplinkAuthException(code, callback.errorDescription ?: "authorization was not completed")
        }
        val code = callback.code?.takeIf(String::isNotBlank)
            ?: throw SnaplinkAuthException("invalid_request", "authorization response did not contain a code")
        return sessionMutex.withLock {
            if (logoutInProgress || authorizationGeneration != authorizationRevision.get() || sessionGeneration != sessionRevision.get()) {
                throw SnaplinkAuthException("invalid_request", "authorization transaction was superseded")
            }
            val response = transport.exchangeCode(code, transaction.verifier)
            val tokens = newTokenSet(response)
            withContext(Dispatchers.IO) {
                synchronized(storeLock) {
                    if (logoutInProgress || authorizationGeneration != authorizationRevision.get() || sessionGeneration != sessionRevision.get()) {
                        throw SnaplinkAuthException("invalid_request", "authorization transaction was superseded")
                    }
                    writeTokenSet(tokens)
                    loggedOut = false
                    sessionRevision.incrementAndGet()
                    authorizationRevision.incrementAndGet()
                }
            }
            tokens.toSession()
        }
    }

    /** Returns a valid bearer token, refreshing under a per-client single-flight lock. */
    public suspend fun accessToken(): String = sessionMutex.withLock {
        if (logoutInProgress || loggedOut) throw SnaplinkAuthException("login_required", "native login is required")
        val current = withContext(Dispatchers.IO) { readTokenSet() }
            ?: throw SnaplinkAuthException("login_required", "native login is required")
        if (current.expiresAtEpochSeconds > nowSeconds() + REFRESH_SKEW_SECONDS) {
            return@withLock current.accessToken
        }
        val refreshToken = current.refreshToken
        if (refreshToken.isNullOrBlank()) {
            withContext(Dispatchers.IO) { secureStore.delete(tokenSetKey) }
            throw SnaplinkAuthException("login_required", "the access token expired and no refresh token is available")
        }
        val refreshed = try {
            val response = transport.refresh(refreshToken)
            if (logoutInProgress) throw SnaplinkAuthException("login_required", "native login is required")
            mergeRefresh(current, response)
        } catch (error: Exception) {
            if (error is SnaplinkAuthException && error.errorCode == "invalid_grant") {
                withContext(Dispatchers.IO) { secureStore.delete(tokenSetKey) }
            }
            throw error
        }
        withContext(Dispatchers.IO) {
            synchronized(storeLock) {
                if (logoutInProgress) throw SnaplinkAuthException("login_required", "native login is required")
                writeTokenSet(refreshed)
            }
        }
        refreshed.accessToken
    }

    /** Revokes the best available token and always removes local credentials. */
    public suspend fun logout() {
        synchronized(storeLock) {
            if (logoutInProgress) throw SnaplinkAuthException("operation_in_progress", "logout is already in progress")
            logoutInProgress = true
            loggedOut = true
            sessionRevision.incrementAndGet()
            authorizationRevision.incrementAndGet()
        }
        try {
            sessionMutex.withLock {
                val tokenResult = withContext(Dispatchers.IO) { runCatching { readTokenSet() } }
                try {
                    withContext(Dispatchers.IO) { secureStore.delete(tokenSetKey) }
                } finally {
                    withContext(Dispatchers.IO) {
                        synchronized(storeLock) { secureStore.delete(pendingTransactionKey) }
                    }
                }
                val tokens = tokenResult.getOrThrow()
                if (tokens != null) {
                    val token = tokens.refreshToken ?: tokens.accessToken
                    val hint = if (tokens.refreshToken != null) "refresh_token" else "access_token"
                    transport.revoke(token, hint)
                }
            }
        } finally {
            synchronized(storeLock) { logoutInProgress = false }
        }
    }

    private fun validateTransaction(transaction: LoginTransaction) {
        if (transaction.clientId != configuration.clientId ||
            OAuthProtocol.canonicalIssuer(transaction.issuer) != OAuthProtocol.canonicalIssuer(configuration.issuerBaseUrl) ||
            transaction.redirectUri != configuration.redirectUri
        ) {
            throw SnaplinkAuthException("invalid_request", "hosted-login transaction belongs to another client")
        }
        val ageSeconds = (clockMillis() - transaction.createdAtMillis) / 1000
        if (ageSeconds < 0 || ageSeconds > configuration.transactionTtlSeconds) {
            throw SnaplinkAuthException("invalid_request", "hosted-login transaction is missing or expired")
        }
    }

    private fun newTokenSet(response: OAuthTokenResponse): StoredTokenSet {
        validateTokenResponse(response)
        return StoredTokenSet(
            accessToken = response.accessToken,
            refreshToken = response.refreshToken?.takeIf(String::isNotBlank),
            expiresAtEpochSeconds = nowSeconds() + response.expiresInSeconds,
            scope = response.scope,
        )
    }

    private fun mergeRefresh(current: StoredTokenSet, response: OAuthTokenResponse): StoredTokenSet {
        validateTokenResponse(response)
        return StoredTokenSet(
            accessToken = response.accessToken,
            refreshToken = response.refreshToken?.takeIf(String::isNotBlank) ?: current.refreshToken,
            expiresAtEpochSeconds = nowSeconds() + response.expiresInSeconds,
            scope = response.scope ?: current.scope,
        )
    }

    private fun validateTokenResponse(response: OAuthTokenResponse) {
        if (response.accessToken.isBlank() || !response.tokenType.equals("Bearer", ignoreCase = true) ||
            response.expiresInSeconds <= 0 || response.expiresInSeconds > MAX_TOKEN_LIFETIME_SECONDS
        ) {
            throw SnaplinkAuthException("invalid_response", "Snaplink returned an invalid token response")
        }
    }

    private fun readTokenSet(): StoredTokenSet? = secureStore.read(tokenSetKey)?.let(::decodeTokenSet)

    private fun writeTokenSet(tokens: StoredTokenSet) {
        secureStore.write(tokenSetKey, encodeTokenSet(tokens))
    }

    private fun takeTransaction(): LoginTransaction? = synchronized(storeLock) {
        val encoded = secureStore.read(pendingTransactionKey) ?: return@synchronized null
        secureStore.delete(pendingTransactionKey)
        decodeTransaction(encoded)
    }

    private fun storageKey(kind: String): String {
        val identity = "${configuration.issuerBaseUrl}\u0000${configuration.clientId}\u0000${configuration.redirectUri}\u0000$kind"
        val digest = MessageDigest.getInstance("SHA-256").digest(identity.toByteArray(Charsets.UTF_8))
        return "snaplink.sso.v1.${Base64.getUrlEncoder().withoutPadding().encodeToString(digest)}"
    }

    private fun nowSeconds(): Long = clockMillis() / 1000

    private fun encodeTransaction(transaction: LoginTransaction): String = encodeBinary { output ->
        output.writeInt(STORAGE_VERSION)
        output.writeUTF(transaction.issuer)
        output.writeUTF(transaction.clientId)
        output.writeUTF(transaction.redirectUri)
        output.writeUTF(transaction.state)
        output.writeUTF(transaction.verifier)
        output.writeLong(transaction.createdAtMillis)
    }

    private fun decodeTransaction(encoded: String): LoginTransaction = decodeBinary(encoded) { input ->
        requireVersion(input)
        LoginTransaction(
            issuer = input.readUTF(),
            clientId = input.readUTF(),
            redirectUri = input.readUTF(),
            state = input.readUTF(),
            verifier = input.readUTF(),
            createdAtMillis = input.readLong(),
        )
    }

    private fun encodeTokenSet(tokens: StoredTokenSet): String = encodeBinary { output ->
        output.writeInt(STORAGE_VERSION)
        output.writeUTF(tokens.accessToken)
        output.writeBoolean(tokens.refreshToken != null)
        tokens.refreshToken?.let(output::writeUTF)
        output.writeLong(tokens.expiresAtEpochSeconds)
        output.writeBoolean(tokens.scope != null)
        tokens.scope?.let(output::writeUTF)
    }

    private fun decodeTokenSet(encoded: String): StoredTokenSet = decodeBinary(encoded) { input ->
        requireVersion(input)
        StoredTokenSet(
            accessToken = input.readUTF(),
            refreshToken = if (input.readBoolean()) input.readUTF() else null,
            expiresAtEpochSeconds = input.readLong(),
            scope = if (input.readBoolean()) input.readUTF() else null,
        )
    }

    private fun requireVersion(input: DataInputStream) {
        if (input.readInt() != STORAGE_VERSION) throw SnaplinkAuthException("secure_storage_error", "unsupported SDK secure-storage record")
    }

    private fun encodeBinary(block: (DataOutputStream) -> Unit): String {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use(block)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes.toByteArray())
    }

    private fun <T> decodeBinary(encoded: String, block: (DataInputStream) -> T): T {
        try {
            val bytes = Base64.getUrlDecoder().decode(encoded)
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val value = block(input)
                if (input.available() != 0) throw IllegalArgumentException("trailing secure record data")
                return value
            }
        } catch (error: SnaplinkAuthException) {
            throw error
        } catch (error: Exception) {
            throw SnaplinkAuthException("secure_storage_error", "invalid SDK secure-storage record", cause = error)
        }
    }

    private fun StoredTokenSet.toSession() = SnaplinkSession(accessToken, expiresAtEpochSeconds)

    private data class LoginTransaction(
        val issuer: String,
        val clientId: String,
        val redirectUri: String,
        val state: String,
        val verifier: String,
        val createdAtMillis: Long,
    )

    private data class StoredTokenSet(
        val accessToken: String,
        val refreshToken: String?,
        val expiresAtEpochSeconds: Long,
        val scope: String?,
    )

    public companion object {
        private const val STORAGE_VERSION = 1
        private const val REFRESH_SKEW_SECONDS = 60
        private const val MAX_TOKEN_LIFETIME_SECONDS = 31_536_000L
    }
}
