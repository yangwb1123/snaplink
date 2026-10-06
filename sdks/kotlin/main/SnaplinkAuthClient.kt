package com.snaplink.sso

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
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
    private val commerceTransport: SnaplinkCommerceTransport,
) {
    private val sessionMutex = Mutex()
    private val pendingTransactionKey = storageKey("transaction")
    private val tokenSetKey = storageKey("tokens")
    private val pendingActivationKey = storageKey("activation")
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
        HttpCommerceTransport(configuration),
    )

    /**
     * Uses a caller-supplied store for the transaction, token, and activation
     * records. The transport and the clock stay the production ones; a store
     * that cannot keep a record fails the session closed rather than silently
     * reporting a signed-out client.
     */
    public constructor(
        secureStore: SnaplinkSecureStore,
        configuration: SnaplinkConfiguration,
    ) : this(
        configuration,
        secureStore,
        HttpOAuthTransport(configuration),
        System::currentTimeMillis,
        HttpCommerceTransport(configuration),
    )

    internal constructor(
        configuration: SnaplinkConfiguration,
        secureStore: SnaplinkSecureStore,
        transport: OAuthTransport,
        clockMillis: () -> Long,
    ) : this(configuration, secureStore, transport, clockMillis, FailingCommerceTransport)

    /**
     * Prepares a one-time product activation before hosted login.
     *
     * Safe to call repeatedly before redirecting; each call replaces the pending
     * ticket. The ticket is claimed automatically by the next successful
     * [handleAuthorizationCallback], so a license key or invitation code never
     * has to outlive the request that carried it.
     */
    public suspend fun setup(options: SnaplinkSetupOptions): SnaplinkActivationPreparation {
        val productId = options.productId.trim()
        if (productId.isEmpty()) {
            throw SnaplinkAuthException("invalid_request", "productId is required to prepare an activation")
        }
        val licenseKey = options.licenseKey?.trim()?.takeIf(String::isNotEmpty)
        val invitationCode = options.invitationCode?.trim()?.takeIf(String::isNotEmpty)
        if ((licenseKey == null) == (invitationCode == null)) {
            throw SnaplinkAuthException(
                "invalid_request",
                "exactly one of licenseKey or invitationCode is required",
            )
        }
        val preparation = commerceTransport.prepareActivation(
            SnaplinkActivationPrepareRequest(
                clientId = configuration.clientId,
                productId = productId,
                licenseKey = licenseKey,
                invitationCode = invitationCode,
                tenantHint = options.tenantHint,
                locale = options.locale,
                appVersion = options.appVersion,
            ),
        )
        withContext(Dispatchers.IO) {
            synchronized(storeLock) {
                secureStore.write(
                    pendingActivationKey,
                    encodePendingActivation(
                        PendingActivation(
                            productId = preparation.productId,
                            ticket = preparation.ticket,
                            expiresAtEpochSeconds = nowSeconds() + preparation.expiresInSeconds,
                        ),
                    ),
                )
            }
        }
        return preparation
    }

    /** Returns the server-derived account context for a product binding. */
    public suspend fun accountContext(productId: String): SnaplinkAccountContext {
        val bearer = accessToken()
        val product = productId.trim()
        if (product.isEmpty()) {
            throw SnaplinkAuthException("invalid_request", "productID is required to read the account context")
        }
        return commerceTransport.accountContext(product, bearer)
    }

    /** Returns the caller's stored allowlisted presentation preferences. */
    public suspend fun presentationPreferences(): SnaplinkPresentationPreferences {
        val raw = commerceTransport.myPreferences(accessToken())
        return SnaplinkPresentationPreferencesCodec.fromStored(raw)
    }

    /** Merges presentation preferences. An empty patch is an accepted no-op. */
    public suspend fun updatePresentationPreferences(patch: SnaplinkPresentationPreferencesPatch) {
        // Validate before the network: a malformed value must never reach the
        // server as a request.
        val fields = SnaplinkPresentationPreferencesCodec.toUpdateRequest(patch)
        commerceTransport.putMyPreferences(fields, accessToken())
    }

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
        if (logoutInProgress) throw SnaplinkAuthException("operation_in_progress", "a session lifecycle operation is in progress")
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
                if (logoutInProgress) throw SnaplinkAuthException("operation_in_progress", "a session lifecycle operation is in progress")
                secureStore.write(pendingTransactionKey, encodeTransaction(transaction))
                authorizationRevision.incrementAndGet()
            }
        }
        return url
    }

    /** Completes the app-link/custom-scheme callback. The transaction is consumed once. */
    public suspend fun handleAuthorizationCallback(callbackUri: URI): SnaplinkSession {
        if (logoutInProgress) throw SnaplinkAuthException("operation_in_progress", "a session lifecycle operation is in progress")
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
            val description = (callback.errorDescription ?: "authorization was not completed").take(MAX_OAUTH_ERROR_TEXT)
            throw SnaplinkAuthException(code.take(MAX_OAUTH_ERROR_CODE), description)
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
            claimPendingActivation(tokens.accessToken)
            tokens.toSession()
        }
    }

    /** Returns a valid bearer token, refreshing under a per-client single-flight lock. */
    public suspend fun accessToken(): String = sessionMutex.withLock {
        if (logoutInProgress || loggedOut) throw SnaplinkAuthException("login_required", "native login is required")
        val current = withContext(Dispatchers.IO) { readTokenSet() }
            ?: throw SnaplinkAuthException("login_required", "native login is required")
        if (current.isUsable()) {
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

    /** Removes local credentials without contacting Snaplink. */
    public suspend fun clear() {
        synchronized(storeLock) {
            if (logoutInProgress) throw SnaplinkAuthException("operation_in_progress", "a session lifecycle operation is already in progress")
            logoutInProgress = true
            loggedOut = true
            sessionRevision.incrementAndGet()
            authorizationRevision.incrementAndGet()
        }
        try {
            withContext(NonCancellable) {
                sessionMutex.withLock {
                    withContext(Dispatchers.IO) {
                        synchronized(storeLock) {
                            try {
                                secureStore.delete(tokenSetKey)
                            } finally {
                                secureStore.delete(pendingTransactionKey)
                                secureStore.delete(pendingActivationKey)
                            }
                        }
                    }
                }
            }
        } finally {
            synchronized(storeLock) { logoutInProgress = false }
        }
    }

    /** Revokes the best available token and always removes local credentials. */
    public suspend fun logout() {
        synchronized(storeLock) {
            if (logoutInProgress) throw SnaplinkAuthException("operation_in_progress", "a session lifecycle operation is already in progress")
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
                        synchronized(storeLock) {
                            secureStore.delete(pendingTransactionKey)
                            secureStore.delete(pendingActivationKey)
                        }
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

    /** Returns the persisted session after ensuring its access token is not expired. */
    public suspend fun currentSession(): SnaplinkSession {
        accessToken()
        val current = withContext(Dispatchers.IO) { readTokenSet() }
            ?: throw SnaplinkAuthException("login_required", "native login is required")
        return current.toSession()
    }

    /**
     * Whether this client holds a usable session in local storage right now.
     *
     * A point-in-time read: no network I/O, no refresh, and no write or delete, so
     * it can neither create nor resurrect a session. False means "authenticate
     * again" and is reported when no record exists, when the stored access token is
     * at or inside the refresh skew [accessToken] applies, and while a clear or
     * logout is in flight.
     *
     * A storage failure raises `secure_storage_error` instead of answering false:
     * an unreadable record and an absent session are different situations, and a
     * caller that cannot tell them apart must not be pushed into a re-login loop
     * by an SDK storage fault.
     */
    public suspend fun isLoggedIn(): Boolean {
        return withContext(Dispatchers.IO) {
            synchronized(storeLock) {
                // Same predicate [accessToken] applies before it reaches the
                // network: while a clear or logout is in flight, or after one
                // completed, there is no session to report.
                if (logoutInProgress || loggedOut) {
                    false
                } else {
                    secureStore.read(tokenSetKey)?.let(::decodeTokenSet)?.isUsable() == true
                }
            }
        }
    }

    /**
     * Claims a prepared activation with the freshly minted bearer, if one is
     * still pending for this client.
     *
     * The local session is already stored when this runs, so a claim failure
     * leaves the user signed in; read the outcome later with [accountContext].
     * A ticket the server already accepted is not retried: the pending record is
     * dropped either way, because the claim route is idempotent per subject and
     * a stale ticket must not linger in encrypted storage.
     */
    private suspend fun claimPendingActivation(bearer: String) {
        val pending = withContext(Dispatchers.IO) { readPendingActivation() } ?: return
        if (pending.expiresAtEpochSeconds <= nowSeconds()) {
            withContext(Dispatchers.IO) { secureStore.delete(pendingActivationKey) }
            return
        }
        try {
            commerceTransport.claimActivation(pending.ticket, pending.productId, bearer)
            withContext(Dispatchers.IO) { secureStore.delete(pendingActivationKey) }
        } catch (error: Exception) {
            withContext(Dispatchers.IO) { runCatching { secureStore.delete(pendingActivationKey) } }
            throw error
        }
    }

    private fun validateTransaction(transaction: LoginTransaction) {
        if (transaction.clientId != configuration.clientId ||
            OAuthProtocol.canonicalIssuer(transaction.issuer) != OAuthProtocol.canonicalIssuer(configuration.issuerBaseUrl) ||
            transaction.redirectUri != configuration.redirectUri
        ) {
            throw SnaplinkAuthException("invalid_request", "hosted-login transaction belongs to another client")
        }
        val nowMillis = clockMillis()
        val ageMillis = nowMillis - transaction.createdAtMillis
        val maxAgeMillis = configuration.transactionTtlSeconds * 1000
        if (nowMillis < transaction.createdAtMillis || ageMillis < 0 || ageMillis > maxAgeMillis) {
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

    private fun readPendingActivation(): PendingActivation? = synchronized(storeLock) {
        secureStore.read(pendingActivationKey)?.let(::decodePendingActivation)
    }

    private data class PendingActivation(
        val productId: String,
        val ticket: String,
        val expiresAtEpochSeconds: Long,
    )

    private fun encodePendingActivation(pending: PendingActivation): String = encodeBinary { output ->
        output.writeInt(STORAGE_VERSION)
        output.writeUTF(RECORD_ACTIVATION)
        output.writeUTF(pending.productId)
        output.writeUTF(pending.ticket)
        output.writeLong(pending.expiresAtEpochSeconds)
    }

    private fun decodePendingActivation(encoded: String): PendingActivation = decodeBinary(encoded) { input ->
        requireVersion(input)
        if (input.readUTF() != RECORD_ACTIVATION) {
            throw SnaplinkAuthException("secure_storage_error", "unsupported SDK secure-storage record")
        }
        PendingActivation(
            productId = input.readUTF(),
            ticket = input.readUTF(),
            expiresAtEpochSeconds = input.readLong(),
        )
    }

    private fun storageKey(kind: String): String {
        val identity = "${configuration.issuerBaseUrl}\u0000${configuration.clientId}\u0000${configuration.redirectUri}\u0000$kind"
        val digest = MessageDigest.getInstance("SHA-256").digest(identity.toByteArray(Charsets.UTF_8))
        return "snaplink.sso.v1.${Base64.getUrlEncoder().withoutPadding().encodeToString(digest)}"
    }

    private fun nowSeconds(): Long = clockMillis() / 1000

    /**
     * Whether this record can be served without a round trip.
     *
     * Shared with [isLoggedIn] so the query can never claim a session that
     * [accessToken] would have to renew: `isLoggedIn() == false` implies that
     * an [accessToken] call would reach the network.
     */
    private fun StoredTokenSet.isUsable(): Boolean =
        expiresAtEpochSeconds > nowSeconds() + REFRESH_SKEW_SECONDS

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
        private const val RECORD_ACTIVATION = "activation"
        private const val REFRESH_SKEW_SECONDS = 60
        private const val MAX_TOKEN_LIFETIME_SECONDS = 31_536_000L
        private const val MAX_OAUTH_ERROR_CODE = 64
        private const val MAX_OAUTH_ERROR_TEXT = 512
    }
}
