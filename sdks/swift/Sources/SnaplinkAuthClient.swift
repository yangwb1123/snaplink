import CryptoKit
import Foundation

/// Hosted login and token lifecycle for one native public OAuth client.
public actor SnaplinkAuthClient {
    private let configuration: SnaplinkConfiguration
    private let secureStore: any SnaplinkSecureStore
    private let transport: any OAuthTransport
    private let commerceTransport: any SnaplinkCommerceTransport
    private let clock: @Sendable () -> Date
    private let transactionAccount: String
    private let tokenAccount: String
    private let activationAccount: String
    private var refreshTask: Task<OAuthTokenResponse, Error>?
    private var sessionRevision: UInt64 = 0
    private var authorizationRevision: UInt64 = 0
    private var logoutInProgress = false
    private var loggedOut = false

    /// Uses Keychain storage and a cookie-free URLSession transport by default.
    public init(configuration: SnaplinkConfiguration) {
        self.init(
            configuration: configuration,
            secureStore: KeychainSecureStore(),
            transport: URLSessionOAuthTransport(configuration: configuration),
            commerceTransport: URLSessionCommerceTransport(configuration: configuration),
            clock: { Date() }
        )
    }

    init(
        configuration: SnaplinkConfiguration,
        secureStore: any SnaplinkSecureStore,
        transport: any OAuthTransport,
        clock: @escaping @Sendable () -> Date
    ) {
        self.init(
            configuration: configuration,
            secureStore: secureStore,
            transport: transport,
            commerceTransport: URLSessionCommerceTransport(configuration: configuration),
            clock: clock
        )
    }

    init(
        configuration: SnaplinkConfiguration,
        secureStore: any SnaplinkSecureStore,
        transport: any OAuthTransport,
        commerceTransport: any SnaplinkCommerceTransport,
        clock: @escaping @Sendable () -> Date
    ) {
        self.configuration = configuration
        self.secureStore = secureStore
        self.transport = transport
        self.commerceTransport = commerceTransport
        self.clock = clock
        self.transactionAccount = Self.storageAccount(configuration: configuration, kind: "transaction")
        self.tokenAccount = Self.storageAccount(configuration: configuration, kind: "tokens")
        self.activationAccount = Self.storageAccount(configuration: configuration, kind: "activation")
    }

    /// Prepares a one-time product activation before hosted login.
    ///
    /// Safe to call repeatedly before redirecting; each call replaces the pending
    /// ticket. The ticket is claimed automatically by the next successful
    /// ``handleAuthorizationCallback(_:)``, so a license key or invitation code
    /// never has to outlive the request that carried it.
    @discardableResult
    public func setup(_ options: SnaplinkSetupOptions) async throws -> SnaplinkActivationPreparation {
        let productID = options.productID.trimmingCharacters(in: .whitespacesAndNewlines)
        let licenseKey = options.licenseKey?.trimmingCharacters(in: .whitespacesAndNewlines)
        let invitationCode = options.invitationCode?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !productID.isEmpty else {
            throw SnaplinkAuthError(
                code: "invalid_request",
                message: "productID is required to prepare an activation"
            )
        }
        let hasLicense = licenseKey?.isEmpty == false
        let hasInvitation = invitationCode?.isEmpty == false
        guard hasLicense != hasInvitation else {
            throw SnaplinkAuthError(
                code: "invalid_request",
                message: "exactly one of licenseKey or invitationCode is required"
            )
        }
        let preparation = try await commerceTransport.prepareActivation(
            SnaplinkActivationPrepareRequest(
                clientID: configuration.clientID,
                productID: productID,
                licenseKey: hasLicense ? licenseKey : nil,
                invitationCode: hasInvitation ? invitationCode : nil,
                tenantHint: options.tenantHint,
                locale: options.locale,
                appVersion: options.appVersion
            )
        )
        let pending = PendingActivation(
            productID: preparation.productID,
            ticket: preparation.ticket,
            expiresAt: clock().addingTimeInterval(preparation.expiresIn)
        )
        try save(pending, account: activationAccount)
        return preparation
    }

    /// Returns the server-derived account context for a product binding.
    public func accountContext(productID: String) async throws -> SnaplinkAccountContext {
        let bearer = try await accessToken()
        let product = productID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !product.isEmpty else {
            throw SnaplinkAuthError(
                code: "invalid_request",
                message: "productID is required to read the account context"
            )
        }
        return try await commerceTransport.accountContext(productID: product, bearer: bearer)
    }

    /// Returns the caller's stored allowlisted presentation preferences.
    public func presentationPreferences() async throws -> SnaplinkPresentationPreferences {
        let bearer = try await accessToken()
        let raw = try await commerceTransport.myPreferences(bearer: bearer)
        return try SnaplinkPresentationPreferencesCodec.fromStored(raw)
    }

    /// Merges presentation preferences. An empty patch is an accepted no-op.
    public func updatePresentationPreferences(
        _ patch: SnaplinkPresentationPreferencesPatch
    ) async throws {
        let body = try SnaplinkPresentationPreferencesCodec.toUpdateRequest(patch)
        let bearer = try await accessToken()
        try await commerceTransport.putMyPreferences(body, bearer: bearer)
    }

    /// Creates a short-lived one-use transaction and returns the hosted-login URL.
    public func beginAuthorization() throws -> URL {
        guard !logoutInProgress else {
            throw SnaplinkAuthError(code: "operation_in_progress", message: "a session lifecycle operation is in progress")
        }
        let pkce = try OAuthProtocol.createPKCE()
        let state = try OAuthProtocol.randomURLSafe(byteCount: 32)
        let url = try OAuthProtocol.buildAuthorizationURL(
            configuration: configuration,
            state: state,
            challenge: pkce.challenge
        )
        let transaction = AuthorizationTransaction(
            issuer: configuration.issuerBaseURL.absoluteString,
            clientID: configuration.clientID,
            redirectURI: configuration.redirectURI.absoluteString,
            state: state,
            verifier: pkce.verifier,
            createdAt: clock()
        )
        try save(transaction, account: transactionAccount)
        authorizationRevision &+= 1
        return url
    }

    /// Validates the app-link/custom-scheme callback and performs the code exchange.
    public func handleAuthorizationCallback(_ callbackURL: URL) async throws -> SnaplinkSession {
        guard !logoutInProgress else {
            throw SnaplinkAuthError(code: "operation_in_progress", message: "a session lifecycle operation is in progress")
        }
        let sessionGeneration = sessionRevision
        let authorizationGeneration = authorizationRevision
        guard let transaction = try takeTransaction() else {
            throw SnaplinkAuthError(code: "invalid_request", message: "hosted-login transaction is missing or expired")
        }
        try validate(transaction)
        let callback = try OAuthProtocol.parseCallback(configuration: configuration, callbackURL: callbackURL)
        guard let state = callback.state, !state.isEmpty, state == transaction.state else {
            throw SnaplinkAuthError(code: "invalid_request", message: "authorization state did not match")
        }
        guard let issuer = callback.issuer, let issuerURL = URL(string: issuer),
              OAuthProtocol.canonicalIssuer(issuerURL) == OAuthProtocol.canonicalIssuer(configuration.issuerBaseURL) else {
            throw SnaplinkAuthError(code: "invalid_request", message: "authorization issuer did not match Snaplink")
        }
        if let error = callback.error,
           !error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw SnaplinkAuthError(
                code: String(error.prefix(64)),
                message: String((callback.errorDescription ?? "authorization was not completed").prefix(512))
            )
        }
        guard let code = callback.code,
              !code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw SnaplinkAuthError(code: "invalid_request", message: "authorization response did not contain a code")
        }
        let response = try await transport.exchangeCode(code, verifier: transaction.verifier)
        try validate(response)
        guard sessionGeneration == sessionRevision,
              authorizationGeneration == authorizationRevision,
              !logoutInProgress else {
            throw SnaplinkAuthError(code: "invalid_request", message: "authorization transaction was superseded")
        }
        let tokens = StoredTokenSet(
            response: response,
            previousRefreshToken: nil,
            previousScope: nil,
            now: clock()
        )
        try save(tokens, account: tokenAccount)
        loggedOut = false
        refreshTask = nil
        sessionRevision &+= 1
        authorizationRevision &+= 1
        _ = try await claimPendingActivation(bearer: tokens.accessToken)
        return tokens.session
    }

    /// Claims a prepared activation with the freshly minted bearer, if one is
    /// still pending for this client.
    ///
    /// The local session is already stored when this runs, so a claim failure
    /// leaves the user signed in; read the outcome later with
    /// ``accountContext(productID:)``. A ticket the server already accepted is
    /// not retried: the pending record is dropped either way, because the claim
    /// route is idempotent per subject and a stale ticket must not linger in
    /// Keychain.
    @discardableResult
    private func claimPendingActivation(bearer: String) async throws -> SnaplinkAccountContext? {
        guard let pending: PendingActivation = try load(account: activationAccount) else { return nil }
        guard pending.expiresAt > clock() else {
            try secureStore.delete(account: activationAccount)
            return nil
        }
        do {
            let context = try await commerceTransport.claimActivation(
                ticket: pending.ticket,
                productID: pending.productID,
                bearer: bearer
            )
            try secureStore.delete(account: activationAccount)
            return context
        } catch {
            try? secureStore.delete(account: activationAccount)
            throw error
        }
    }

    /// Returns a non-expired bearer token, refreshing with per-instance single-flight behavior.
    public func accessToken() async throws -> String {
        guard !logoutInProgress, !loggedOut else {
            throw SnaplinkAuthError(code: "login_required", message: "native login is required")
        }
        guard let current: StoredTokenSet = try load(account: tokenAccount) else {
            throw SnaplinkAuthError(code: "login_required", message: "native login is required")
        }
        let now = clock()
        if current.expiresAt > now && current.effectiveRefreshAt > now {
            return current.accessToken
        }
        guard let refreshToken = current.refreshToken, !refreshToken.isEmpty else {
            try secureStore.delete(account: tokenAccount)
            throw SnaplinkAuthError(code: "login_required", message: "the access token expired and no refresh token is available")
        }
        let generation = sessionRevision
        let task: Task<OAuthTokenResponse, Error>
        if let existing = refreshTask {
            task = existing
        } else {
            task = Task { try await transport.refresh(refreshToken) }
            refreshTask = task
        }
        do {
            let response = try await task.value
            try validate(response)
            guard generation == sessionRevision, !logoutInProgress else {
                throw SnaplinkAuthError(code: "login_required", message: "the session changed during token refresh")
            }
            let refreshed = StoredTokenSet(
                response: response,
                previousRefreshToken: current.refreshToken,
                previousScope: current.scope,
                now: clock()
            )
            try save(refreshed, account: tokenAccount)
            refreshTask = nil
            return refreshed.accessToken
        } catch {
            if generation == sessionRevision {
                refreshTask = nil
                if (error as? SnaplinkAuthError)?.code == "invalid_grant" {
                    try? secureStore.delete(account: tokenAccount)
                }
            }
            throw error
        }
    }

    /// Removes local credentials without contacting Snaplink.
    public func clear() throws {
        guard !logoutInProgress else {
            throw SnaplinkAuthError(code: "operation_in_progress", message: "a session lifecycle operation is already in progress")
        }
        logoutInProgress = true
        loggedOut = true
        sessionRevision &+= 1
        authorizationRevision &+= 1
        refreshTask?.cancel()
        refreshTask = nil
        defer { logoutInProgress = false }
        try clearLocalCredentials()
    }

    /// Returns the persisted session after ensuring its access token is not expired.
    public func currentSession() async throws -> SnaplinkSession {
        _ = try await accessToken()
        guard let current: StoredTokenSet = try load(account: tokenAccount) else {
            throw SnaplinkAuthError(code: "login_required", message: "native login is required")
        }
        return current.session
    }

    /// Revokes the refresh token when present and always clears local credentials first.
    public func logout() async throws {
        guard !logoutInProgress else {
            throw SnaplinkAuthError(code: "operation_in_progress", message: "a session lifecycle operation is already in progress")
        }
        logoutInProgress = true
        loggedOut = true
        sessionRevision &+= 1
        authorizationRevision &+= 1
        refreshTask?.cancel()
        refreshTask = nil
        defer { logoutInProgress = false }

        let tokens: StoredTokenSet?
        do {
            tokens = try load(account: tokenAccount)
        } catch {
            try? clearLocalCredentials()
            throw error
        }
        try clearLocalCredentials()
        guard let tokens else { return }
        let token = tokens.refreshToken ?? tokens.accessToken
        let hint = tokens.refreshToken == nil ? "access_token" : "refresh_token"
        try await transport.revoke(token, tokenTypeHint: hint)
    }

    private func validate(_ transaction: AuthorizationTransaction) throws {
        guard transaction.clientID == configuration.clientID,
              transaction.redirectURI == configuration.redirectURI.absoluteString,
              URL(string: transaction.issuer).flatMap(OAuthProtocol.canonicalIssuer) == OAuthProtocol.canonicalIssuer(configuration.issuerBaseURL) else {
            throw SnaplinkAuthError(code: "invalid_request", message: "hosted-login transaction belongs to another client")
        }
        let age = clock().timeIntervalSince(transaction.createdAt)
        guard age >= 0, age <= configuration.transactionTTL else {
            throw SnaplinkAuthError(code: "invalid_request", message: "hosted-login transaction is missing or expired")
        }
    }

    private func validate(_ response: OAuthTokenResponse) throws {
        guard !response.accessToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              response.tokenType.caseInsensitiveCompare("Bearer") == .orderedSame,
              response.expiresIn > 0, response.expiresIn <= 31_536_000 else {
            throw SnaplinkAuthError(code: "invalid_response", message: "Snaplink returned an invalid token response")
        }
    }

    private func takeTransaction() throws -> AuthorizationTransaction? {
        guard let transaction: AuthorizationTransaction = try load(account: transactionAccount) else { return nil }
        try secureStore.delete(account: transactionAccount)
        return transaction
    }

    private func clearLocalCredentials() throws {
        var firstError: Error?
        for account in [tokenAccount, transactionAccount, activationAccount] {
            do {
                try secureStore.delete(account: account)
            } catch {
                if firstError == nil { firstError = error }
            }
        }
        if let firstError { throw firstError }
    }

    private func load<Value: Decodable>(account: String) throws -> Value? {
        guard let data = try secureStore.read(account: account) else { return nil }
        guard data.count <= Self.maximumStoredBytes else {
            throw SnaplinkAuthError(code: "secure_storage_error", message: "stored SDK value exceeds the storage limit")
        }
        do {
            return try JSONDecoder().decode(Value.self, from: data)
        } catch {
            throw SnaplinkAuthError(code: "secure_storage_error", message: "stored SDK value is invalid")
        }
    }

    private func save<Value: Encodable>(_ value: Value, account: String) throws {
        do {
            let data = try JSONEncoder().encode(value)
            guard data.count <= Self.maximumStoredBytes else {
                throw SnaplinkAuthError(code: "secure_storage_error", message: "SDK value exceeds the storage limit")
            }
            try secureStore.write(data, account: account)
        } catch let error as SnaplinkAuthError {
            throw error
        } catch {
            throw SnaplinkAuthError(code: "secure_storage_error", message: "could not encode secure SDK value")
        }
    }

    private static func storageAccount(configuration: SnaplinkConfiguration, kind: String) -> String {
        let identity = "\(configuration.issuerBaseURL.absoluteString)\u{0}\(configuration.clientID)\u{0}\(configuration.redirectURI.absoluteString)\u{0}\(kind)"
        let digest = SHA256.hash(data: Data(identity.utf8))
        return "snaplink.sso.v1." + digest.map { String(format: "%02x", $0) }.joined()
    }

    private static let maximumStoredBytes = 64 * 1024
}

private struct AuthorizationTransaction: Codable, Sendable {
    let issuer: String
    let clientID: String
    let redirectURI: String
    let state: String
    let verifier: String
    let createdAt: Date
}

/// A prepared activation awaiting the post-login claim. It holds only the
/// opaque ticket, never the license key or invitation code.
private struct PendingActivation: Codable, Sendable {
    let productID: String
    let ticket: String
    let expiresAt: Date
}

struct StoredTokenSet: Codable, Sendable {
    let accessToken: String
    let refreshToken: String?
    let expiresAt: Date
    let refreshAt: Date?
    let scope: String?

    init(
        response: OAuthTokenResponse,
        previousRefreshToken: String?,
        previousScope: String?,
        now: Date
    ) {
        accessToken = response.accessToken
        refreshToken = response.refreshToken.flatMap { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0 }
            ?? previousRefreshToken
        let lifetime = TimeInterval(response.expiresIn)
        let epochSeconds = now.timeIntervalSince1970.rounded(.down)
        let issuedAt = Date(timeIntervalSince1970: epochSeconds)
        expiresAt = issuedAt.addingTimeInterval(lifetime)
        refreshAt = issuedAt.addingTimeInterval(lifetime - min(Self.maximumRefreshLead, lifetime / 10))
        scope = response.scope ?? previousScope
    }

    var effectiveRefreshAt: Date {
        min(refreshAt ?? expiresAt.addingTimeInterval(-Self.maximumRefreshLead), expiresAt)
    }

    var session: SnaplinkSession { SnaplinkSession(accessToken: accessToken, expiresAt: expiresAt) }

    private static let maximumRefreshLead: TimeInterval = 60
}
