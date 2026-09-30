import CryptoKit
import Foundation

/// Hosted login and token lifecycle for one native public OAuth client.
public actor SnaplinkAuthClient {
    private let configuration: SnaplinkConfiguration
    private let secureStore: any SnaplinkSecureStore
    private let transport: any OAuthTransport
    private let clock: @Sendable () -> Date
    private let transactionAccount: String
    private let tokenAccount: String
    private var refreshTask: Task<OAuthTokenResponse, Error>?
    private var sessionRevision: UInt64 = 0
    private var authorizationRevision: UInt64 = 0
    private var logoutInProgress = false
    private var loggedOut = false

    /// Uses Keychain storage and a cookie-free URLSession transport by default.
    public init(configuration: SnaplinkConfiguration) {
        self.configuration = configuration
        self.secureStore = KeychainSecureStore()
        self.transport = URLSessionOAuthTransport(configuration: configuration)
        self.clock = { Date() }
        self.transactionAccount = Self.storageAccount(configuration: configuration, kind: "transaction")
        self.tokenAccount = Self.storageAccount(configuration: configuration, kind: "tokens")
    }

    init(
        configuration: SnaplinkConfiguration,
        secureStore: any SnaplinkSecureStore,
        transport: any OAuthTransport,
        clock: @escaping @Sendable () -> Date
    ) {
        self.configuration = configuration
        self.secureStore = secureStore
        self.transport = transport
        self.clock = clock
        self.transactionAccount = Self.storageAccount(configuration: configuration, kind: "transaction")
        self.tokenAccount = Self.storageAccount(configuration: configuration, kind: "tokens")
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
        return tokens.session
    }

    /// Returns a non-expired bearer token, refreshing with per-instance single-flight behavior.
    public func accessToken() async throws -> String {
        guard !logoutInProgress, !loggedOut else {
            throw SnaplinkAuthError(code: "login_required", message: "native login is required")
        }
        guard let current: StoredTokenSet = try load(account: tokenAccount) else {
            throw SnaplinkAuthError(code: "login_required", message: "native login is required")
        }
        if current.expiresAt.timeIntervalSince(clock()) > Self.refreshSkew {
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
        for account in [tokenAccount, transactionAccount] {
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

    private static let refreshSkew: TimeInterval = 60
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

struct StoredTokenSet: Codable, Sendable {
    let accessToken: String
    let refreshToken: String?
    let expiresAt: Date
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
        let epochSeconds = now.timeIntervalSince1970.rounded(.down)
        expiresAt = Date(timeIntervalSince1970: epochSeconds + TimeInterval(response.expiresIn))
        scope = response.scope ?? previousScope
    }

    var session: SnaplinkSession { SnaplinkSession(accessToken: accessToken, expiresAt: expiresAt) }
}
