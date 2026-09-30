import Foundation

public struct SnaplinkAuthError: Error, Sendable, Equatable, LocalizedError, SnaplinkClassifiedError {
    public let code: String
    public let message: String
    public let statusCode: Int?

    public init(code: String, message: String, statusCode: Int? = nil) {
        self.code = code
        self.message = message
        self.statusCode = statusCode
    }

    public var errorDescription: String? { message }

    public var status: Int? { statusCode }

    /// The server's code verbatim, with its class from the shared taxonomy.
    public var classification: SnaplinkErrorClassification {
        SnaplinkErrorClassification(code: code, status: statusCode)
    }
}

public struct SnaplinkSession: Sendable, Equatable {
    public let accessToken: String
    public let expiresAt: Date
}

/// Secure key/value storage boundary. Production defaults to Keychain.
protocol SnaplinkSecureStore: Sendable {
    func read(account: String) throws -> Data?
    func write(_ data: Data, account: String) throws
    func delete(account: String) throws
}

struct OAuthTokenResponse: Decodable, Sendable {
    let accessToken: String
    let tokenType: String
    let expiresIn: Int
    let refreshToken: String?
    let scope: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case scope
    }
}

protocol OAuthTransport: Sendable {
    func exchangeCode(_ code: String, verifier: String) async throws -> OAuthTokenResponse
    func refresh(_ refreshToken: String) async throws -> OAuthTokenResponse
    func revoke(_ token: String, tokenTypeHint: String) async throws
}
