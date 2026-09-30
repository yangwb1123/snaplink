import Foundation

public struct SnaplinkConfiguration: Sendable {
    public let issuerBaseURL: URL
    public let loginPageURL: URL
    public let clientID: String
    public let redirectURI: URL
    public let scopes: [String]
    public let resources: [String]
    public let transactionTTL: TimeInterval
    public let prompt: String?
    public let loginHint: String?
    public let acrValues: String?
    public let uiLocales: String?
    public let maxAge: Int?

    public init(
        issuerBaseURL: URL,
        clientID: String,
        redirectURI: URL,
        loginPageURL: URL? = nil,
        scopes: [String] = ["openid", "profile", "email"],
        resources: [String] = [],
        transactionTTL: TimeInterval = 600,
        allowInsecureHTTPForDevelopment: Bool = false,
        prompt: String? = nil,
        loginHint: String? = nil,
        acrValues: String? = nil,
        uiLocales: String? = nil,
        maxAge: Int? = nil
    ) throws {
        let issuer = try Self.validatedWebURL(
            issuerBaseURL,
            name: "issuerBaseURL",
            allowQuery: false,
            allowInsecureHTTPForDevelopment: allowInsecureHTTPForDevelopment
        )
        let page = try Self.validatedWebURL(
            loginPageURL ?? URL(string: issuer.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/login/")!,
            name: "loginPageURL",
            allowQuery: true,
            allowInsecureHTTPForDevelopment: allowInsecureHTTPForDevelopment
        )
        try Self.validateRedirectURI(redirectURI)
        let cleanClientID = clientID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanClientID.isEmpty, !cleanClientID.contains(where: { $0.isWhitespace }) else {
            throw SnaplinkAuthError(code: "invalid_request", message: "clientID must be non-empty and whitespace-free")
        }
        let resolvedScopes = scopes.isEmpty ? ["openid", "profile", "email"] : scopes
        guard resolvedScopes.allSatisfy({ !$0.isEmpty && !$0.contains(where: { $0.isWhitespace }) }) else {
            throw SnaplinkAuthError(code: "invalid_request", message: "scope values must be non-empty and whitespace-free")
        }
        guard resources.allSatisfy({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) else {
            throw SnaplinkAuthError(code: "invalid_request", message: "resource values must be non-empty")
        }
        guard transactionTTL.isFinite, transactionTTL >= 1, transactionTTL <= 3600 else {
            throw SnaplinkAuthError(code: "invalid_request", message: "transactionTTL must be between 1 and 3600 seconds")
        }
        guard maxAge.map({ $0 >= 0 }) ?? true else {
            throw SnaplinkAuthError(code: "invalid_request", message: "maxAge must be non-negative")
        }
        try Self.rejectCredentialQuery(page, name: "loginPageURL")

        self.issuerBaseURL = Self.withoutTrailingSlash(issuer)
        self.loginPageURL = page
        self.clientID = cleanClientID
        self.redirectURI = redirectURI
        self.scopes = resolvedScopes
        self.resources = resources
        self.transactionTTL = transactionTTL
        self.prompt = prompt
        self.loginHint = loginHint
        self.acrValues = acrValues
        self.uiLocales = uiLocales
        self.maxAge = maxAge
    }

    private static func validatedWebURL(
        _ url: URL,
        name: String,
        allowQuery: Bool,
        allowInsecureHTTPForDevelopment: Bool
    ) throws -> URL {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil else {
            throw SnaplinkAuthError(code: "invalid_request", message: "\(name) must be an absolute HTTP(S) URL without credentials")
        }
        guard scheme == "https" || (scheme == "http" && allowInsecureHTTPForDevelopment && isLoopback(host)) else {
            throw SnaplinkAuthError(code: "invalid_request", message: "\(name) must use HTTPS; HTTP is allowed only for explicit loopback development")
        }
        if !allowQuery && components.query != nil || components.fragment != nil {
            throw SnaplinkAuthError(code: "invalid_request", message: "\(name) contains a forbidden query or fragment")
        }
        components.scheme = scheme
        return components.url ?? url
    }

    private static func validateRedirectURI(_ url: URL) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil else {
            throw SnaplinkAuthError(code: "invalid_request", message: "redirectURI must be an absolute registered callback without query or fragment")
        }
        let https = scheme == "https" && !(components.host ?? "").isEmpty
            && (components.port == nil || components.port == 443)
        let forbiddenSchemes: Set<String> = ["http", "https", "file", "javascript", "data", "content", "intent"]
        let custom = !forbiddenSchemes.contains(scheme) && !scheme.isEmpty
        guard https || custom else {
            throw SnaplinkAuthError(code: "invalid_request", message: "redirectURI must be HTTPS or a registered custom scheme")
        }
        if custom && components.host == nil && components.path.isEmpty {
            throw SnaplinkAuthError(code: "invalid_request", message: "custom redirectURI must identify an application callback")
        }
    }

    private static func rejectCredentialQuery(_ url: URL, name: String) throws {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let sensitive: Set<String> = ["client_secret", "code_verifier"]
        if items.contains(where: { sensitive.contains($0.name.lowercased()) }) {
            throw SnaplinkAuthError(code: "invalid_request", message: "\(name) contains a credential parameter")
        }
    }

    private static func withoutTrailingSlash(_ url: URL) -> URL {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return url }
        while components.path.count > 1 && components.path.hasSuffix("/") {
            components.path.removeLast()
        }
        return components.url ?? url
    }

    private static func isLoopback(_ host: String) -> Bool {
        let lowercased = host.lowercased()
        return lowercased == "localhost" || lowercased == "127.0.0.1" || lowercased == "::1"
    }
}
