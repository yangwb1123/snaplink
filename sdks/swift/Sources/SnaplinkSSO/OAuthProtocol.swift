import CryptoKit
import Foundation
import Security

struct PKCEPair: Sendable {
    let verifier: String
    let challenge: String
}

struct AuthorizationCallback: Sendable {
    let code: String?
    let state: String?
    let issuer: String?
    let error: String?
    let errorDescription: String?
}

enum OAuthProtocol {
    private static let managedParameters: Set<String> = [
        "client_id", "redirect_uri", "response_type", "response_mode", "scope", "state",
        "code_challenge", "code_challenge_method", "resource", "prompt", "max_age",
        "login_hint", "acr_values", "ui_locales"
    ]

    static func createPKCE() throws -> PKCEPair {
        let verifier = try randomURLSafe(byteCount: 64)
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return PKCEPair(verifier: verifier, challenge: base64URL(Data(digest)))
    }

    static func randomURLSafe(byteCount: Int) throws -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        guard status == errSecSuccess else {
            throw SnaplinkAuthError(code: "crypto_error", message: "could not generate an OAuth transaction value")
        }
        return base64URL(Data(bytes))
    }

    static func buildAuthorizationURL(
        configuration: SnaplinkConfiguration,
        state: String,
        challenge: String
    ) throws -> URL {
        guard var components = URLComponents(url: configuration.loginPageURL, resolvingAgainstBaseURL: false) else {
            throw SnaplinkAuthError(code: "invalid_request", message: "loginPageURL is invalid")
        }
        var queryItems = (components.queryItems ?? []).filter { !managedParameters.contains($0.name.lowercased()) }
        queryItems += [
            URLQueryItem(name: "client_id", value: configuration.clientID),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI.absoluteString),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "response_mode", value: "query"),
            URLQueryItem(name: "scope", value: configuration.scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256")
        ]
        queryItems += configuration.resources.map { URLQueryItem(name: "resource", value: $0) }
        if let prompt = configuration.prompt, !prompt.isEmpty {
            queryItems.append(URLQueryItem(name: "prompt", value: prompt))
        }
        if let maxAge = configuration.maxAge {
            queryItems.append(URLQueryItem(name: "max_age", value: String(maxAge)))
        }
        if let loginHint = configuration.loginHint, !loginHint.isEmpty {
            queryItems.append(URLQueryItem(name: "login_hint", value: loginHint))
        }
        if let acrValues = configuration.acrValues, !acrValues.isEmpty {
            queryItems.append(URLQueryItem(name: "acr_values", value: acrValues))
        }
        if let uiLocales = configuration.uiLocales, !uiLocales.isEmpty {
            queryItems.append(URLQueryItem(name: "ui_locales", value: uiLocales))
        }
        components.queryItems = queryItems
        components.fragment = nil
        guard let url = components.url else {
            throw SnaplinkAuthError(code: "invalid_request", message: "could not construct hosted-login URL")
        }
        return url
    }

    static func parseCallback(
        configuration: SnaplinkConfiguration,
        callbackURL: URL
    ) throws -> AuthorizationCallback {
        guard callbackURL.user == nil, callbackURL.password == nil, callbackURL.fragment == nil,
              canonicalRedirect(callbackURL) == canonicalRedirect(configuration.redirectURI),
              let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false) else {
            throw SnaplinkAuthError(code: "invalid_request", message: "callback URL does not match the registered redirectURI")
        }
        let items = try decodeQuery(components.percentEncodedQuery)
        func one(_ name: String) throws -> String? {
            let values = items.filter { $0.0 == name }.map { $0.1 }
            guard values.count <= 1 else {
                throw SnaplinkAuthError(code: "invalid_request", message: "authorization callback has duplicate \(name) values")
            }
            return values.first
        }
        return AuthorizationCallback(
            code: try one("code"),
            state: try one("state"),
            issuer: try one("iss"),
            error: try one("error"),
            errorDescription: try one("error_description")
        )
    }

    static func canonicalIssuer(_ url: URL) -> String? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              let scheme = components.scheme?.lowercased(),
              let host = components.host?.lowercased() else { return nil }
        let port: String
        if (scheme == "https" && components.port == 443) || (scheme == "http" && components.port == 80) {
            port = ""
        } else if let value = components.port {
            port = ":\(value)"
        } else {
            port = ""
        }
        var path = components.percentEncodedPath
        while path.hasSuffix("/") { path.removeLast() }
        return "\(scheme)://\(host)\(port)\(path)"
    }

    private static func canonicalRedirect(_ url: URL) -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased() else { return "" }
        let authority: String
        if let host = components.host?.lowercased() {
            let port: String
            if scheme == "https" && components.port == 443 {
                port = ""
            } else if let value = components.port {
                port = ":\(value)"
            } else {
                port = ""
            }
            authority = "//\(host)\(port)"
        } else {
            authority = ""
        }
        return "\(scheme):\(authority)\(components.percentEncodedPath)"
    }

    private static func decodeQuery(_ raw: String?) throws -> [(String, String)] {
        guard let raw, !raw.isEmpty else { return [] }
        return try raw.split(separator: "&", omittingEmptySubsequences: false).map { field in
            let parts = field.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            func decode(_ component: Substring?) throws -> String {
                guard let component else { return "" }
                let formDecoded = String(component).replacingOccurrences(of: "+", with: " ")
                guard let value = formDecoded.removingPercentEncoding else {
                    throw SnaplinkAuthError(code: "invalid_request", message: "authorization callback has malformed query encoding")
                }
                return value
            }
            return (try decode(parts.first), try decode(parts.count > 1 ? parts[1] : nil))
        }
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
