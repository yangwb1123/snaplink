import Foundation

struct URLSessionOAuthTransport: OAuthTransport, @unchecked Sendable {
    private let configuration: SnaplinkConfiguration
    private let sender: SnaplinkHTTPSender

    init(configuration: SnaplinkConfiguration, session: URLSession? = nil) {
        self.configuration = configuration
        self.sender = SnaplinkHTTPSender(session: session)
    }

    func exchangeCode(_ code: String, verifier: String) async throws -> OAuthTokenResponse {
        try await tokenRequest([
            "grant_type": "authorization_code",
            "client_id": configuration.clientID,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": configuration.redirectURI.absoluteString
        ])
    }

    func refresh(_ refreshToken: String) async throws -> OAuthTokenResponse {
        try await tokenRequest([
            "grant_type": "refresh_token",
            "client_id": configuration.clientID,
            "refresh_token": refreshToken
        ])
    }

    func revoke(_ token: String, tokenTypeHint: String) async throws {
        let request = try credentialRequest(path: "token/revoke", fields: [
            "client_id": configuration.clientID,
            "token": token,
            "token_type_hint": tokenTypeHint
        ])
        _ = try await sender.send(request)
    }

    private func tokenRequest(_ fields: [String: String]) async throws -> OAuthTokenResponse {
        let data = try await sender.send(try credentialRequest(path: "token", fields: fields))
        do {
            let response = try JSONDecoder().decode(OAuthTokenResponse.self, from: data)
            guard !response.accessToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  response.tokenType.caseInsensitiveCompare("Bearer") == .orderedSame,
                  response.expiresIn > 0,
                  response.expiresIn <= 31_536_000 else {
                throw SnaplinkAuthError(code: "invalid_response", message: "Snaplink returned an invalid token response")
            }
            return OAuthTokenResponse(
                accessToken: response.accessToken,
                tokenType: response.tokenType,
                expiresIn: response.expiresIn,
                refreshToken: response.refreshToken.flatMap {
                    $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0
                },
                scope: response.scope.flatMap {
                    $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0
                }
            )
        } catch let error as SnaplinkAuthError {
            throw error
        } catch {
            throw SnaplinkAuthError(code: "invalid_response", message: "Snaplink returned an invalid token response")
        }
    }

    private func credentialRequest(path: String, fields: [String: String]) throws -> SnaplinkHTTPRequest {
        try SnaplinkRequestBuilder.credentialForm(
            baseURL: configuration.issuerBaseURL,
            path: path,
            fields: fields
        )
    }
}
