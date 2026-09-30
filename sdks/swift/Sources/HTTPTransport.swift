import Foundation

struct URLSessionOAuthTransport: OAuthTransport, @unchecked Sendable {
    private let configuration: SnaplinkConfiguration
    private let session: URLSession

    init(configuration: SnaplinkConfiguration, session: URLSession? = nil) {
        self.configuration = configuration
        if let session {
            self.session = session
        } else {
            let delegate = RejectRedirects()
            let sessionConfiguration = URLSessionConfiguration.ephemeral
            sessionConfiguration.httpCookieStorage = nil
            sessionConfiguration.httpShouldSetCookies = false
            sessionConfiguration.urlCache = nil
            sessionConfiguration.timeoutIntervalForRequest = Self.requestTimeout
            sessionConfiguration.timeoutIntervalForResource = Self.requestTimeout
            self.session = URLSession(configuration: sessionConfiguration, delegate: delegate, delegateQueue: nil)
        }
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
        _ = try await post("token/revoke", form: [
            "client_id": configuration.clientID,
            "token": token,
            "token_type_hint": tokenTypeHint
        ])
    }

    private func tokenRequest(_ form: [String: String]) async throws -> OAuthTokenResponse {
        let data = try await post("token", form: form)
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

    private func post(_ path: String, form: [String: String]) async throws -> Data {
        var endpoint = configuration.issuerBaseURL
        for component in path.split(separator: "/") {
            endpoint.appendPathComponent(String(component))
        }
        var request = URLRequest(url: endpoint, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: Self.requestTimeout)
        request.httpMethod = "POST"
        request.httpBody = encodeForm(form)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("no-cache", forHTTPHeaderField: "Pragma")
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw SnaplinkAuthError(code: "invalid_response", message: "Snaplink returned a non-HTTP response")
            }
            var data = Data()
            data.reserveCapacity(4096)
            for try await byte in bytes {
                data.append(byte)
                guard data.count <= Self.maximumResponseBytes else {
                    throw SnaplinkAuthError(code: "invalid_response", message: "Snaplink response exceeded the SDK size limit")
                }
            }
            guard (200..<300).contains(http.statusCode) else {
                throw decodeError(data, status: http.statusCode)
            }
            return data
        } catch let error as SnaplinkAuthError {
            throw error
        } catch {
            throw SnaplinkAuthError(code: "network_error", message: "Snaplink request failed")
        }
    }

    private func encodeForm(_ values: [String: String]) -> Data {
        var components = URLComponents()
        components.queryItems = values.keys.sorted().map { URLQueryItem(name: $0, value: values[$0] ?? "") }
        let encoded = (components.percentEncodedQuery ?? "").replacingOccurrences(of: "%20", with: "+")
        return Data(encoded.utf8)
    }

    private func decodeError(_ data: Data, status: Int) -> SnaplinkAuthError {
        struct ErrorBody: Decodable {
            let error: String?
            let errorDescription: String?

            enum CodingKeys: String, CodingKey {
                case error
                case errorDescription = "error_description"
            }

            init(from decoder: Decoder) throws {
                let container = try decoder.container(keyedBy: CodingKeys.self)
                error = try? container.decode(String.self, forKey: .error)
                errorDescription = try? container.decode(String.self, forKey: .errorDescription)
            }
        }
        let body = try? JSONDecoder().decode(ErrorBody.self, from: data)
        let code = body?.error.flatMap {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0
        } ?? "http_error"
        let message = body?.errorDescription.flatMap {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : String($0.prefix(Self.maximumErrorText))
        } ?? "Snaplink request failed with HTTP \(status)"
        return SnaplinkAuthError(code: code, message: message, statusCode: status)
    }

    private static let requestTimeout: TimeInterval = 15
    private static let maximumResponseBytes = 64 * 1024
    private static let maximumErrorText = 512
}

private final class RejectRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}
