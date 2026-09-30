import Foundation

/// Sends a normalized request over an ephemeral, cookie-free session.
///
/// The session owns the transport policy the cross-language contract expects to
/// live here rather than in the session layer: timeouts, redirect refusal, and
/// the response size cap. It performs no I/O in request construction, so the
/// request shape is testable with a double.
struct SnaplinkHTTPSender: @unchecked Sendable {
    private let session: URLSession

    init(session: URLSession? = nil) {
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.httpCookieStorage = nil
            configuration.httpShouldSetCookies = false
            configuration.urlCache = nil
            configuration.timeoutIntervalForRequest = Self.requestTimeout
            configuration.timeoutIntervalForResource = Self.requestTimeout
            self.session = URLSession(
                configuration: configuration,
                delegate: RejectRedirects(),
                delegateQueue: nil
            )
        }
    }

    func send(_ request: SnaplinkHTTPRequest) async throws -> Data {
        do {
            let (bytes, response) = try await session.bytes(for: make(request))
            guard let http = response as? HTTPURLResponse else {
                throw SnaplinkAuthError(code: "invalid_response", message: "Snaplink returned a non-HTTP response")
            }
            var data = Data()
            data.reserveCapacity(4096)
            for try await byte in bytes {
                data.append(byte)
                guard data.count <= Self.maximumResponseBytes else {
                    throw SnaplinkAuthError(
                        code: "invalid_response",
                        message: "Snaplink response exceeded the SDK size limit"
                    )
                }
            }
            guard (200..<300).contains(http.statusCode) else {
                throw Self.decodeError(data, status: http.statusCode)
            }
            return data
        } catch let error as SnaplinkAuthError {
            throw error
        } catch {
            // The failure message never echoes the request, so a credential
            // cannot leak through an error.
            throw SnaplinkAuthError(code: "network_error", message: "Snaplink request failed")
        }
    }

    private func make(_ request: SnaplinkHTTPRequest) -> URLRequest {
        var urlRequest = URLRequest(
            url: request.url,
            cachePolicy: .reloadIgnoringLocalCacheData,
            timeoutInterval: Self.requestTimeout
        )
        urlRequest.httpMethod = request.method
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }
        switch request.body {
        case .form(let fields): urlRequest.httpBody = Data(SnaplinkHTTPRequest.encodeForm(fields).utf8)
        case .json(let data): urlRequest.httpBody = data
        case nil: break
        }
        return urlRequest
    }

    private static func decodeError(_ data: Data, status: Int) -> SnaplinkAuthError {
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
            $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? nil
                : String($0.prefix(Self.maximumErrorText))
        } ?? "Snaplink request failed with HTTP \(status)"
        return SnaplinkAuthError(code: code, message: message, statusCode: status)
    }

    static let requestTimeout: TimeInterval = 15
    static let maximumResponseBytes = 64 * 1024
    static let maximumErrorText = 512
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
