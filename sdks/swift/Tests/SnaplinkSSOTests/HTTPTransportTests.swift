import Foundation
import XCTest
@testable import SnaplinkSSO

final class HTTPTransportTests: XCTestCase {
    func testTokenExchangeUsesFormBodyAndNeverUsesCookies() async throws {
        let capturedRequest = RequestCapture()
        StubURLProtocol.setHandler { request in
            capturedRequest.store(request)
            let body = Data(#"{"access_token":"access-1","token_type":"Bearer","expires_in":900,"refresh_token":"refresh-1"}"#.utf8)
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!, body)
        }
        defer { StubURLProtocol.setHandler(nil) }

        let configuration = try SnaplinkConfiguration(
            issuerBaseURL: URL(string: "https://sso.example.test")!,
            clientID: "ios-client",
            redirectURI: URL(string: "com.example.sverp:/oauth/callback")!
        )
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.httpCookieStorage = nil
        sessionConfiguration.httpShouldSetCookies = false
        sessionConfiguration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: sessionConfiguration)
        let transport = URLSessionOAuthTransport(configuration: configuration, session: session)

        let token = try await transport.exchangeCode("code+/=", verifier: "verifier+with space")
        XCTAssertEqual(token.accessToken, "access-1")
        XCTAssertEqual(token.refreshToken, "refresh-1")
        let request = try XCTUnwrap(capturedRequest.load())
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url?.path, "/token")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Cache-Control"), "no-store")
        XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
        XCTAssertTrue(request.value(forHTTPHeaderField: "Content-Type")?.contains("application/x-www-form-urlencoded") == true)
        let bodyData = try XCTUnwrap(request.httpBody)
        let body = try XCTUnwrap(String(data: bodyData, encoding: .utf8))
        let fields = decodeForm(body)
        XCTAssertEqual(fields["grant_type"], "authorization_code")
        XCTAssertEqual(fields["client_id"], "ios-client")
        XCTAssertEqual(fields["code"], "code+/=")
        XCTAssertEqual(fields["code_verifier"], "verifier+with space")
        XCTAssertFalse(body.contains("client_secret"))
    }
    func testRefreshRequestOmitsPKCEAndPreservesOAuthError() async throws {
        let capturedRequest = RequestCapture()
        StubURLProtocol.setHandler { request in
            capturedRequest.store(request)
            let body = Data(#"{"error":"invalid_grant","error_description":"refresh expired"}"#.utf8)
            return (HTTPURLResponse(url: request.url!, statusCode: 400, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!, body)
        }
        defer { StubURLProtocol.setHandler(nil) }

        let configuration = try SnaplinkConfiguration(
            issuerBaseURL: URL(string: "https://sso.example.test")!,
            clientID: "ios-client",
            redirectURI: URL(string: "com.example.sverp:/oauth/callback")!
        )
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.httpCookieStorage = nil
        sessionConfiguration.httpShouldSetCookies = false
        sessionConfiguration.protocolClasses = [StubURLProtocol.self]
        let transport = URLSessionOAuthTransport(
            configuration: configuration,
            session: URLSession(configuration: sessionConfiguration)
        )

        do {
            _ = try await transport.refresh("refresh-1")
            XCTFail("invalid refresh must fail")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_grant")
            XCTAssertEqual(error.statusCode, 400)
        }
        let request = try XCTUnwrap(capturedRequest.load())
        let requestBody = try XCTUnwrap(request.httpBody)
        let body = try XCTUnwrap(String(data: requestBody, encoding: .utf8))
        let fields = decodeForm(body)
        XCTAssertEqual(fields["grant_type"], "refresh_token")
        XCTAssertEqual(fields["refresh_token"], "refresh-1")
        XCTAssertEqual(fields["client_id"], "ios-client")
        XCTAssertNil(fields["code_verifier"])
    }
}

private func decodeForm(_ raw: String) -> [String: String] {
    func decode(_ component: Substring?) -> String {
        guard let component else { return "" }
        let plusDecoded = String(component).replacingOccurrences(of: "+", with: " ")
        return plusDecoded.removingPercentEncoding ?? plusDecoded
    }
    return Dictionary(uniqueKeysWithValues: raw.split(separator: "&").map { field in
        let parts = field.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        return (decode(parts.first), decode(parts.count > 1 ? parts[1] : nil))
    })
}

private final class RequestCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var request: URLRequest?

    func store(_ request: URLRequest) {
        lock.lock()
        defer { lock.unlock() }
        self.request = request
    }

    func load() -> URLRequest? {
        lock.lock()
        defer { lock.unlock() }
        return request
    }
}

private final class HandlerStorage: @unchecked Sendable {
    private let lock = NSLock()
    private var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    func set(_ handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?) {
        lock.lock()
        defer { lock.unlock() }
        self.handler = handler
    }

    func get() -> ((URLRequest) throws -> (HTTPURLResponse, Data))? {
        lock.lock()
        defer { lock.unlock() }
        return handler
    }
}

private final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    private static let handlers = HandlerStorage()

    static func setHandler(_ handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?) {
        handlers.set(handler)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handlers.get() else {
            client?.urlProtocol(self, didFailWithError: URLError(.resourceUnavailable))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
