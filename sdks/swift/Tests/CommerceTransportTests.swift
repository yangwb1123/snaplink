import Foundation
import XCTest
@testable import SnaplinkSSO

final class CommerceTransportTests: XCTestCase {
    func testPrepareActivationSendsCredentialOnlyInTheJSONBody() async throws {
        let capture = CommerceRequestCapture()
        let transport = try makeTransport(capture: capture) { request in
            (200, Data(#"{"activation_ticket":"ticket-1","product_id":"pro","expires_in":300}"#.utf8))
        }

        let preparation = try await transport.prepareActivation(SnaplinkActivationPrepareRequest(
            clientID: "ios-client",
            productID: "pro",
            licenseKey: "lic-secret",
            invitationCode: nil,
            tenantHint: nil,
            locale: "en-US",
            appVersion: nil
        ))

        XCTAssertEqual(preparation.ticket, "ticket-1")
        XCTAssertEqual(preparation.productID, "pro")
        XCTAssertEqual(preparation.expiresIn, 300)

        let request = try XCTUnwrap(capture.load())
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url?.path, "/api/v1/activation/prepare")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Cache-Control"), "no-store")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Pragma"), "no-cache")
        XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
        let fields = try jsonBody(request)
        XCTAssertEqual(fields["client_id"], "ios-client")
        XCTAssertEqual(fields["product_id"], "pro")
        XCTAssertEqual(fields["license_key"], "lic-secret")
        XCTAssertEqual(fields["locale"], "en-US")
        XCTAssertNil(fields["invitation_code"])
        XCTAssertNil(fields["tenant_hint"])
        XCTAssertNil(fields["app_version"])
    }

    func testPrepareActivationRejectsATicketForAnotherProduct() async throws {
        let transport = try makeTransport { _ in
            (200, Data(#"{"activation_ticket":"t","product_id":"other","expires_in":300}"#.utf8))
        }
        do {
            _ = try await transport.prepareActivation(request(productID: "pro"))
            XCTFail("a ticket bound to another product must be rejected")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_response")
        }
    }

    func testClaimActivationSendsTheBearerAndTicket() async throws {
        let capture = CommerceRequestCapture()
        let transport = try makeTransport(capture: capture) { _ in (200, self.accountContextBody()) }

        let context = try await transport.claimActivation(
            ticket: "ticket-1",
            productID: "pro",
            bearer: "access-1"
        )

        XCTAssertEqual(context.productID, "pro")
        XCTAssertEqual(context.tenantID, "tenant-1")
        let request = try XCTUnwrap(capture.load())
        XCTAssertEqual(request.url?.path, "/api/v1/me/activation/claim")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer access-1")
        let fields = try jsonBody(request)
        XCTAssertEqual(fields["activation_ticket"], "ticket-1")
        XCTAssertEqual(fields["product_id"], "pro")
    }

    func testAccountContextIsABearerReadScopedToTheProduct() async throws {
        let capture = CommerceRequestCapture()
        let transport = try makeTransport(capture: capture) { _ in (200, self.accountContextBody()) }

        _ = try await transport.accountContext(productID: "pro", bearer: "access-1")

        let request = try XCTUnwrap(capture.load())
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertEqual(request.url?.path, "/api/v1/me/account-context")
        XCTAssertEqual(request.url?.query, "product_id=pro")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer access-1")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Cache-Control"), "no-store")
    }

    func testAccountContextRejectsAnIncompleteContext() async throws {
        let transport = try makeTransport { _ in
            (200, Data(#"{"context":{"product_id":"pro","tenant_id":""}}"#.utf8))
        }
        do {
            _ = try await transport.accountContext(productID: "pro", bearer: "access-1")
            XCTFail("a context without a tenant must be rejected")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_response")
        }
    }

    func testBackendOutageIsReportedAsTheServerError() async throws {
        let transport = try makeTransport { _ in
            (503, Data(#"{"error":"temporarily_unavailable","error_description":"activation backend down"}"#.utf8))
        }
        do {
            _ = try await transport.accountContext(productID: "pro", bearer: "access-1")
            XCTFail("a 503 must be surfaced")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "temporarily_unavailable")
            XCTAssertEqual(error.statusCode, 503)
        }
    }

    func testPreferencesRoundTripUsesTheAuthenticatedSelfServiceRoute() async throws {
        let capture = CommerceRequestCapture()
        let transport = try makeTransport(capture: capture) { request in
            request.httpMethod == "PUT" ? (200, Data(#"{"status":"ok"}"#.utf8)) : (200, Data("{}".utf8))
        }
        _ = try await transport.myPreferences(bearer: "access-1")
        let read = try XCTUnwrap(capture.load())
        XCTAssertEqual(read.httpMethod, "GET")
        XCTAssertEqual(read.url?.path, "/me/preferences")
        XCTAssertEqual(read.value(forHTTPHeaderField: "Authorization"), "Bearer access-1")
        XCTAssertEqual(read.value(forHTTPHeaderField: "Cache-Control"), "no-store")

        try await transport.putMyPreferences(["locale": "en-US"], bearer: "access-1")
        let write = try XCTUnwrap(capture.load())
        XCTAssertEqual(write.httpMethod, "PUT")
        XCTAssertEqual(write.url?.path, "/me/preferences")
        XCTAssertEqual(write.value(forHTTPHeaderField: "Authorization"), "Bearer access-1")
        XCTAssertEqual(try jsonBody(write), ["locale": "en-US"])
    }

    func testPreferencesUpdateRejectsAnUnexpectedStatus() async throws {
        let transport = try makeTransport { _ in (200, Data(#"{"status":"partial"}"#.utf8)) }
        do {
            try await transport.putMyPreferences(["locale": "en-US"], bearer: "access-1")
            XCTFail("an unexpected status must be reported")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_response")
        }
    }

    private func makeTransport(
        capture: CommerceRequestCapture = CommerceRequestCapture(),
        respond: @escaping (URLRequest) -> (Int, Data)
    ) throws -> URLSessionCommerceTransport {
        CommerceURLProtocolStub.handler = respond
        CommerceURLProtocolStub.capture = capture
        let configuration = try SnaplinkConfiguration(
            issuerBaseURL: URL(string: "https://sso.example.test")!,
            clientID: "ios-client",
            redirectURI: URL(string: "com.example.sverp:/oauth/callback")!
        )
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.httpCookieStorage = nil
        sessionConfiguration.httpShouldSetCookies = false
        sessionConfiguration.protocolClasses = [CommerceURLProtocolStub.self]
        return URLSessionCommerceTransport(
            configuration: configuration,
            session: URLSession(configuration: sessionConfiguration)
        )
    }

    private func request(productID: String) -> SnaplinkActivationPrepareRequest {
        SnaplinkActivationPrepareRequest(
            clientID: "ios-client",
            productID: productID,
            licenseKey: "lic-secret",
            invitationCode: nil,
            tenantHint: nil,
            locale: nil,
            appVersion: nil
        )
    }

    private func jsonBody(_ request: URLRequest) throws -> [String: String] {
        let data = try readBody(request)
        return try JSONDecoder().decode([String: String].self, from: data)
    }

    private func readBody(_ request: URLRequest) throws -> Data {
        if let body = request.httpBody { return body }
        let stream = try XCTUnwrap(request.httpBodyStream)
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBufferPointer { pointer -> Int in
                guard let baseAddress = pointer.baseAddress else { return 0 }
                return stream.read(baseAddress, maxLength: pointer.count)
            }
            guard count > 0 else { break }
            data.append(contentsOf: buffer.prefix(count))
        }
        return data
    }

    private func accountContextBody() -> Data {
        Data("""
        {"context":{"product_id":"pro","tenant_id":"tenant-1","entitlement":{
          "tenant_id":"tenant-1","subscription_id":"sub-1","plan":{"id":"pro","version":1},
          "revision":1,"active":true,"features":{"scim":true},"limits":{"users":{"soft":5,"hard":10}},
          "effective_at":"2026-01-01T00:00:00Z","generated_at":"2026-01-01T00:00:00Z"}}}
        """.utf8)
    }
}

final class CommerceRequestCapture: @unchecked Sendable {
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

final class CommerceURLProtocolStub: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    private static var _handler: ((URLRequest) -> (Int, Data))?
    private static var _capture: CommerceRequestCapture?

    static var handler: ((URLRequest) -> (Int, Data))? {
        get { lock.withLock { _handler } }
        set { lock.withLock { _handler = newValue } }
    }

    static var capture: CommerceRequestCapture? {
        get { lock.withLock { _capture } }
        set { lock.withLock { _capture = newValue } }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler, let capture = Self.capture else {
            client?.urlProtocol(self, didFailWithError: URLError(.resourceUnavailable))
            return
        }
        capture.store(request)
        let (status, data) = handler(request)
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: nil,
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private extension NSLock {
    func withLock<Value>(_ body: () -> Value) -> Value {
        lock()
        defer { unlock() }
        return body()
    }
}
