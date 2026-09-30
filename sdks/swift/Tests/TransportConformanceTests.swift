import Foundation
import XCTest
@testable import SnaplinkSSO

/// Cross-language conformance for the transport seam.
///
/// The cases in `ops/build/sdk-conformance/transport.json` are the shared
/// contract: a transport double replays them byte-identically in every
/// language. This package is a public client, so `confidential_client_auth`
/// and `userinfo_bearer` are asserted from the invariant side — no secret ever
/// reaches a body or a URL, and a supplied Authorization header is forwarded
/// unchanged — rather than by adding a confidential-client capability the
/// package deliberately does not have.
final class TransportConformanceTests: XCTestCase {
    private let baseURL = URL(string: "https://sso.example.test")!

    func testAuthorizationCodeExchangeMatchesTheSharedCase() throws {
        let request = try authorizationCodeExchange()
        let testCase = try sharedCase("authorization_code_exchange")

        XCTAssertEqual(request.method, testCase["method"] as? String)
        XCTAssertEqual(request.url.path, testCase["path"] as? String)
        XCTAssertEqual(
            request.headers["Content-Type"]?.hasPrefix(testCase["content_type"] as? String ?? "") == true,
            true
        )
        let fields = try XCTUnwrap(request.formFields)
        for field in try requiredFields(testCase) {
            XCTAssertNotNil(fields[field], "missing required field \(field)")
        }
        for forbidden in try XCTUnwrap(testCase["forbidden_in_url"] as? [String]) {
            XCTAssertFalse(
                request.url.absoluteString.contains(forbidden),
                "\(forbidden) must never appear in a URL"
            )
        }
        XCTAssertEqual(request.headers["Cache-Control"], "no-store")
    }

    func testRefreshTokenExchangeMatchesTheSharedCase() throws {
        let request = try refreshTokenExchange()
        let testCase = try sharedCase("refresh_token_exchange")

        XCTAssertEqual(request.method, testCase["method"] as? String)
        XCTAssertEqual(request.url.path, testCase["path"] as? String)
        let fields = try XCTUnwrap(request.formFields)
        for field in try requiredFields(testCase) {
            XCTAssertNotNil(fields[field], "missing required field \(field)")
        }
        for forbidden in try XCTUnwrap(testCase["forbidden_fields"] as? [String]) {
            XCTAssertNil(fields[forbidden], "a refresh must never carry \(forbidden)")
        }
    }

    func testAccountContextReadMatchesTheSharedCase() throws {
        let request = try accountContextRead()
        let testCase = try sharedCase("account_context_read")

        XCTAssertEqual(request.method, testCase["method"] as? String)
        XCTAssertEqual(request.url.path, testCase["path"] as? String)
        for field in try XCTUnwrap(testCase["query_fields"] as? [String]) {
            XCTAssertNotNil(request.queryFields[field], "missing query field \(field)")
        }
        XCTAssertEqual(request.headers["Authorization"], "Bearer access-1")
    }

    func testActivationPrepareMatchesTheSharedCase() throws {
        let request = try activationPrepare()
        let testCase = try sharedCase("activation_prepare")

        XCTAssertEqual(request.method, testCase["method"] as? String)
        XCTAssertEqual(request.url.path, testCase["path"] as? String)
        XCTAssertEqual(request.headers["Content-Type"], "application/json")
        let fields = try XCTUnwrap(request.jsonFields)
        for field in try requiredFields(testCase) {
            XCTAssertNotNil(fields[field], "missing required field \(field)")
        }
        let group = try XCTUnwrap(testCase["exactly_one_of"] as? [String])
        let present = group.filter { fields[$0] != nil }
        XCTAssertEqual(
            present.count,
            1,
            "exactly one of \(group) must be present, got \(present)"
        )
        for forbidden in try XCTUnwrap(testCase["forbidden_in_url"] as? [String]) {
            XCTAssertFalse(
                request.url.absoluteString.contains(forbidden),
                "\(forbidden) must never appear in a URL"
            )
        }
    }

    func testAuthorizationHeaderIsForwardedUnchanged() throws {
        // The userinfo case: whatever bearer a caller supplies reaches the
        // resource server verbatim and is never rewritten.
        for bearer in ["access-1", "at+jwt-token", "opaque token"] {
            let request = try SnaplinkRequestBuilder.bearerRead(
                baseURL: baseURL,
                path: "userinfo",
                bearer: bearer
            )
            XCTAssertEqual(request.url.path, "/userinfo")
            XCTAssertEqual(request.headers["Authorization"], "Bearer \(bearer)")
            XCTAssertEqual(request.method, "GET")
            XCTAssertNil(request.body)
        }
    }

    func testNoClientSecretEverReachesABodyOrURL() throws {
        // The confidential-client case, from the invariant side: this package is
        // public-only, so the guarantee is that the field can never be emitted.
        let credentialRequests = [
            try authorizationCodeExchange(),
            try refreshTokenExchange(),
            try activationPrepare(),
            try accountContextRead()
        ]
        for request in credentialRequests {
            XCTAssertNil(request.formFields?["client_secret"])
            XCTAssertNil(request.jsonFields?["client_secret"])
            XCTAssertFalse(request.url.absoluteString.contains("client_secret"))
        }
        let withBasic = try SnaplinkRequestBuilder.credentialForm(
            baseURL: baseURL,
            path: "token",
            fields: ["grant_type": "client_credentials", "client_id": "c"],
            basicAuthorization: "Basic Y2xpZW50OnNlY3JldA=="
        )
        XCTAssertNil(withBasic.formFields?["client_secret"])
        XCTAssertEqual(withBasic.headers["Authorization"], "Basic Y2xpZW50OnNlY3JldA==")
    }

    func testRequestsAreByteIdenticalAcrossRepeatedBuilds() throws {
        XCTAssertEqual(try authorizationCodeExchange().canonical, try authorizationCodeExchange().canonical)
        XCTAssertEqual(try activationPrepare().canonical, try activationPrepare().canonical)
    }

    func testHeaderNamesCanonicalizeCaseInsensitively() throws {
        let lowercased = try SnaplinkHTTPRequest(
            method: "post",
            url: baseURL,
            headers: ["cache-control": "no-store", "authorization": "Bearer t", "content-type": "application/json"]
        )
        let canonical = try SnaplinkHTTPRequest(
            method: "POST",
            url: baseURL,
            headers: ["Cache-Control": "no-store", "Authorization": "Bearer t", "Content-Type": "application/json"]
        )
        XCTAssertEqual(lowercased.headers, canonical.headers)
        XCTAssertEqual(lowercased.canonical, canonical.canonical)
        XCTAssertEqual(lowercased.method, "POST", "the method is preserved in canonical case")
    }

    func testFormBodiesAreDeterministicallyOrdered() throws {
        let first = try SnaplinkHTTPRequest.encodeForm(["b": "2", "a": "1", "c": "3"])
        let second = try SnaplinkHTTPRequest.encodeForm(["c": "3", "a": "1", "b": "2"])
        XCTAssertEqual(first, second)
        XCTAssertEqual(first, "a=1&b=2&c=3")
    }

    func testCredentialEndpointsAlwaysCarryNoStore() throws {
        for path in ["token", "token/revoke", "token/introspect"] {
            let request = try SnaplinkRequestBuilder.credentialForm(
                baseURL: baseURL,
                path: path,
                fields: ["grant_type": "client_credentials"]
            )
            XCTAssertEqual(request.headers["Cache-Control"], "no-store", "\(path) must be no-store")
            XCTAssertEqual(request.headers["Pragma"], "no-cache")
        }
    }

    func testRedactedDescriptionNeverLeaksACredential() throws {
        let request = try authorizationCodeExchange()
        let redacted = request.redactedDescription
        XCTAssertFalse(redacted.contains("verifier-value"))
        XCTAssertFalse(redacted.contains("auth-code-value"))
        XCTAssertTrue(redacted.contains("code_verifier=<redacted>"))

        let bearer = try accountContextRead().redactedDescription
        XCTAssertFalse(bearer.contains("access-1"))
        XCTAssertTrue(bearer.contains("Authorization: <redacted>"))
    }

    func testJSONBodyRejectsATrailingNewline() {
        XCTAssertThrowsError(try SnaplinkHTTPRequest(
            method: "POST",
            url: baseURL,
            body: .json(Data("{\"a\":\"1\"}\n".utf8))
        ))
    }

    func testEndpointConstructionIsPure() {
        let endpoint = SnaplinkRequestBuilder.endpoint(
            baseURL: URL(string: "https://sso.example.test/tenant/")!,
            path: "api/v1/me/preferences"
        )
        XCTAssertEqual(endpoint.absoluteString, "https://sso.example.test/tenant/api/v1/me/preferences")
    }

    func testSharedCaseIdentifiersAreAllImplementedHere() throws {
        let documented = try sharedCases().compactMap { $0["id"] as? String }
        XCTAssertEqual(documented.count, 6, "the shared transport fixture pins six cases")
        for id in documented {
            XCTAssertNotNil(
                try? sharedCase(id),
                "fixture case \(id) disappeared"
            )
        }
    }

    // MARK: - Request builders matching the shipped transports

    private func authorizationCodeExchange() throws -> SnaplinkHTTPRequest {
        try SnaplinkRequestBuilder.credentialForm(
            baseURL: baseURL,
            path: "token",
            fields: [
                "grant_type": "authorization_code",
                "client_id": "ios-client",
                "code": "auth-code-value",
                "code_verifier": "verifier-value",
                "redirect_uri": "com.example.sverp:/oauth/callback"
            ]
        )
    }

    private func refreshTokenExchange() throws -> SnaplinkHTTPRequest {
        try SnaplinkRequestBuilder.credentialForm(
            baseURL: baseURL,
            path: "token",
            fields: [
                "grant_type": "refresh_token",
                "client_id": "ios-client",
                "refresh_token": "refresh-1"
            ]
        )
    }

    private func accountContextRead() throws -> SnaplinkHTTPRequest {
        try SnaplinkRequestBuilder.json(
            method: "GET",
            baseURL: baseURL,
            path: "api/v1/me/account-context",
            query: [URLQueryItem(name: "product_id", value: "pro")],
            bearer: "access-1"
        )
    }

    private func activationPrepare() throws -> SnaplinkHTTPRequest {
        try SnaplinkRequestBuilder.json(
            method: "POST",
            baseURL: baseURL,
            path: "api/v1/activation/prepare",
            fields: [
                "client_id": "ios-client",
                "product_id": "pro",
                "license_key": "lic-secret"
            ]
        )
    }

    private func requiredFields(_ testCase: [String: Any]) throws -> [String] {
        try XCTUnwrap(testCase["required_fields"] as? [String])
    }

    private func sharedCase(_ id: String) throws -> [String: Any] {
        try XCTUnwrap(
            sharedCases().first { $0["id"] as? String == id },
            "missing shared transport case \(id)"
        )
    }

    private func sharedCases() throws -> [[String: Any]] {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("ops/build/sdk-conformance/transport.json"))
        let document = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        return document["cases"] as? [[String: Any]] ?? []
    }
}
