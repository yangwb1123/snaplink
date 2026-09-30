import CryptoKit
import Foundation
import XCTest
@testable import SnaplinkSSO

final class SnaplinkAuthClientTests: XCTestCase {
    func testAuthorizationURLUsesS256AndDoesNotExposeVerifier() async throws {
        let setup = try fixture()
        let url = try await setup.client.beginAuthorization()
        let query = try queryItems(url)
        let challenge = try XCTUnwrap(query["code_challenge"])
        XCTAssertEqual(query["code_challenge_method"], "S256")
        XCTAssertEqual(query["response_type"], "code")
        XCTAssertEqual(query["response_mode"], "query")
        XCTAssertEqual(query["client_id"], "ios-public-client")
        XCTAssertEqual(query["theme"], "dark")
        XCTAssertEqual(query["prompt"], "login consent")
        XCTAssertEqual(query["max_age"], "0")
        XCTAssertEqual(query["login_hint"], "user@example.test")
        XCTAssertEqual(query["acr_values"], "urn:example:mfa")
        XCTAssertEqual(query["ui_locales"], "en-US zh-CN")
        XCTAssertNil(query["stale"])
        XCTAssertFalse(url.absoluteString.contains("code_verifier"))
        XCTAssertFalse(url.absoluteString.contains("client_secret"))
        XCTAssertEqual(challenge.count, 43)

        let pair = try OAuthProtocol.createPKCE()
        let digest = SHA256.hash(data: Data(pair.verifier.utf8))
        XCTAssertEqual(pair.challenge, base64URL(Data(digest)))
    }

    func testCallbackRejectsStateAndIssuerMismatchBeforeCodeExchange() async throws {
        let setup = try fixture()
        _ = try await setup.client.beginAuthorization()
        let badState = URL(string: "com.example.sverp:/oauth/callback?code=one&state=wrong&iss=https%3A%2F%2Fsso.example.test")!
        do {
            _ = try await setup.client.handleAuthorizationCallback(badState)
            XCTFail("state mismatch must fail")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_request")
        }
        let exchangeCountAfterState = await setup.transport.exchangeCount
        XCTAssertEqual(exchangeCountAfterState, 0)

        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        let badIssuer = URL(string: "com.example.sverp:/oauth/callback?code=one&state=\(state)&iss=https%3A%2F%2Fevil.example.test")!
        do {
            _ = try await setup.client.handleAuthorizationCallback(badIssuer)
            XCTFail("issuer mismatch must fail")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_request")
        }
        let exchangeCountAfterIssuer = await setup.transport.exchangeCount
        XCTAssertEqual(exchangeCountAfterIssuer, 0)

        let finalAuthURL = try await setup.client.beginAuthorization()
        let finalState = try XCTUnwrap(queryItems(finalAuthURL)["state"])
        var wrongRedirect = URLComponents(url: callbackURL(state: finalState, code: "one"), resolvingAgainstBaseURL: false)!
        wrongRedirect.scheme = "com.attacker.app"
        do {
            _ = try await setup.client.handleAuthorizationCallback(wrongRedirect.url!)
            XCTFail("redirect mismatch must fail")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_request")
        }
        let exchangeCountAfterRedirect = await setup.transport.exchangeCount
        XCTAssertEqual(exchangeCountAfterRedirect, 0)
    }

    func testCallbackErrorUsesFormDecodingAndBoundedDiagnostics() async throws {
        let setup = try fixture()
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        let callback = URL(string: "com.example.sverp:/oauth/callback?error=\(String(repeating: "e", count: 80))&error_description=login+cancelled%2Bhere\(String(repeating: "x", count: 600))&state=\(state)&iss=https%3A%2F%2Fsso.example.test")!
        do {
            _ = try await setup.client.handleAuthorizationCallback(callback)
            XCTFail("OAuth error callback must not exchange a code")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code.count, 64)
            XCTAssertEqual(error.message.count, 512)
            XCTAssertTrue(error.message.hasPrefix("login cancelled+here"))
        }
        let exchangeCount = await setup.transport.exchangeCount
        XCTAssertEqual(exchangeCount, 0)
    }

    func testWhitespaceOnlyCallbackErrorAndCodeAreRejected() async throws {
        let blankError = try fixture()
        let errorAuthURL = try await blankError.client.beginAuthorization()
        let errorState = try XCTUnwrap(queryItems(errorAuthURL)["state"])
        let errorCallback = URL(string: "com.example.sverp:/oauth/callback?error=%20%20&state=\(errorState)&iss=https%3A%2F%2Fsso.example.test")!
        do {
            _ = try await blankError.client.handleAuthorizationCallback(errorCallback)
            XCTFail("blank OAuth error without a code must fail closed")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_request")
        }
        let errorExchangeCount = await blankError.transport.exchangeCount
        XCTAssertEqual(errorExchangeCount, 0)

        let blankCode = try fixture()
        let codeAuthURL = try await blankCode.client.beginAuthorization()
        let codeState = try XCTUnwrap(queryItems(codeAuthURL)["state"])
        let codeCallback = URL(string: "com.example.sverp:/oauth/callback?code=%20%20&state=\(codeState)&iss=https%3A%2F%2Fsso.example.test")!
        do {
            _ = try await blankCode.client.handleAuthorizationCallback(codeCallback)
            XCTFail("blank authorization code must not be exchanged")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_request")
        }
        let codeExchangeCount = await blankCode.transport.exchangeCount
        XCTAssertEqual(codeExchangeCount, 0)
    }

    func testCallbackTransactionTTLUsesExactBoundary() async throws {
        let exact = try fixture()
        let exactAuthURL = try await exact.client.beginAuthorization()
        let exactState = try XCTUnwrap(queryItems(exactAuthURL)["state"])
        exact.clock.advance(600)
        let session = try await exact.client.handleAuthorizationCallback(
            callbackURL(state: exactState, code: "auth-code")
        )
        XCTAssertEqual(session.accessToken, "access-initial")

        let expired = try fixture()
        let expiredAuthURL = try await expired.client.beginAuthorization()
        let expiredState = try XCTUnwrap(queryItems(expiredAuthURL)["state"])
        expired.clock.advance(600.001)
        do {
            _ = try await expired.client.handleAuthorizationCallback(
                callbackURL(state: expiredState, code: "auth-code")
            )
            XCTFail("transaction beyond the TTL must be rejected")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_request")
        }
        let exchangeCount = await expired.transport.exchangeCount
        XCTAssertEqual(exchangeCount, 0)
    }

    func testSessionExpiryUsesWholeEpochSeconds() async throws {
        let setup = try fixture()
        setup.clock.advance(0.75)
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        let session = try await setup.client.handleAuthorizationCallback(callbackURL(state: state, code: "auth-code"))
        XCTAssertEqual(session.expiresAt, Date(timeIntervalSince1970: 1_900))
    }

    func testRefreshWithoutScopeRetainsExistingScopeAndRefreshToken() {
        let initial = StoredTokenSet(
            response: OAuthTokenResponse(
                accessToken: "access-old",
                tokenType: "Bearer",
                expiresIn: 900,
                refreshToken: "refresh-old",
                scope: "openid profile"
            ),
            previousRefreshToken: nil,
            previousScope: nil,
            now: Date(timeIntervalSince1970: 1_000)
        )
        let refreshed = StoredTokenSet(
            response: OAuthTokenResponse(
                accessToken: "access-new",
                tokenType: "Bearer",
                expiresIn: 900,
                refreshToken: nil,
                scope: nil
            ),
            previousRefreshToken: initial.refreshToken,
            previousScope: initial.scope,
            now: Date(timeIntervalSince1970: 1_100)
        )
        XCTAssertEqual(refreshed.refreshToken, "refresh-old")
        XCTAssertEqual(refreshed.scope, "openid profile")
    }

    func testWhitespaceOnlyAccessTokenIsRejected() async throws {
        let setup = try fixture()
        await setup.transport.setInitialResponse(OAuthTokenResponse(
            accessToken: " \t\n",
            tokenType: "Bearer",
            expiresIn: 900,
            refreshToken: "refresh-one",
            scope: "openid"
        ))
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        do {
            _ = try await setup.client.handleAuthorizationCallback(callbackURL(state: state, code: "auth-code"))
            XCTFail("whitespace-only access token must be rejected")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_response")
        }
        do {
            _ = try await setup.client.accessToken()
            XCTFail("rejected token response must not create a local session")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "login_required")
        }
    }

    func testCallbackExchangesCodeAndPersistsBearerToken() async throws {
        let setup = try fixture()
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        let callback = callbackURL(state: state, code: "auth-code")
        let session = try await setup.client.handleAuthorizationCallback(callback)
        XCTAssertEqual(session.accessToken, "access-initial")
        let lastCode = await setup.transport.lastCode
        let lastVerifier = await setup.transport.lastVerifier
        XCTAssertEqual(lastCode, "auth-code")
        let storedVerifier = try XCTUnwrap(lastVerifier)
        XCTAssertGreaterThanOrEqual(storedVerifier.count, 43)
        let accessToken = try await setup.client.accessToken()
        XCTAssertEqual(accessToken, "access-initial")
    }

    func testCurrentSessionRestoresPersistedSessionWithoutRefreshing() async throws {
        let setup = try fixture()
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        let original = try await setup.client.handleAuthorizationCallback(callbackURL(state: state, code: "code"))

        let restored = try await setup.client.currentSession()
        let refreshCount = await setup.transport.refreshCount
        XCTAssertEqual(restored, original)
        XCTAssertEqual(refreshCount, 0)
    }

    func testCurrentSessionRefreshesExpiredPersistedSession() async throws {
        let setup = try fixture()
        await setup.transport.setInitialResponse(OAuthTokenResponse(
            accessToken: "access-old",
            tokenType: "Bearer",
            expiresIn: 1,
            refreshToken: "refresh-one",
            scope: "openid"
        ))
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        _ = try await setup.client.handleAuthorizationCallback(callbackURL(state: state, code: "code"))
        setup.clock.advance(2)

        let current = try await setup.client.currentSession()
        let refreshCount = await setup.transport.refreshCount
        XCTAssertEqual(current.accessToken, "access-refreshed")
        XCTAssertEqual(current.expiresAt, setup.clock.now.addingTimeInterval(900))
        XCTAssertEqual(refreshCount, 1)
    }

    func testShortLivedSessionDoesNotRefreshImmediately() async throws {
        let setup = try fixture()
        await setup.transport.setInitialResponse(OAuthTokenResponse(
            accessToken: "access-short-lived",
            tokenType: "Bearer",
            expiresIn: 30,
            refreshToken: "refresh-one",
            scope: "openid"
        ))
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        _ = try await setup.client.handleAuthorizationCallback(callbackURL(state: state, code: "code"))

        let immediateToken = try await setup.client.accessToken()
        let initialRefreshCount = await setup.transport.refreshCount
        XCTAssertEqual(immediateToken, "access-short-lived")
        XCTAssertEqual(initialRefreshCount, 0)

        setup.clock.advance(28)
        let refreshedToken = try await setup.client.accessToken()
        let finalRefreshCount = await setup.transport.refreshCount
        XCTAssertEqual(refreshedToken, "access-refreshed")
        XCTAssertEqual(finalRefreshCount, 1)
    }

    func testLegacyStoredSessionWithoutRefreshAtCanBeRestored() async throws {
        let setup = try fixture()
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        _ = try await setup.client.handleAuthorizationCallback(callbackURL(state: state, code: "code"))
        let stored = try XCTUnwrap(setup.store.onlyStoredValue())
        var payload = try XCTUnwrap(JSONSerialization.jsonObject(with: stored.data) as? [String: Any])
        payload.removeValue(forKey: "refreshAt")
        let legacyPayload = try JSONSerialization.data(withJSONObject: payload)
        setup.store.replace(legacyPayload, account: stored.account)

        let session = try await setup.client.currentSession()
        let refreshCount = await setup.transport.refreshCount
        XCTAssertEqual(session.accessToken, "access-initial")
        XCTAssertEqual(refreshCount, 0)
    }

    func testCurrentSessionRequiresLoginWhenNoSessionIsStored() async throws {
        let setup = try fixture()
        do {
            _ = try await setup.client.currentSession()
            XCTFail("missing session must require login")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "login_required")
        }
    }

    func testConcurrentExpiredTokenCallsShareOneRefresh() async throws {
        let setup = try fixture()
        await setup.transport.setInitialResponse(OAuthTokenResponse(
            accessToken: "access-old",
            tokenType: "Bearer",
            expiresIn: 1,
            refreshToken: "refresh-one",
            scope: "openid"
        ))
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        _ = try await setup.client.handleAuthorizationCallback(callbackURL(state: state, code: "code"))
        setup.clock.advance(2)

        async let first = setup.client.accessToken()
        async let second = setup.client.accessToken()
        let firstToken = try await first
        let secondToken = try await second
        let refreshCount = await setup.transport.refreshCount
        XCTAssertEqual(firstToken, "access-refreshed")
        XCTAssertEqual(secondToken, "access-refreshed")
        XCTAssertEqual(refreshCount, 1)
    }

    func testStartingNewAuthorizationDoesNotInvalidateInflightRefresh() async throws {
        let setup = try fixture()
        await setup.transport.setInitialResponse(OAuthTokenResponse(
            accessToken: "access-old",
            tokenType: "Bearer",
            expiresIn: 1,
            refreshToken: "refresh-one",
            scope: "openid"
        ))
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        _ = try await setup.client.handleAuthorizationCallback(callbackURL(state: state, code: "code"))
        setup.clock.advance(2)
        await setup.transport.pauseNextRefresh()

        let client = setup.client
        let refreshTask = Task { try await client.accessToken() }
        await setup.transport.waitForRefreshStart()
        _ = try await setup.client.beginAuthorization()
        await setup.transport.releaseRefresh()

        let refreshedToken = try await refreshTask.value
        let storedToken = try await setup.client.accessToken()
        XCTAssertEqual(refreshedToken, "access-refreshed")
        XCTAssertEqual(storedToken, "access-refreshed")
    }

    func testClearDropsLocalSessionAndPendingTransactionWithoutRevocation() async throws {
        let setup = try fixture()
        let firstAuthURL = try await setup.client.beginAuthorization()
        let firstState = try XCTUnwrap(queryItems(firstAuthURL)["state"])
        _ = try await setup.client.handleAuthorizationCallback(callbackURL(state: firstState, code: "auth-code"))
        let pendingAuthURL = try await setup.client.beginAuthorization()
        let pendingState = try XCTUnwrap(queryItems(pendingAuthURL)["state"])

        try await setup.client.clear()
        let revokeCount = await setup.transport.revokeCount
        let exchangeCount = await setup.transport.exchangeCount
        XCTAssertEqual(revokeCount, 0)
        XCTAssertEqual(exchangeCount, 1)
        do {
            _ = try await setup.client.accessToken()
            XCTFail("clear must remove the local session")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "login_required")
        }
        do {
            _ = try await setup.client.handleAuthorizationCallback(callbackURL(state: pendingState, code: "second-code"))
            XCTFail("clear must remove the pending transaction")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "invalid_request")
        }
        let finalExchangeCount = await setup.transport.exchangeCount
        XCTAssertEqual(finalExchangeCount, 1)
    }

    func testLogoutClearsLocalTokensWhenRevocationFails() async throws {
        let setup = try fixture()
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        _ = try await setup.client.handleAuthorizationCallback(callbackURL(state: state, code: "code"))
        await setup.transport.setRevocationFailure(true)
        do {
            try await setup.client.logout()
            XCTFail("revocation failure should be reported")
        } catch {
            XCTAssertTrue(error is SnaplinkAuthError)
        }
        do {
            _ = try await setup.client.accessToken()
            XCTFail("logout must clear the local bearer")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "login_required")
        }
    }

    func testFailedKeychainDeleteLeavesClientLoggedOutInMemory() async throws {
        let setup = try fixture()
        let authURL = try await setup.client.beginAuthorization()
        let state = try XCTUnwrap(queryItems(authURL)["state"])
        _ = try await setup.client.handleAuthorizationCallback(callbackURL(state: state, code: "code"))
        setup.store.setFailDelete(true)
        do {
            try await setup.client.logout()
            XCTFail("Keychain deletion failure should be reported")
        } catch {
            XCTAssertTrue(error is SnaplinkAuthError)
        }
        setup.store.setFailDelete(false)
        do {
            _ = try await setup.client.accessToken()
            XCTFail("a failed logout must not reactivate the in-memory session")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "login_required")
        }
    }

    func testOmittedOptionalAuthParametersRemoveStaleLoginPageValues() throws {
        let configuration = try SnaplinkConfiguration(
            issuerBaseURL: URL(string: "https://sso.example.test")!,
            clientID: "ios-public-client",
            redirectURI: URL(string: "com.example.sverp:/oauth/callback")!,
            loginPageURL: URL(string: "https://login.example.test/login/?prompt=old&max_age=99&login_hint=old&acr_values=old&ui_locales=old")!
        )
        let url = try OAuthProtocol.buildAuthorizationURL(
            configuration: configuration,
            state: "state",
            challenge: "challenge"
        )
        let query = try queryItems(url)
        XCTAssertNil(query["prompt"])
        XCTAssertNil(query["max_age"])
        XCTAssertNil(query["login_hint"])
        XCTAssertNil(query["acr_values"])
        XCTAssertNil(query["ui_locales"])
    }

    func testConfigurationRejectsUntrustedEndpointsAndCallbackQueries() throws {
        XCTAssertThrowsError(try SnaplinkConfiguration(
            issuerBaseURL: URL(string: "http://sso.example.test")!,
            clientID: "ios-public-client",
            redirectURI: URL(string: "com.example.sverp:/oauth/callback")!
        ))
        XCTAssertThrowsError(try SnaplinkConfiguration(
            issuerBaseURL: URL(string: "https://sso.example.test")!,
            clientID: "ios-public-client",
            redirectURI: URL(string: "https://app.example.test/callback?state=attacker")!
        ))
        XCTAssertThrowsError(try SnaplinkConfiguration(
            issuerBaseURL: URL(string: "https://sso.example.test")!,
            clientID: "ios-public-client",
            redirectURI: URL(string: "com.example.sverp:/oauth/callback")!,
            maxAge: -1
        ))
    }

    private func fixture() throws -> Fixture {
        let configuration = try SnaplinkConfiguration(
            issuerBaseURL: URL(string: "https://sso.example.test")!,
            clientID: "ios-public-client",
            redirectURI: URL(string: "com.example.sverp:/oauth/callback")!,
            loginPageURL: URL(string: "https://login.example.test/login/?theme=dark&code_challenge=stale&prompt=old&max_age=99&login_hint=old&acr_values=old&ui_locales=old")!,
            resources: ["https://api.example.test"],
            prompt: "login consent",
            loginHint: "user@example.test",
            acrValues: "urn:example:mfa",
            uiLocales: "en-US zh-CN",
            maxAge: 0
        )
        let store = MemorySecureStore()
        let transport = FakeOAuthTransport()
        let clock = TestClock()
        let client = SnaplinkAuthClient(
            configuration: configuration,
            secureStore: store,
            transport: transport,
            clock: { clock.now }
        )
        return Fixture(client: client, transport: transport, clock: clock, store: store)
    }

    private func queryItems(_ url: URL) throws -> [String: String] {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        var values: [String: String] = [:]
        for item in items { values[item.name] = item.value }
        return values
    }

    private func callbackURL(state: String, code: String) -> URL {
        var components = URLComponents(string: "com.example.sverp:/oauth/callback")!
        components.queryItems = [
            URLQueryItem(name: "code", value: code),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "iss", value: "https://sso.example.test")
        ]
        return components.url!
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private struct Fixture {
        let client: SnaplinkAuthClient
        let transport: FakeOAuthTransport
        let clock: TestClock
        let store: MemorySecureStore
    }
}

private final class MemorySecureStore: SnaplinkSecureStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]
    private var failDelete = false

    func onlyStoredValue() -> (account: String, data: Data)? {
        lock.lock()
        defer { lock.unlock() }
        guard values.count == 1, let value = values.first else { return nil }
        return (account: value.key, data: value.value)
    }

    func replace(_ data: Data, account: String) {
        lock.lock()
        defer { lock.unlock() }
        values[account] = data
    }

    func setFailDelete(_ fail: Bool) {
        lock.lock()
        defer { lock.unlock() }
        failDelete = fail
    }

    func read(account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return values[account]
    }

    func write(_ data: Data, account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values[account] = data
    }

    func delete(account: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if failDelete { throw SnaplinkAuthError(code: "secure_storage_error", message: "delete failed") }
        values.removeValue(forKey: account)
    }
}

private actor FakeOAuthTransport: OAuthTransport {
    private var initialResponse = OAuthTokenResponse(
        accessToken: "access-initial",
        tokenType: "Bearer",
        expiresIn: 900,
        refreshToken: "refresh-one",
        scope: "openid"
    )
    private var shouldFailRevocation = false
    private var pauseRefreshOnNextCall = false
    private var refreshGate: CheckedContinuation<Void, Never>?
    private var refreshStartWaiter: CheckedContinuation<Void, Never>?
    private(set) var exchangeCount = 0
    private(set) var refreshCount = 0
    private(set) var revokeCount = 0
    private(set) var lastCode: String?
    private(set) var lastVerifier: String?

    func setInitialResponse(_ response: OAuthTokenResponse) { initialResponse = response }
    func setRevocationFailure(_ fail: Bool) { shouldFailRevocation = fail }
    func pauseNextRefresh() { pauseRefreshOnNextCall = true }
    func waitForRefreshStart() async {
        if refreshCount > 0 { return }
        await withCheckedContinuation { refreshStartWaiter = $0 }
    }
    func releaseRefresh() {
        refreshGate?.resume()
        refreshGate = nil
    }

    func exchangeCode(_ code: String, verifier: String) async throws -> OAuthTokenResponse {
        exchangeCount += 1
        lastCode = code
        lastVerifier = verifier
        return initialResponse
    }

    func refresh(_ refreshToken: String) async throws -> OAuthTokenResponse {
        refreshCount += 1
        refreshStartWaiter?.resume()
        refreshStartWaiter = nil
        if pauseRefreshOnNextCall {
            pauseRefreshOnNextCall = false
            await withCheckedContinuation { refreshGate = $0 }
        } else {
            try await Task.sleep(for: .milliseconds(40))
        }
        XCTAssertEqual(refreshToken, "refresh-one")
        return OAuthTokenResponse(
            accessToken: "access-refreshed",
            tokenType: "Bearer",
            expiresIn: 900,
            refreshToken: "refresh-two",
            scope: "openid"
        )
    }

    func revoke(_ token: String, tokenTypeHint: String) async throws {
        revokeCount += 1
        XCTAssertEqual(token, "refresh-one")
        XCTAssertEqual(tokenTypeHint, "refresh_token")
        if shouldFailRevocation {
            throw SnaplinkAuthError(code: "network_error", message: "unavailable")
        }
    }
}

private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Date(timeIntervalSince1970: 1_000)

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func advance(_ seconds: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        value = value.addingTimeInterval(seconds)
    }
}
