import AuthenticationServices
import Foundation
import XCTest
@testable import SnaplinkSSO
#if os(macOS)
import AppKit
#elseif os(iOS)
import UIKit
#endif

@MainActor
final class SystemBrowserAuthorizerTests: XCTestCase {
    func testTaskCancellationCancelsThePendingBrowserSession() async {
        let (browser, session) = makeBrowser()
        let task = Task { @MainActor in try await authorize(browser) }
        await session.waitUntilStarted()

        task.cancel()

        do {
            _ = try await task.value
            XCTFail("cancelled authorization task must throw")
        } catch is CancellationError {
            XCTAssertEqual(session.cancelCount, 1)
        } catch {
            XCTFail("expected CancellationError, got \(error)")
        }
    }

    func testManualCancellationReturnsAuthorizationCancelled() async {
        let (browser, session) = makeBrowser()
        let task = Task { @MainActor in try await authorize(browser) }
        await session.waitUntilStarted()

        browser.cancelAuthorization()

        do {
            _ = try await task.value
            XCTFail("manual browser cancellation must fail the authorization")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "authorization_cancelled")
            XCTAssertEqual(session.cancelCount, 1)
        } catch {
            XCTFail("expected SnaplinkAuthError, got \(error)")
        }
    }

    func testBrowserRejectsOverlappingAuthorization() async {
        let (browser, session) = makeBrowser()
        let task = Task { @MainActor in try await authorize(browser) }
        await session.waitUntilStarted()

        do {
            _ = try await authorize(browser)
            XCTFail("one browser instance must not run overlapping authorization flows")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "operation_in_progress")
        } catch {
            XCTFail("expected SnaplinkAuthError, got \(error)")
        }

        browser.cancelAuthorization()
        do {
            _ = try await task.value
            XCTFail("the pending authorization should have been cancelled")
        } catch let error as SnaplinkAuthError {
            XCTAssertEqual(error.code, "authorization_cancelled")
        } catch {
            XCTFail("expected SnaplinkAuthError, got \(error)")
        }
    }

    private func makeBrowser() -> (SnaplinkSystemBrowser, FakeBrowserAuthorizationSession) {
        let session = FakeBrowserAuthorizationSession()
        let factory = FakeBrowserAuthorizationSessionFactory(session: session)
        return (SnaplinkSystemBrowser(sessionFactory: factory), session)
    }

    private func authorize(_ browser: SnaplinkSystemBrowser) async throws -> URL {
        try await browser.authorize(
            url: URL(string: "https://login.example.test/login/")!,
            redirectURI: URL(string: "com.example.app:/oauth/callback")!,
            presentationContextProvider: FakePresentationContextProvider()
        )
    }
}

@MainActor
private final class FakeBrowserAuthorizationSession: BrowserAuthorizationSession {
    private var completion: ((URL?, Error?) -> Void)?
    private var startedContinuation: CheckedContinuation<Void, Never>?
    private(set) var started = false
    private(set) var cancelCount = 0

    func setCompletion(_ completion: @escaping (URL?, Error?) -> Void) {
        self.completion = completion
    }

    func start() -> Bool {
        started = true
        startedContinuation?.resume()
        startedContinuation = nil
        return true
    }

    func cancel() {
        cancelCount += 1
        completion?(nil, URLError(.cancelled))
    }

    func waitUntilStarted() async {
        guard !started else { return }
        await withCheckedContinuation { startedContinuation = $0 }
    }
}

@MainActor
private struct FakeBrowserAuthorizationSessionFactory: BrowserAuthorizationSessionFactory {
    let session: FakeBrowserAuthorizationSession

    func makeSession(
        url: URL,
        redirectURI: URL,
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding,
        prefersEphemeralSession: Bool,
        completion: @escaping (URL?, Error?) -> Void
    ) throws -> any BrowserAuthorizationSession {
        session.setCompletion(completion)
        return session
    }
}

@MainActor
private final class FakePresentationContextProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if os(macOS)
        return NSWindow()
        #elseif os(iOS)
        return UIWindow()
        #else
        fatalError("unsupported test platform")
        #endif
    }
}
