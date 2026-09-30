import AuthenticationServices
import Foundation

@MainActor
protocol BrowserAuthorizationSession: AnyObject {
    func start() -> Bool
    func cancel()
}

@MainActor
protocol BrowserAuthorizationSessionFactory {
    func makeSession(
        url: URL,
        redirectURI: URL,
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding,
        prefersEphemeralSession: Bool,
        completion: @escaping (URL?, Error?) -> Void
    ) throws -> any BrowserAuthorizationSession
}

extension ASWebAuthenticationSession: BrowserAuthorizationSession {}

/// Uses the operating system's browser authentication session (never a WebView).
@MainActor
public final class SnaplinkSystemBrowser {
    private var session: (any BrowserAuthorizationSession)?
    private var sessionID: UUID?
    private let sessionFactory: any BrowserAuthorizationSessionFactory

    public init() {
        self.sessionFactory = SystemBrowserSessionFactory()
    }

    init(sessionFactory: any BrowserAuthorizationSessionFactory) {
        self.sessionFactory = sessionFactory
    }

    public func authorize(
        url: URL,
        redirectURI: URL,
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding,
        prefersEphemeralSession: Bool = false
    ) async throws -> URL {
        guard session == nil else {
            throw SnaplinkAuthError(code: "operation_in_progress", message: "browser authorization is already in progress")
        }
        guard redirectURI.scheme != nil else {
            throw SnaplinkAuthError(code: "invalid_request", message: "redirectURI has no scheme")
        }
        let authorizationID = UUID()
        let cancellation = BrowserAuthorizationCancellation()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await performAuthorization(
                url: url,
                redirectURI: redirectURI,
                authorizationID: authorizationID,
                cancellation: cancellation,
                presentationContextProvider: presentationContextProvider,
                prefersEphemeralSession: prefersEphemeralSession
            )
        } onCancel: { [weak self] in
            cancellation.cancel()
            Task { @MainActor in self?.cancelAuthorization(id: authorizationID) }
        }
    }

    private func performAuthorization(
        url: URL,
        redirectURI: URL,
        authorizationID: UUID,
        cancellation: BrowserAuthorizationCancellation,
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding,
        prefersEphemeralSession: Bool
    ) async throws -> URL {
        defer {
            if sessionID == authorizationID {
                session = nil
                sessionID = nil
            }
        }
        return try await withCheckedThrowingContinuation { continuation in
            guard !cancellation.isCancelled else {
                continuation.resume(throwing: CancellationError())
                return
            }
            let completion: (URL?, Error?) -> Void = { callbackURL, error in
                if cancellation.isCancelled {
                    continuation.resume(throwing: CancellationError())
                } else if let callbackURL {
                    continuation.resume(returning: callbackURL)
                } else if let error {
                    continuation.resume(throwing: SnaplinkAuthError(
                        code: "authorization_cancelled",
                        message: error.localizedDescription
                    ))
                } else {
                    continuation.resume(throwing: SnaplinkAuthError(
                        code: "invalid_response",
                        message: "system browser returned no authorization callback"
                    ))
                }
            }
            do {
                let authSession = try sessionFactory.makeSession(
                    url: url,
                    redirectURI: redirectURI,
                    presentationContextProvider: presentationContextProvider,
                    prefersEphemeralSession: prefersEphemeralSession,
                    completion: completion
                )
                session = authSession
                sessionID = authorizationID
                if !authSession.start() {
                    session = nil
                    sessionID = nil
                    continuation.resume(throwing: cancellation.isCancelled ? CancellationError() : SnaplinkAuthError(
                        code: "browser_unavailable",
                        message: "system browser authorization could not be started"
                    ))
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    /// Cancels the active system-browser flow, if any.
    public func cancelAuthorization() {
        session?.cancel()
    }

    private func cancelAuthorization(id: UUID) {
        guard sessionID == id else { return }
        session?.cancel()
    }
}

@MainActor
private struct SystemBrowserSessionFactory: BrowserAuthorizationSessionFactory {
    func makeSession(
        url: URL,
        redirectURI: URL,
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding,
        prefersEphemeralSession: Bool,
        completion: @escaping (URL?, Error?) -> Void
    ) throws -> any BrowserAuthorizationSession {
        guard let scheme = redirectURI.scheme else {
            throw SnaplinkAuthError(code: "invalid_request", message: "redirectURI has no scheme")
        }
        let authSession: ASWebAuthenticationSession
        if scheme.lowercased() == "https" {
            guard let host = redirectURI.host else {
                throw SnaplinkAuthError(code: "invalid_request", message: "HTTPS redirectURI has no host")
            }
            guard #available(iOS 17.4, macOS 14.4, *) else {
                throw SnaplinkAuthError(
                    code: "unsupported_platform",
                    message: "HTTPS callbacks require iOS 17.4 or macOS 14.4; use a registered custom URI scheme on older systems"
                )
            }
            let callback = ASWebAuthenticationSession.Callback.https(host: host, path: redirectURI.path)
            authSession = ASWebAuthenticationSession(url: url, callback: callback, completionHandler: completion)
        } else {
            authSession = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: completion)
        }
        authSession.presentationContextProvider = presentationContextProvider
        authSession.prefersEphemeralWebBrowserSession = prefersEphemeralSession
        return authSession
    }
}

private final class BrowserAuthorizationCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        defer { lock.unlock() }
        cancelled = true
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}
