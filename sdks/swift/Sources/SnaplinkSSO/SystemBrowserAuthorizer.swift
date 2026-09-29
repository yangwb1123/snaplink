import AuthenticationServices
import Foundation

/// Uses the operating system's browser authentication session (never a WebView).
@MainActor
public final class SnaplinkSystemBrowser {
    private var session: ASWebAuthenticationSession?

    public init() {}

    public func authorize(
        url: URL,
        redirectURI: URL,
        presentationContextProvider: ASWebAuthenticationPresentationContextProviding,
        prefersEphemeralSession: Bool = false
    ) async throws -> URL {
        guard let scheme = redirectURI.scheme else {
            throw SnaplinkAuthError(code: "invalid_request", message: "redirectURI has no scheme")
        }
        return try await withCheckedThrowingContinuation { continuation in
            let completion: (URL?, Error?) -> Void = { [weak self] callbackURL, error in
                Task { @MainActor in self?.session = nil }
                if let callbackURL {
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
            let authSession: ASWebAuthenticationSession
            if scheme.lowercased() == "https" {
                guard let host = redirectURI.host else {
                    continuation.resume(throwing: SnaplinkAuthError(
                        code: "invalid_request",
                        message: "HTTPS redirectURI has no host"
                    ))
                    return
                }
                let callback = ASWebAuthenticationSession.Callback.https(host: host, path: redirectURI.path)
                authSession = ASWebAuthenticationSession(url: url, callback: callback, completionHandler: completion)
            } else {
                authSession = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: completion)
            }
            authSession.presentationContextProvider = presentationContextProvider
            authSession.prefersEphemeralWebBrowserSession = prefersEphemeralSession
            session = authSession
            if !authSession.start() {
                session = nil
                continuation.resume(throwing: SnaplinkAuthError(
                    code: "browser_unavailable",
                    message: "system browser authorization could not be started"
                ))
            }
        }
    }
}
