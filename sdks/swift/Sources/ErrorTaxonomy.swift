import Foundation

/// The class of an error code, from the shared taxonomy in
/// `ops/build/sdk-conformance/errors.json`.
///
/// The class is what a caller branches on for behaviour; the code is what it
/// logs. A server code is carried verbatim, so an SDK never invents a local
/// variant for one.
public enum SnaplinkErrorClass: String, CaseIterable, Sendable {
    case oauth
    case activation
    case authorization
    case authentication
    case commerce
    case license
    /// A code this SDK originated, never one the server sent.
    case sdk
}

/// What a caller should do about a code.
public enum SnaplinkErrorRecovery: String, CaseIterable, Sendable {
    /// Terminal for this operation; do not retry.
    case terminal
    /// Transient server-side failure; bounded retry with backoff.
    case retryWithBackoff
    /// The grant or token is gone; authenticate again.
    case reauthenticate
    /// The ceremony must be re-run (for example a new WebAuthn or MFA step).
    case recreateCeremony
    /// The request will never be issuable as written.
    case fixRequest
}

/// The controlled code vocabulary and its classification.
///
/// A code the server sends that is not in this table is still surfaced verbatim
/// through ``SnaplinkErrorClassification/code``; it simply carries no class, so
/// a caller cannot mistake an unknown code for a known one.
public enum SnaplinkErrorCatalog {
    public struct Entry: Sendable, Hashable {
        public let code: String
        public let errorClass: SnaplinkErrorClass
        public let recovery: SnaplinkErrorRecovery
    }

    /// The controlled vocabulary sourced from `docs/error-codes.md` plus the
    /// SDK-originated license class. Adding a case here is a contract change.
    public static let entries: [String: Entry] = {
        var table: [String: Entry] = [:]
        func add(_ code: String, _ errorClass: SnaplinkErrorClass, _ recovery: SnaplinkErrorRecovery) {
            table[code] = Entry(code: code, errorClass: errorClass, recovery: recovery)
        }
        // Oracle-safe collapsing is preserved end to end: each wire code appears
        // once, with no per-cause variant.
        add("activation_invalid", .activation, .terminal)
        add("activation_not_found", .activation, .fixRequest)
        add("activation_unavailable", .activation, .retryWithBackoff)
        add("invalid_grant", .oauth, .reauthenticate)
        add("invalid_client", .oauth, .terminal)
        add("invalid_scope", .oauth, .fixRequest)
        add("insufficient_scope", .authorization, .fixRequest)
        add("invalid_token", .authentication, .reauthenticate)
        add("session_invalid", .authentication, .recreateCeremony)
        add("mfa_invalid", .authentication, .recreateCeremony)
        add("commerce_entitlement_not_found", .commerce, .fixRequest)
        add("commerce_tenant_subscribed", .commerce, .fixRequest)
        for code in SnaplinkLicenseErrorCode.allCases {
            add(code.rawValue, .license, .terminal)
        }
        return table
    }()

    /// The entry for a code, or nil when the server sent one this build does not
    /// recognise.
    public static func entry(for code: String) -> Entry? { entries[code] }
}

/// A code, its class, and the recovery a caller should take.
///
/// ``code`` is always the verbatim value: the server's code for a protocol
/// failure, or the SDK's own namespaced code otherwise. Nothing is remapped.
public struct SnaplinkErrorClassification: Sendable, Hashable {
    public let code: String
    public let status: Int?
    public let errorClass: SnaplinkErrorClass
    public let recovery: SnaplinkErrorRecovery

    public init(code: String, status: Int?, errorClass: SnaplinkErrorClass, recovery: SnaplinkErrorRecovery) {
        self.code = code
        self.status = status
        self.errorClass = errorClass
        self.recovery = recovery
    }

    /// Classifies a code carried by an error, preferring the server's status.
    ///
    /// An unrecognised code stays verbatim and is reported as SDK-originated
    /// rather than being forced into a known class.
    public init(code: String, status: Int?) {
        if let entry = SnaplinkErrorCatalog.entry(for: code) {
            self.init(
                code: code,
                status: status,
                errorClass: entry.errorClass,
                recovery: entry.recovery
            )
        } else {
            self.init(
                code: code,
                status: status,
                errorClass: .sdk,
                recovery: .terminal
            )
        }
    }
}

/// One shape a caller can catch for every SDK failure, so auth, commerce, and
/// license errors are handled through a single `catch`.
///
/// The verbatim code is read from ``classification/code`` rather than required
/// as a `String`, so each error type keeps its own strongly typed code while a
/// caller still has one uniform surface to branch on.
public protocol SnaplinkClassifiedError: Error {
    /// Human-facing detail. Never parsed for behaviour.
    var message: String { get }
    /// The HTTP status when the failure came from the server; nil for a failure
    /// this SDK originated.
    var status: Int? { get }
    var classification: SnaplinkErrorClassification { get }
}
