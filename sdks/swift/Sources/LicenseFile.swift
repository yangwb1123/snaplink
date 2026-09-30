import CryptoKit
import Foundation

/// The only algorithm and envelope version this build accepts.
public enum SnaplinkLicenseEnvelope {
    public static let algorithm = "Ed25519"
    public static let version = 1
}

/// A stable code for an entitlement-file failure.
///
/// These originate in the SDK, never on the wire, and are namespaced so a
/// caller cannot confuse them with a network failure. None is recoverable by
/// retrying.
public enum SnaplinkLicenseErrorCode: String, CaseIterable, Sendable {
    case malformed = "license_malformed"
    case algorithmUnsupported = "license_algorithm_unsupported"
    case signatureInvalid = "license_signature_invalid"
    case untrustedKey = "license_untrusted_key"
    case trustUnconfigured = "license_trust_unconfigured"
}

/// An entitlement-file verification failure.
public struct SnaplinkLicenseError: Error, Sendable, Equatable, LocalizedError, SnaplinkClassifiedError {
    public let code: SnaplinkLicenseErrorCode
    public let message: String

    public init(code: SnaplinkLicenseErrorCode, message: String) {
        self.code = code
        self.message = message
    }

    public var errorDescription: String? { message }

    /// Always nil: a local verification failure has no HTTP status and must
    /// never be remapped onto a network error.
    public var status: Int? { nil }

    public var classification: SnaplinkErrorClassification {
        SnaplinkErrorClassification(code: code.rawValue, status: nil)
    }
}

/// A set of public keys an entitlement file may be signed by.
///
/// A file names the `key_id` it was signed with, so a deployment can hold a
/// current and a next key during rotation without weakening verification.
///
/// A trust root is always supplied by the caller, which is what makes OEM and
/// private-CA deployments possible.
public struct SnaplinkLicenseTrust: Sendable {
    private var keys: [String: Data]

    /// An empty trust root. Every file is rejected until a key is added.
    public init() {
        keys = [:]
    }

    /// Trusts a raw 32-byte Ed25519 public key.
    ///
    /// A key of the wrong size is rejected rather than stored, so a typo cannot
    /// silently widen or narrow trust.
    public mutating func addKey(id: String, publicKey: Data) throws {
        guard !id.isEmpty else {
            throw SnaplinkLicenseError(code: .malformed, message: "a trusted key needs an id")
        }
        guard publicKey.count == Self.publicKeyBytes else {
            throw SnaplinkLicenseError(
                code: .malformed,
                message: "key \(id) is not \(Self.publicKeyBytes) bytes"
            )
        }
        keys[id] = publicKey
    }

    /// Trusts a base64 standard-encoded Ed25519 public key.
    public mutating func addBase64Key(id: String, encoded: String) throws {
        guard let raw = Data(base64Encoded: encoded) else {
            throw SnaplinkLicenseError(code: .malformed, message: "key \(id) is not base64")
        }
        try addKey(id: id, publicKey: raw)
    }

    /// A trust root for a single trusted key.
    public static func fromKey(id: String, base64Encoded: String) throws -> SnaplinkLicenseTrust {
        var trust = SnaplinkLicenseTrust()
        try trust.addBase64Key(id: id, encoded: base64Encoded)
        return trust
    }

    /// Whether any key is trusted.
    public var isEmpty: Bool { keys.isEmpty }

    /// The trusted key identifiers, sorted, for diagnostics.
    public var keyIDs: [String] { keys.keys.sorted() }

    fileprivate func key(for id: String) -> Data? { keys[id] }

    private static let publicKeyBytes = 32
}

/// A verified commercial entitlement read from a local file.
public struct SnaplinkLicenseFile: Sendable, Equatable {
    public let entitlement: SnaplinkEntitlement
    public let keyID: String

    public init(entitlement: SnaplinkEntitlement, keyID: String) {
        self.entitlement = entitlement
        self.keyID = keyID
    }

    /// Classifies the file's entitlement at `now`.
    ///
    /// The three-state classification is identical to the online path, so a
    /// deployment moving between the two does not change behaviour.
    public func state(at now: Date) -> SnaplinkLicenseState {
        entitlement.state(at: now)
    }
}

/// Verifies a signed entitlement file entirely locally.
///
/// `docs/commercial-model.md` requires that offline and private deployments gate
/// paid features from a signed file and that authentication never calls a vendor
/// licensing service on a login path. That second clause is only satisfiable
/// because this function performs no network I/O on any path, including login.
///
/// The declared algorithm and version are checked before any signature work, so
/// `none` and friends are refused rather than tolerated. Any failure throws:
/// this never returns an inactive or free-tier entitlement in place of a
/// rejected file.
public enum SnaplinkLicenseFileVerifier {
    public static func verify(_ raw: Data, trust: SnaplinkLicenseTrust?) throws -> SnaplinkLicenseFile {
        guard let trust, !trust.isEmpty else {
            throw SnaplinkLicenseError(code: .trustUnconfigured, message: "no trust root was supplied")
        }
        let envelope = try parse(raw)
        guard let key = trust.key(for: envelope.keyID) else {
            throw SnaplinkLicenseError(
                code: .untrustedKey,
                message: "no trusted key is configured for \(envelope.keyID)"
            )
        }
        guard let payload = Data(base64Encoded: envelope.payload) else {
            throw SnaplinkLicenseError(code: .malformed, message: "the payload is not base64")
        }
        guard let signature = Data(base64Encoded: envelope.signature) else {
            throw SnaplinkLicenseError(code: .malformed, message: "the signature is not base64")
        }
        guard signature.count == Self.signatureBytes else {
            throw SnaplinkLicenseError(
                code: .malformed,
                message: "the signature is not \(Self.signatureBytes) bytes"
            )
        }
        // Algorithm-gated: the allowlist is enforced above, so this is the only
        // primitive a conforming verifier needs.
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: key)
        guard publicKey.isValidSignature(signature, for: payload) else {
            throw SnaplinkLicenseError(code: .signatureInvalid, message: "the signature did not verify")
        }
        let entitlement: SnaplinkEntitlement
        do {
            entitlement = try JSONDecoder().decode(SnaplinkEntitlement.self, from: payload)
        } catch {
            throw SnaplinkLicenseError(
                code: .malformed,
                message: "the payload is not an entitlement"
            )
        }
        return SnaplinkLicenseFile(entitlement: entitlement, keyID: envelope.keyID)
    }

    private struct Envelope: Decodable {
        let version: Int
        let algorithm: String
        let keyID: String
        let payload: String
        let signature: String

        enum CodingKeys: String, CodingKey {
            case version
            case algorithm
            case keyID = "key_id"
            case payload
            case signature
        }
    }

    /// Decodes the envelope and applies the version and algorithm gate.
    ///
    /// A structurally incomplete envelope is malformed rather than silently
    /// reading as version 0 with an empty algorithm: every SDK reports a
    /// missing field the same way, and the shared fixture holds them to one
    /// answer.
    private static func parse(_ raw: Data) throws -> Envelope {
        let envelope: Envelope
        do {
            envelope = try JSONDecoder().decode(Envelope.self, from: raw)
        } catch {
            throw SnaplinkLicenseError(code: .malformed, message: "the license file is not a readable envelope")
        }
        guard envelope.version == SnaplinkLicenseEnvelope.version else {
            throw SnaplinkLicenseError(
                code: .algorithmUnsupported,
                message: "envelope version \(envelope.version) is not supported"
            )
        }
        guard envelope.algorithm == SnaplinkLicenseEnvelope.algorithm else {
            throw SnaplinkLicenseError(
                code: .algorithmUnsupported,
                message: "algorithm \(envelope.algorithm) is not supported"
            )
        }
        return envelope
    }

    private static let signatureBytes = 64
}
