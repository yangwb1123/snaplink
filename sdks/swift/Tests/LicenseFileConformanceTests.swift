import CryptoKit
import Foundation
import XCTest
@testable import SnaplinkSSO

/// Cross-language conformance for entitlement-file verification.
///
/// The cases in `ops/build/sdk-conformance/license_file.json` are the shared
/// contract, pinned identically by the Go, Python, TypeScript, PHP, and Rust
/// SDKs. The signing key below is a test fixture generated for this suite and is
/// deliberately not a vendor key: the point of these tests is the verification
/// outcome, not the provenance of the trust root.
final class LicenseFileConformanceTests: XCTestCase {
    private let referenceNow = Date(timeIntervalSince1970: 1_700_000_000)
    private let vendorKeyID = "vendor-2026"
    private let untrustedKeyID = "untrusted-2026"

    func testValidSignatureVerifiesOfflineAndGrantsTheEntitlement() throws {
        let file = try verify(makeFile())
        XCTAssertEqual(file.keyID, vendorKeyID)
        XCTAssertTrue(file.entitlement.has(.scim, at: referenceNow))
        XCTAssertTrue(file.state(at: referenceNow).isActive)
    }

    func testTamperedPayloadDoesNotVerify() throws {
        // Flip one byte of the signed payload: the shape still parses as an
        // entitlement, so only a real signature check can catch it.
        let original = payload()
        var tampered = original
        tampered[tampered.startIndex] ^= 0x01
        XCTAssertNotEqual(tampered, original)

        var fields = try decodeEnvelope(makeFile())
        fields["payload"] = .string(tampered.base64EncodedString())
        let error = assertLicenseError {
            _ = try SnaplinkLicenseFileVerifier.verify(
                try encodeEnvelope(fields),
                trust: try trust()
            )
        }
        XCTAssertEqual(error.code, .signatureInvalid)
    }

    func testSignatureFromAnUntrustedKeyDoesNotVerify() throws {
        let fields = try decodeEnvelope(makeFile(signer: .untrusted))
        let error = assertLicenseError {
            _ = try SnaplinkLicenseFileVerifier.verify(try encodeEnvelope(fields), trust: try trust())
        }
        XCTAssertEqual(error.code, .signatureInvalid)
    }

    func testCallerPinnedKeyIsAccepted() throws {
        let file = try verify(
            makeFile(signer: .untrusted, keyID: untrustedKeyID),
            trustedKeys: [untrustedKeyID: fixtureKey(for: .untrusted)]
        )
        XCTAssertEqual(file.keyID, untrustedKeyID)
        XCTAssertTrue(file.state(at: referenceNow).isActive)
    }

    func testExpiredEntitlementIsInactiveRatherThanAnError() throws {
        let file = try verify(makeFile())
        let afterExpiry = Date(timeIntervalSince1970: 1_700_000_000 + 40 * 24 * 3600)
        let state = file.state(at: afterExpiry)
        XCTAssertEqual(state.kind, .inactive)
        XCTAssertEqual(state.reason, .expired)
        XCTAssertFalse(file.entitlement.has(.scim, at: afterExpiry))
    }

    func testMalformedEnvelopeIsAnErrorNotAnEmptyEntitlement() throws {
        let error = assertLicenseError {
            _ = try SnaplinkLicenseFileVerifier.verify(Data("not json at all".utf8), trust: try trust())
        }
        XCTAssertEqual(error.code, .malformed)
    }

    func testMissingEnvelopeFieldIsMalformed() throws {
        var fields = try decodeEnvelope(makeFile())
        fields["key_id"] = nil
        let error = assertLicenseError {
            _ = try SnaplinkLicenseFileVerifier.verify(try encodeEnvelope(fields), trust: try trust())
        }
        XCTAssertEqual(error.code, .malformed)
    }

    func testUnsupportedAlgorithmIsRefusedBeforeSignatureWork() throws {
        var fields = try decodeEnvelope(makeFile())
        fields["algorithm"] = .string("none")
        let error = assertLicenseError {
            _ = try SnaplinkLicenseFileVerifier.verify(try encodeEnvelope(fields), trust: try trust())
        }
        XCTAssertEqual(error.code, .algorithmUnsupported)
    }

    func testUnsupportedEnvelopeVersionIsRefused() throws {
        var fields = try decodeEnvelope(makeFile())
        fields["version"] = .integer(2)
        let error = assertLicenseError {
            _ = try SnaplinkLicenseFileVerifier.verify(try encodeEnvelope(fields), trust: try trust())
        }
        XCTAssertEqual(error.code, .algorithmUnsupported)
    }

    func testUnknownKeyIDIsUntrusted() throws {
        let error = assertLicenseError {
            _ = try SnaplinkLicenseFileVerifier.verify(
                makeFile(keyID: "rotated-away"),
                trust: try trust()
            )
        }
        XCTAssertEqual(error.code, .untrustedKey)
    }

    func testEmptyTrustRootRefusesEveryFile() throws {
        for trust in [nil, SnaplinkLicenseTrust()] {
            let error = assertLicenseError {
                _ = try SnaplinkLicenseFileVerifier.verify(makeFile(), trust: trust)
            }
            XCTAssertEqual(error.code, .trustUnconfigured)
        }
    }

    func testMalformedKeyMaterialIsRejectedAtTrustConstruction() {
        XCTAssertThrowsError(try SnaplinkLicenseTrust.fromKey(id: "k", base64Encoded: "not base64!"))
        XCTAssertThrowsError(try SnaplinkLicenseTrust.fromKey(id: "k", base64Encoded: "c2hvcnQ="))
        var trust = SnaplinkLicenseTrust()
        XCTAssertThrowsError(try trust.addKey(id: "", publicKey: Data(repeating: 1, count: 32)))
    }

    func testTrustRootReportsItsKeyIdentifiers() throws {
        var trust = SnaplinkLicenseTrust()
        XCTAssertTrue(trust.isEmpty)
        try trust.addBase64Key(id: "b", encoded: fixtureKey(for: .vendor).base64EncodedString())
        try trust.addBase64Key(id: "a", encoded: fixtureKey(for: .untrusted).base64EncodedString())
        XCTAssertEqual(trust.keyIDs, ["a", "b"])
        XCTAssertFalse(trust.isEmpty)
    }

    func testFixtureCaseIdentifiersAreAllImplementedHere() throws {
        let fixture = try loadSharedFixture()
        let implemented: Set<String> = [
            "valid_signature",
            "tampered_payload",
            "signature_from_wrong_key",
            "caller_pinned_key",
            "expired_entitlement",
            "malformed_envelope",
            "unsupported_algorithm"
        ]
        for id in implemented {
            XCTAssert(fixture.contains(id), "fixture case \(id) disappeared")
        }
    }

    // MARK: - Fixture plumbing

    private enum Signer {
        case vendor
        case untrusted
    }

    private func fixtureKey(for signer: Signer) -> Data {
        Data(base64Encoded: signer == .vendor ? Self.vendorKeyBase64 : Self.untrustedKeyBase64)!
    }

    private func fixtureSigningKey(for signer: Signer) -> Data {
        Data(base64Encoded: signer == .vendor ? Self.vendorSigningKeyBase64 : Self.untrustedSigningKeyBase64)!
    }

    private func trust() throws -> SnaplinkLicenseTrust {
        try trustKeys([vendorKeyID: fixtureKey(for: .vendor)])
    }

    private func trustKeys(_ keys: [String: Data]) throws -> SnaplinkLicenseTrust {
        var trust = SnaplinkLicenseTrust()
        for (id, key) in keys.sorted(by: { $0.key < $1.key }) {
            try trust.addKey(id: id, publicKey: key)
        }
        return trust
    }

    /// The entitlement payload: active from the reference epoch, expiring 30
    /// days later, granting `scim` and `core_sso`.
    private func payload() -> Data {
        Data("""
        {"tenant_id":"tenant-1","subscription_id":"sub-1","plan":{"id":"pro","version":1},
         "revision":1,"active":true,"features":{"scim":true,"core_sso":true},
         "limits":{"users":{"soft":5,"hard":10,"unlimited":false}},
         "effective_at":1699999940,"expires_at":1702591940,"generated_at":1699999940}
        """.utf8)
    }

    private func makeFile(
        signer: Signer = .vendor,
        keyID: String? = nil,
        algorithm: String = SnaplinkLicenseEnvelope.algorithm
    ) -> Data {
        let payload = payload()
        let signature = try! Curve25519.Signing.PrivateKey(
            rawRepresentation: fixtureSigningKey(for: signer)
        ).signature(for: payload)
        let fields: [String: JSONValue] = [
            "version": .integer(SnaplinkLicenseEnvelope.version),
            "algorithm": .string(algorithm),
            "key_id": .string(keyID ?? vendorKeyID),
            "payload": .string(payload.base64EncodedString()),
            "signature": .string(signature.base64EncodedString())
        ]
        return try! encodeEnvelope(fields)
    }

    private func verify(_ raw: Data, trustedKeys: [String: Data]) throws -> SnaplinkLicenseFile {
        try SnaplinkLicenseFileVerifier.verify(raw, trust: try trustKeys(trustedKeys))
    }

    private func verify(_ raw: Data) throws -> SnaplinkLicenseFile {
        try SnaplinkLicenseFileVerifier.verify(raw, trust: try trust())
    }

    private func assertLicenseError(
        _ body: () throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> SnaplinkLicenseError {
        do {
            _ = try body()
            XCTFail("verification must not succeed", file: file, line: line)
            return SnaplinkLicenseError(code: .malformed, message: "unreachable")
        } catch let error as SnaplinkLicenseError {
            return error
        } catch {
            XCTFail("expected a SnaplinkLicenseError, got \(error)", file: file, line: line)
            return SnaplinkLicenseError(code: .malformed, message: "unreachable")
        }
    }

    private enum JSONValue: Encodable {
        case string(String)
        case integer(Int)

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .string(let value): try container.encode(value)
            case .integer(let value): try container.encode(value)
            }
        }
    }

    private func encodeEnvelope(_ fields: [String: JSONValue?]) throws -> Data {
        var object: [String: JSONValue] = [:]
        for (name, value) in fields {
            if let value { object[name] = value }
        }
        return try JSONEncoder().encode(object)
    }

    private func decodeEnvelope(_ raw: Data) throws -> [String: JSONValue?] {
        let object = try JSONSerialization.jsonObject(with: raw) as? [String: Any] ?? [:]
        var fields: [String: JSONValue?] = [:]
        for (name, value) in object {
            if let text = value as? String {
                fields[name] = .string(text)
            } else if let number = value as? NSNumber {
                fields[name] = .integer(number.intValue)
            } else {
                fields[name] = nil
            }
        }
        return fields
    }

    private func loadSharedFixture() throws -> Set<String> {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // SnaplinkSSOTests
            .deletingLastPathComponent() // swift
            .deletingLastPathComponent() // sdks
            .deletingLastPathComponent() // repository root
        let path = root
            .appendingPathComponent("ops/build/sdk-conformance/license_file.json")
        let data = try Data(contentsOf: path)
        let document = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        let cases = document["cases"] as? [[String: Any]] ?? []
        return Set(cases.compactMap { $0["id"] as? String })
    }

    /// A deterministic Ed25519 keypair generated for this suite. The private
    /// half is a published test fixture, not a vendor key.
    private static let vendorSigningKeyBase64 = "KRjHjzv/Ftj3WZSilOLxcwADZKROiJ31Fs3DZAsB1e0="
    private static let vendorKeyBase64 = "RFnhOMhTnQmsRm705Jz0XJGNJ978Iz0niDDB6FwnlHs="
    private static let untrustedSigningKeyBase64 = "SABXwz0zTacoJIKLrG5j/3m13fzwpVWd5gukE/sK6TY="
    private static let untrustedKeyBase64 = "0mg8bZoM0k8YhA3y0yjAG+EpHQ9ed9P+Cc/JNSlpU6E="
}
