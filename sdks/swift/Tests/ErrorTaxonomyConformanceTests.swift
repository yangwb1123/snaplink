import Foundation
import XCTest
@testable import SnaplinkSSO

/// Cross-language conformance for the error taxonomy.
///
/// The cases in `ops/build/sdk-conformance/errors.json` are the shared
/// contract: every SDK error type must classify each code identically, carry
/// the server's code verbatim, and keep SDK-originated codes distinguishable.
final class ErrorTaxonomyConformanceTests: XCTestCase {
    func testEverySharedCaseIsClassifiedWithItsDocumentedClass() throws {
        let cases = try sharedCases()
        XCTAssertFalse(cases.isEmpty, "the shared error fixture must not be empty")

        for testCase in cases {
            let code = try XCTUnwrap(testCase["code"] as? String, "case without a code: \(testCase)")
            let expectedClass = try XCTUnwrap(
                testCase["class"] as? String,
                "case \(code) has no class"
            )
            let entry = try XCTUnwrap(
                SnaplinkErrorCatalog.entry(for: code),
                "the controlled vocabulary is missing \(code)"
            )
            XCTAssertEqual(
                entry.errorClass.rawValue,
                expectedClass,
                "case \(code) is classified as \(entry.errorClass.rawValue), not \(expectedClass)"
            )
            if let status = testCase["status"] as? Int {
                let error = SnaplinkAuthError(code: code, message: "x", statusCode: status)
                XCTAssertEqual(error.classification.status, status, "case \(code) lost its status")
            }
        }
    }

    func testSharedCaseIdentifiersAreAllImplementedHere() throws {
        let cases = try sharedCases()
        let documented = try cases.map { try XCTUnwrap($0["code"] as? String) }
        XCTAssertFalse(documented.isEmpty)
        // The fixture carries one case per code; the catalog must cover them all.
        for code in documented {
            XCTAssertNotNil(SnaplinkErrorCatalog.entry(for: code), "case \(code) is not classified")
        }
    }

    func testServerCodeIsCarriedVerbatimAndNeverRewritten() throws {
        for testCase in try sharedCases() {
            let code = try XCTUnwrap(testCase["code"] as? String)
            // The license case has no status: it originates in the SDK.
            let error = SnaplinkAuthError(
                code: code,
                message: "server said so",
                statusCode: testCase["status"] as? Int
            )
            XCTAssertEqual(error.classification.code, code)
            XCTAssertEqual(error.code, code)
            XCTAssertEqual(error.classification.errorClass.rawValue, testCase["class"] as? String)
        }
    }

    func testUnknownServerCodeStaysVerbatimWithoutBeingForcedIntoAClass() {
        let error = SnaplinkAuthError(code: "some_future_code", message: "x", statusCode: 418)
        XCTAssertEqual(error.classification.code, "some_future_code")
        XCTAssertEqual(error.classification.status, 418)
        XCTAssertEqual(error.classification.errorClass, .sdk)
        XCTAssertNil(SnaplinkErrorCatalog.entry(for: "some_future_code"))
    }

    func testLicenseCodesAreNeverRemappedOntoANetworkError() {
        for licenseCode in SnaplinkLicenseErrorCode.allCases {
            let error = SnaplinkLicenseError(code: licenseCode, message: "local failure")
            XCTAssertEqual(error.classification.code, licenseCode.rawValue)
            XCTAssertEqual(error.classification.errorClass, .license)
            XCTAssertNil(error.status, "a local verification failure has no HTTP status")
            XCTAssertEqual(error.classification.recovery, .terminal)
        }
    }

    func testRecoveryGuidanceMatchesTheDocumentedResponses() throws {
        let expected: [String: SnaplinkErrorRecovery] = [
            "activation_unavailable": .retryWithBackoff,
            "activation_invalid": .terminal,
            "invalid_grant": .reauthenticate,
            "invalid_client": .terminal,
            "invalid_scope": .fixRequest,
            "insufficient_scope": .fixRequest,
            "invalid_token": .reauthenticate,
            "session_invalid": .recreateCeremony,
            "mfa_invalid": .recreateCeremony
        ]
        for (code, recovery) in expected {
            let entry = try XCTUnwrap(
                SnaplinkErrorCatalog.entry(for: code),
                "\(code) must be in the catalog"
            )
            XCTAssertEqual(entry.recovery, recovery, "\(code) recovery guidance drifted")
        }
    }

    func testInvalidGrantIsNeverInstructedToRetryRefreshForever() throws {
        // A refresh denied by conditional access is invalid_grant, so a caller
        // must not treat it as transient.
        let entry = try XCTUnwrap(SnaplinkErrorCatalog.entry(for: "invalid_grant"))
        XCTAssertNotEqual(entry.recovery, .retryWithBackoff)
    }

    func testInsufficientScopeIsDistinctFromInvalidScope() throws {
        let insufficient = try XCTUnwrap(SnaplinkErrorCatalog.entry(for: "insufficient_scope"))
        let invalid = try XCTUnwrap(SnaplinkErrorCatalog.entry(for: "invalid_scope"))
        XCTAssertEqual(insufficient.errorClass, .authorization)
        XCTAssertEqual(invalid.errorClass, .oauth)
    }

    func testEveryErrorTypeIsCatchableThroughOneShape() throws {
        let authError = SnaplinkAuthError(code: "invalid_grant", message: "denied", statusCode: 400)
        let licenseError = SnaplinkLicenseError(code: .signatureInvalid, message: "local failure")
        let errors: [any SnaplinkClassifiedError] = [authError, licenseError]

        XCTAssertEqual(errors.map(\.classification.errorClass), [.oauth, .license])
        for error in errors {
            XCTAssertFalse(error.classification.code.isEmpty)
            XCTAssertFalse(error.message.isEmpty)
        }
    }

    private func sharedCases() throws -> [[String: Any]] {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // SnaplinkSSOTests
            .deletingLastPathComponent() // swift
            .deletingLastPathComponent() // sdks
            .deletingLastPathComponent() // repository root
        let data = try Data(contentsOf: root.appendingPathComponent("ops/build/sdk-conformance/errors.json"))
        let document = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        return document["cases"] as? [[String: Any]] ?? []
    }
}
