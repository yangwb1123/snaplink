import Foundation
import XCTest
@testable import SnaplinkSSO

/// Cross-language conformance for entitlement semantics.
///
/// The cases in `ops/build/sdk-conformance/entitlement.json` are the shared
/// contract. The boundaries are the whole point: a naive `entitlement != nil`
/// check passes the obvious cases and fails every inactive one here.
final class EntitlementConformanceTests: XCTestCase {
    func testEverySharedCaseIsClassifiedIdentically() throws {
        for testCase in try sharedCases() {
            let id = try XCTUnwrap(testCase["id"] as? String)
            let entitlement = try decodeEntitlement(testCase["entitlement"])
            let now = Date(timeIntervalSince1970: try XCTUnwrap(
                (testCase["now"] as? Double) ?? referenceNow,
                "case \(id) declares an unparsable now"
            ))

            let state = SnaplinkAccountContext(
                productID: "fixture",
                tenantID: "fixture",
                entitlement: entitlement
            ).licenseState(at: now)

            XCTAssertEqual(
                state.kind.rawValue,
                try XCTUnwrap(testCase["expect_state"] as? String, "case \(id) has no expect_state"),
                "case \(id) classified as \(state.kind.rawValue)"
            )
            if let reason = testCase["expect_inactive_reason"] as? String {
                XCTAssertEqual(
                    state.reason?.rawValue,
                    reason,
                    "case \(id) reported the wrong inactive reason"
                )
            } else {
                XCTAssertNil(state.reason, "case \(id) must not report an inactive reason")
            }
        }
    }

    func testFeatureLookupsMatchTheSharedExpectation() throws {
        for testCase in try sharedCases() {
            let id = try XCTUnwrap(testCase["id"] as? String)
            guard let expected = testCase["expect_features"] as? [String: Bool],
                  let entitlement = try decodeEntitlement(testCase["entitlement"]) else { continue }
            let now = Date(timeIntervalSince1970: try XCTUnwrap((testCase["now"] as? Double) ?? referenceNow))
            for (key, granted) in expected {
                let feature = try XCTUnwrap(
                    SnaplinkFeature(rawValue: key),
                    "case \(id) expects an unknown feature \(key)"
                )
                XCTAssertEqual(
                    entitlement.has(feature, at: now),
                    granted,
                    "case \(id): feature \(key)"
                )
            }
        }
    }

    func testLimitLookupsMatchTheSharedExpectation() throws {
        for testCase in try sharedCases() {
            let id = try XCTUnwrap(testCase["id"] as? String)
            guard let expected = testCase["expect_limits"] as? [String: [String: Any]],
                  let entitlement = try decodeEntitlement(testCase["entitlement"]) else { continue }
            let now = Date(timeIntervalSince1970: try XCTUnwrap((testCase["now"] as? Double) ?? referenceNow))
            for (key, grant) in expected {
                let limit = try XCTUnwrap(
                    SnaplinkLimit(rawValue: key),
                    "case \(id) expects an unknown limit \(key)"
                )
                let resolved = try XCTUnwrap(
                    entitlement.limit(limit, at: now),
                    "case \(id): limit \(key) must resolve on an active entitlement"
                )
                XCTAssertEqual(resolved.soft, grant["soft"] as? Int64 ?? Int64(grant["soft"] as? Int ?? 0))
                XCTAssertEqual(resolved.hard, grant["hard"] as? Int64 ?? Int64(grant["hard"] as? Int ?? 0))
                XCTAssertEqual(
                    resolved.unlimited,
                    grant["unlimited"] as? Bool ?? false,
                    "case \(id): unlimited must short-circuit the soft/hard pair"
                )
            }
        }
    }

    func testAnInactiveEntitlementGrantsNothing() throws {
        for testCase in try sharedCases() {
            let id = try XCTUnwrap(testCase["id"] as? String)
            let expectedState = try XCTUnwrap(testCase["expect_state"] as? String)
            guard expectedState != "active",
                  let entitlement = try decodeEntitlement(testCase["entitlement"]) else { continue }
            let now = Date(timeIntervalSince1970: try XCTUnwrap((testCase["now"] as? Double) ?? referenceNow))
            for feature in SnaplinkFeature.allCases {
                XCTAssertFalse(
                    entitlement.has(feature, at: now),
                    "case \(id): \(feature.rawValue) must not be granted while inactive"
                )
            }
            for limit in SnaplinkLimit.allCases {
                XCTAssertNil(
                    entitlement.limit(limit, at: now),
                    "case \(id): \(limit.rawValue) must not resolve while inactive"
                )
            }
        }
    }

    func testAbsentEntitlementIsNeverTreatedAsUnlimited() throws {
        let context = SnaplinkAccountContext(productID: "pro", tenantID: "tenant-1", entitlement: nil)
        let now = try XCTUnwrap(referenceNow, "the shared fixture must pin a reference now")
        let state = context.licenseState(at: Date(timeIntervalSince1970: now))
        XCTAssertEqual(state.kind, .notActivated)
        XCTAssertFalse(state.isActive)
        XCTAssertNil(state.entitlement)
    }

    private var referenceNow: Double? {
        get throws {
            let root = URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .deletingLastPathComponent()
            let data = try Data(contentsOf: root.appendingPathComponent("ops/build/sdk-conformance/entitlement.json"))
            let document = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
            return document["reference_now"] as? Double
        }
    }

    private func decodeEntitlement(_ value: Any?) throws -> SnaplinkEntitlement? {
        guard let value, !(value is NSNull) else { return nil }
        let data = try JSONSerialization.data(withJSONObject: value)
        return try JSONDecoder().decode(SnaplinkEntitlement.self, from: data)
    }

    private func sharedCases() throws -> [[String: Any]] {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("ops/build/sdk-conformance/entitlement.json"))
        let document = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        return document["cases"] as? [[String: Any]] ?? []
    }
}
