import Foundation
import XCTest
@testable import SnaplinkSSO

final class EntitlementTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    func testActiveEntitlementGrantsOnlyReportedFeatures() {
        let entitlement = entitlement(
            active: true,
            features: ["scim": true, "vault": false, "core_sso": true],
            effectiveAt: now.addingTimeInterval(-60),
            expiresAt: now.addingTimeInterval(3600)
        )
        XCTAssertTrue(entitlement.state(at: now).isActive)
        XCTAssertTrue(entitlement.has(.scim, at: now))
        XCTAssertTrue(entitlement.has(.coreSSO, at: now))
        XCTAssertFalse(entitlement.has(.vault, at: now))
        XCTAssertFalse(entitlement.has(.federation, at: now))
    }

    func testInactiveEntitlementGrantsNothingRegardlessOfFeatures() {
        let lapsed = entitlement(
            active: true,
            features: ["scim": true],
            effectiveAt: now.addingTimeInterval(-7200),
            expiresAt: now
        )
        XCTAssertFalse(lapsed.state(at: now).isActive)
        XCTAssertFalse(lapsed.has(.scim, at: now))
        XCTAssertNil(lapsed.limit(.users, at: now))
    }

    func testStateClassifiesSuspendedNotYetEffectiveAndExpired() {
        let suspended = entitlement(active: false, features: [:], effectiveAt: now, expiresAt: nil)
        let suspendedState = suspended.state(at: now)
        XCTAssertEqual(suspendedState.kind, .inactive)
        XCTAssertEqual(suspendedState.reason, .suspended)

        let future = entitlement(
            active: true,
            features: ["scim": true],
            effectiveAt: now.addingTimeInterval(60),
            expiresAt: nil
        )
        let futureState = future.state(at: now)
        XCTAssertEqual(futureState.kind, .inactive)
        XCTAssertEqual(futureState.reason, .notYetEffective)

        let expired = entitlement(
            active: true,
            features: ["scim": true],
            effectiveAt: now.addingTimeInterval(-3600),
            expiresAt: now.addingTimeInterval(-1)
        )
        let expiredState = expired.state(at: now)
        XCTAssertEqual(expiredState.kind, .inactive)
        XCTAssertEqual(expiredState.reason, .expired)
        XCTAssertEqual(expiredState.until, now.addingTimeInterval(-1))
    }

    func testExpiryBoundaryIsExclusive() {
        let entitlement = entitlement(
            active: true,
            features: ["scim": true],
            effectiveAt: now.addingTimeInterval(-60),
            expiresAt: now
        )
        XCTAssertFalse(entitlement.has(.scim, at: now))
        XCTAssertTrue(entitlement.has(.scim, at: now.addingTimeInterval(-1)))
    }

    func testLimitGrantAndUnknownFeatures() {
        let entitlement = entitlement(
            active: true,
            features: ["scim": true, "quantum_signing": true],
            limits: ["users": SnaplinkLimitGrant(soft: 5, hard: 10), "sessions": SnaplinkLimitGrant(soft: 0, hard: 0, unlimited: true)],
            effectiveAt: now.addingTimeInterval(-60),
            expiresAt: nil
        )
        XCTAssertEqual(entitlement.limit(.users, at: now), SnaplinkLimitGrant(soft: 5, hard: 10))
        XCTAssertEqual(entitlement.limit(.sessions, at: now)?.unlimited, true)
        XCTAssertNil(entitlement.limit(.storageBytes, at: now))
        XCTAssertEqual(entitlement.unknownFeatures, ["quantum_signing"])
    }

    func testDecodesUnixSecondsAndRFC3339Timestamps() throws {
        let unixSeconds = try decodeEntitlement("""
        {"tenant_id":"t1","subscription_id":"s1","plan":{"id":"pro","version":2},"revision":1,
         "active":true,"features":{},"limits":{},"effective_at":1699999940,"generated_at":1699999940}
        """)
        XCTAssertEqual(unixSeconds.effectiveAt, Date(timeIntervalSince1970: 1_699_999_940))
        XCTAssertNil(unixSeconds.expiresAt)

        let rfc3339 = try decodeEntitlement("""
        {"tenant_id":"t1","subscription_id":"s1","plan":{"id":"pro","version":2},"revision":1,
         "active":true,"features":{},"limits":{},"effective_at":"2026-01-01T00:00:00Z",
         "expires_at":"2026-02-01T00:00:00.500Z","generated_at":"2026-01-01T00:00:00Z"}
        """)
        XCTAssertEqual(rfc3339.effectiveAt, Date(timeIntervalSince1970: 1_767_225_600))
        XCTAssertEqual(rfc3339.expiresAt?.timeIntervalSince1970 ?? 0, 1_769_904_000.5, accuracy: 0.001)
    }

    func testUnparsableTimestampDecodesAsAbsentRatherThanGuessed() throws {
        let entitlement = try decodeEntitlement("""
        {"tenant_id":"t1","subscription_id":"s1","plan":{"id":"pro","version":2},"revision":1,
         "active":true,"features":{"scim":true},"limits":{},"effective_at":"whenever",
         "expires_at":"nonsense","generated_at":"2026-01-01T00:00:00Z"}
        """)
        XCTAssertEqual(entitlement.effectiveAt, .distantPast)
        XCTAssertNil(entitlement.expiresAt)
    }

    private func decodeEntitlement(_ json: String) throws -> SnaplinkEntitlement {
        try JSONDecoder().decode(SnaplinkEntitlement.self, from: Data(json.utf8))
    }

    private func entitlement(
        active: Bool,
        features: [String: Bool],
        limits: [String: SnaplinkLimitGrant] = [:],
        effectiveAt: Date,
        expiresAt: Date?
    ) -> SnaplinkEntitlement {
        SnaplinkEntitlement(
            tenantID: "tenant-1",
            subscriptionID: "sub-1",
            plan: SnaplinkPlanRef(id: "pro", version: 1),
            revision: 1,
            active: active,
            features: features,
            limits: limits,
            effectiveAt: effectiveAt,
            expiresAt: expiresAt,
            generatedAt: effectiveAt
        )
    }
}
