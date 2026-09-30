import Foundation

/// A stable product capability identifier, mirroring `commerce.FeatureKey`.
///
/// An enum rather than a bare string is deliberate: a caller cannot hand
/// ``SnaplinkEntitlement/has(_:at:)`` an arbitrary key, so a plan can never
/// appear to grant a capability this build cannot gate. A key the server adds
/// later stays readable through ``SnaplinkEntitlement/unknownFeatures``.
public enum SnaplinkFeature: String, CaseIterable, Sendable {
    case coreSSO = "core_sso"
    case multiTenant = "multi_tenant"
    case auditGovernance = "audit_governance"
    case notifications
    case im
    case account
    case vault
    case scim
    case federation
    case highAvailability = "high_availability"
}

/// A stable quota dimension, mirroring `commerce.LimitKey`.
public enum SnaplinkLimit: String, CaseIterable, Sendable {
    case users
    case clients
    case sessions
    case tokenRate = "token_rate"
    case storageBytes = "storage_bytes"
    case storageObjects = "storage_objects"
}

/// Why an entitlement is present but not usable.
///
/// Presentation only. It must never drive retry or authorization behaviour: the
/// server collapses distinct internal causes into one wire code, and a client
/// that branched on the reason would leak the distinction the server hides.
public enum SnaplinkInactiveReason: String, Sendable {
    case notYetEffective = "not_yet_effective"
    case expired
    case suspended
}

/// Which of the three licence states applies.
///
/// A two-state optional cannot tell "never activated" from "activated once but
/// lapsed", and those need different copy and different follow-up actions.
public enum SnaplinkLicenseStateKind: String, Sendable {
    case notActivated = "not_activated"
    case inactive
    case active
}

/// The classified state of a product licence.
public struct SnaplinkLicenseState: Sendable, Equatable {
    public let kind: SnaplinkLicenseStateKind
    public let reason: SnaplinkInactiveReason?
    public let until: Date?
    public let entitlement: SnaplinkEntitlement?

    public init(
        kind: SnaplinkLicenseStateKind,
        reason: SnaplinkInactiveReason? = nil,
        until: Date? = nil,
        entitlement: SnaplinkEntitlement? = nil
    ) {
        self.kind = kind
        self.reason = reason
        self.until = until
        self.entitlement = entitlement
    }

    /// Whether grants are live. This is the only question a feature gate asks.
    public var isActive: Bool { kind == .active }
}

/// A soft threshold and a hard safety limit.
///
/// `unlimited` short-circuits the pair: an unlimited grant reports zero for
/// both thresholds, so a caller reading `soft` alone would see a bogus number.
public struct SnaplinkLimitGrant: Decodable, Sendable, Equatable {
    public let soft: Int64
    public let hard: Int64
    public let unlimited: Bool

    public init(soft: Int64, hard: Int64, unlimited: Bool = false) {
        self.soft = soft
        self.hard = hard
        self.unlimited = unlimited
    }

    private enum CodingKeys: String, CodingKey {
        case soft
        case hard
        case unlimited
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        soft = try container.decode(Int64.self, forKey: .soft)
        hard = try container.decode(Int64.self, forKey: .hard)
        // The schema declares a default of false, so the server may omit it.
        unlimited = try container.decodeIfPresent(Bool.self, forKey: .unlimited) ?? false
    }
}

/// A plan identifier and its immutable published version.
public struct SnaplinkPlanRef: Codable, Sendable, Equatable {
    public let id: String
    public let version: Int64

    public init(id: String, version: Int64) {
        self.id = id
        self.version = version
    }
}

/// A server-derived commercial entitlement snapshot.
///
/// The server remains the authority on every authorization decision; this
/// snapshot exists for user experience only.
public struct SnaplinkEntitlement: Decodable, Sendable, Equatable {
    public let tenantID: String
    public let subscriptionID: String
    public let plan: SnaplinkPlanRef
    public let revision: Int64
    public let active: Bool
    public let features: [String: Bool]
    public let limits: [String: SnaplinkLimitGrant]
    public let effectiveAt: Date
    public let expiresAt: Date?
    public let generatedAt: Date

    private enum CodingKeys: String, CodingKey {
        case tenantID = "tenant_id"
        case subscriptionID = "subscription_id"
        case plan
        case revision
        case active
        case features
        case limits
        case effectiveAt = "effective_at"
        case expiresAt = "expires_at"
        case generatedAt = "generated_at"
    }

    public init(
        tenantID: String,
        subscriptionID: String,
        plan: SnaplinkPlanRef,
        revision: Int64,
        active: Bool,
        features: [String: Bool],
        limits: [String: SnaplinkLimitGrant],
        effectiveAt: Date,
        expiresAt: Date?,
        generatedAt: Date
    ) {
        self.tenantID = tenantID
        self.subscriptionID = subscriptionID
        self.plan = plan
        self.revision = revision
        self.active = active
        self.features = features
        self.limits = limits
        self.effectiveAt = effectiveAt
        self.expiresAt = expiresAt
        self.generatedAt = generatedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        tenantID = try container.decode(String.self, forKey: .tenantID)
        subscriptionID = try container.decode(String.self, forKey: .subscriptionID)
        plan = try container.decode(SnaplinkPlanRef.self, forKey: .plan)
        revision = try container.decode(Int64.self, forKey: .revision)
        active = try container.decode(Bool.self, forKey: .active)
        features = try container.decodeIfPresent([String: Bool].self, forKey: .features) ?? [:]
        limits = try container.decodeIfPresent([String: SnaplinkLimitGrant].self, forKey: .limits) ?? [:]
        effectiveAt = try container.decode(SnaplinkWireDate.self, forKey: .effectiveAt).value ?? .distantPast
        expiresAt = try container.decodeIfPresent(SnaplinkWireDate.self, forKey: .expiresAt)?.value
        generatedAt = try container.decode(SnaplinkWireDate.self, forKey: .generatedAt).value ?? .distantPast
    }

    /// Classifies the entitlement at `now`.
    ///
    /// Mirrors `commerce.EntitlementSnapshot.effective` exactly: the expiry
    /// boundary is exclusive, so an entitlement whose window closes at `now` is
    /// already inactive at `now`.
    public func state(at now: Date) -> SnaplinkLicenseState {
        guard active else {
            return SnaplinkLicenseState(kind: .inactive, reason: .suspended, until: expiresAt)
        }
        if now < effectiveAt {
            return SnaplinkLicenseState(kind: .inactive, reason: .notYetEffective)
        }
        if let expiresAt, now >= expiresAt {
            return SnaplinkLicenseState(kind: .inactive, reason: .expired, until: expiresAt)
        }
        return SnaplinkLicenseState(kind: .active, entitlement: self)
    }

    /// Whether `feature` is granted at `now`.
    ///
    /// False for an inactive entitlement regardless of what the map says.
    public func has(_ feature: SnaplinkFeature, at now: Date) -> Bool {
        state(at: now).isActive && features[feature.rawValue] == true
    }

    /// The grant for `limit` at `now`, or nil when inactive, absent, or
    /// unrecognised.
    public func limit(_ limit: SnaplinkLimit, at now: Date) -> SnaplinkLimitGrant? {
        guard state(at: now).isActive else { return nil }
        return limits[limit.rawValue]
    }

    /// Feature keys the server sent that this build does not recognise, so an
    /// operator can see a plan grants something the SDK cannot yet gate instead
    /// of silently ignoring it.
    public var unknownFeatures: [String] {
        let known = Set(SnaplinkFeature.allCases.map(\.rawValue))
        return features.keys.filter { !known.contains($0) }.sorted()
    }
}

/// A timestamp that accepts either RFC 3339 text or Unix seconds.
///
/// Snaplink fixtures and hand-written entitlement files use Unix seconds while
/// the live API uses RFC 3339, so every entitlement timestamp goes through this
/// instead of one fixed format. An unrecognised value decodes as absent rather
/// than being guessed.
struct SnaplinkWireDate: Decodable {
    let value: Date?

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let text = try? container.decode(String.self), let parsed = Self.parse(text) {
            value = parsed
            return
        }
        if let seconds = try? container.decode(Double.self) {
            value = Date(timeIntervalSince1970: seconds)
            return
        }
        value = nil
    }

    private static func parse(_ text: String) -> Date? {
        for formatter in formatters {
            if let date = formatter.date(from: text) { return date }
        }
        return nil
    }

    private static let formatters: [ISO8601DateFormatter] = {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let standard = ISO8601DateFormatter()
        standard.formatOptions = [.withInternetDateTime]
        return [fractional, standard]
    }()
}
