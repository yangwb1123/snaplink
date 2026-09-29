/** A stable product capability identifier, mirroring `commerce.FeatureKey`. */
export type Feature = "core_sso" | "multi_tenant" | "audit_governance" | "notifications" | "im" | "account" | "vault" | "scim" | "federation" | "high_availability";
/** Every feature key the server currently defines, in declaration order. */
export declare const ALL_FEATURES: readonly Feature[];
/** A stable quota dimension, mirroring `commerce.LimitKey`. */
export type Limit = "users" | "clients" | "sessions" | "token_rate" | "storage_bytes" | "storage_objects";
/** Every limit key the server currently defines, in declaration order. */
export declare const ALL_LIMITS: readonly Limit[];
/**
 * Why an entitlement is present but not usable.
 *
 * Presentation only. It must never drive retry or authorization behaviour: the
 * server collapses distinct internal causes into one wire code, and a client
 * that branched on the reason would leak the distinction the server hides.
 */
export type InactiveReason = "not_yet_effective" | "expired" | "suspended";
/** Which of the three states a product licence is in. */
export type LicenseStateKind = "not_activated" | "inactive" | "active";
/**
 * The classified state of a product licence.
 *
 * A nullable entitlement cannot tell "never activated" from "activated once but
 * lapsed", and those need different copy and different follow-up actions.
 */
export type LicenseState = {
    kind: "not_activated";
    reason?: undefined;
    until?: undefined;
    entitlement?: undefined;
} | {
    kind: "inactive";
    reason: InactiveReason;
    until?: number;
    entitlement?: undefined;
} | {
    kind: "active";
    reason?: undefined;
    until?: undefined;
    entitlement: Entitlement;
};
/** A soft threshold and a hard safety limit. */
export interface LimitGrant {
    soft: number;
    hard: number;
    unlimited: boolean;
}
/** A server-derived commercial entitlement snapshot. */
export interface Entitlement {
    tenantId: string;
    subscriptionId: string;
    plan: {
        id: string;
        version: number;
    };
    revision: number;
    active: boolean;
    features: Map<string, boolean>;
    limits: Map<string, LimitGrant>;
    effectiveAt: number;
    expiresAt?: number;
    generatedAt: number;
}
/** Build a typed entitlement from the wire shape. */
export declare function entitlementFromWire(raw: unknown): Entitlement;
/** Current time in Unix seconds, the clock the state helpers expect. */
export declare function unixNow(): number;
/**
 * Classify the entitlement at `now`.
 *
 * Mirrors `commerce.EntitlementSnapshot.effective` exactly: the `expires_at`
 * boundary is exclusive, so an entitlement whose window closes at `t` is already
 * inactive at `t`.
 */
export declare function stateAt(entitlement: Entitlement, now: number): LicenseState;
/** Whether `state` grants anything. The only question a feature gate should ask. */
export declare function isActive(state: LicenseState): boolean;
/**
 * Whether `feature` is granted at `now`.
 *
 * Returns false for an inactive entitlement regardless of what the map says, and
 * false for a key this build does not recognise: a caller could otherwise pass
 * an arbitrary string and be granted whatever the server sent.
 */
export declare function hasFeature(entitlement: Entitlement, feature: Feature, now: number): boolean;
/** The grant for `limit` at `now`, or undefined when inactive, absent, or unknown. */
export declare function limitOf(entitlement: Entitlement, limit: Limit, now: number): LimitGrant | undefined;
/** Feature keys the server sent that this build does not recognise. */
export declare function unknownFeatures(entitlement: Entitlement): string[];
/** Limit keys the server sent that this build does not recognise. */
export declare function unknownLimits(entitlement: Entitlement): string[];
/**
 * Return the entitlement carried by an account-context response.
 *
 * Returns undefined for a context with no entitlement, which is the
 * never-activated case rather than a lapsed one.
 */
export declare function entitlementFromAccountContext(context: unknown): Entitlement | undefined;
/** Classify an account-context response at `now`. */
export declare function licenseStateFromAccountContext(context: unknown, now: number): LicenseState;
