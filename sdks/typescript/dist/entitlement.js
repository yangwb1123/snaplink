// Application-facing commercial entitlement for the Snaplink TypeScript SDK.
//
// The server is always the authority on what a tenant may do. This module
// exists so a caller never has to know the wire shape of an entitlement in
// order to decide whether a feature is available, and so a lapsed entitlement
// is never mistaken for a live one.
//
// `stateAt` reproduces `commerce.EntitlementSnapshot.effective` exactly: an
// entitlement is effective only when `active` is set, `now` is not before
// `effective_at`, and `expires_at` is unset or strictly after `now`. A presence
// check cannot make that distinction, which is why LicenseState has three kinds
// rather than a nullable entitlement.
/** Every feature key the server currently defines, in declaration order. */
export const ALL_FEATURES = [
    "core_sso",
    "multi_tenant",
    "audit_governance",
    "notifications",
    "im",
    "account",
    "vault",
    "scim",
    "federation",
    "high_availability",
];
/** Every limit key the server currently defines, in declaration order. */
export const ALL_LIMITS = [
    "users",
    "clients",
    "sessions",
    "token_rate",
    "storage_bytes",
    "storage_objects",
];
/**
 * Accepts the RFC 3339 form Go's `time.Time` serialises, a Unix-seconds integer
 * as a fixture or hand-written file may use, and null.
 */
function parseTimestamp(value) {
    if (value === null || value === undefined)
        return undefined;
    if (typeof value === "number" && Number.isFinite(value))
        return Math.trunc(value);
    if (typeof value !== "string")
        return undefined;
    const text = value.trim();
    if (text === "")
        return undefined;
    if (/^-?\d+$/.test(text))
        return Number.parseInt(text, 10);
    const parsed = Date.parse(text);
    if (Number.isNaN(parsed))
        return undefined;
    return Math.trunc(parsed / 1000);
}
function toLimitGrant(value) {
    if (typeof value !== "object" || value === null)
        return { soft: 0, hard: 0, unlimited: false };
    const raw = value;
    return {
        soft: typeof raw.soft === "number" ? raw.soft : 0,
        hard: typeof raw.hard === "number" ? raw.hard : 0,
        unlimited: raw.unlimited === true,
    };
}
/** Build a typed entitlement from the wire shape. */
export function entitlementFromWire(raw) {
    if (typeof raw !== "object" || raw === null) {
        throw new Error("entitlement must be an object");
    }
    const wire = raw;
    const features = new Map();
    for (const [key, flag] of Object.entries(wire.features ?? {})) {
        features.set(key, flag === true);
    }
    const limits = new Map();
    for (const [key, grant] of Object.entries(wire.limits ?? {})) {
        limits.set(key, toLimitGrant(grant));
    }
    const plan = wire.plan;
    return {
        tenantId: wire.tenant_id ?? "",
        subscriptionId: wire.subscription_id ?? "",
        plan: {
            id: plan?.id ?? "",
            version: typeof plan?.version === "number" ? plan.version : 0,
        },
        revision: typeof wire.revision === "number" ? wire.revision : 0,
        active: wire.active === true,
        features,
        limits,
        effectiveAt: parseTimestamp(wire.effective_at) ?? 0,
        expiresAt: parseTimestamp(wire.expires_at),
        generatedAt: parseTimestamp(wire.generated_at) ?? 0,
    };
}
/** Current time in Unix seconds, the clock the state helpers expect. */
export function unixNow() {
    return Math.trunc(Date.now() / 1000);
}
/**
 * Classify the entitlement at `now`.
 *
 * Mirrors `commerce.EntitlementSnapshot.effective` exactly: the `expires_at`
 * boundary is exclusive, so an entitlement whose window closes at `t` is already
 * inactive at `t`.
 */
export function stateAt(entitlement, now) {
    if (!entitlement.active) {
        return { kind: "inactive", reason: "suspended", until: entitlement.expiresAt };
    }
    if (now < entitlement.effectiveAt) {
        return { kind: "inactive", reason: "not_yet_effective" };
    }
    if (entitlement.expiresAt !== undefined && now >= entitlement.expiresAt) {
        return { kind: "inactive", reason: "expired", until: entitlement.expiresAt };
    }
    return { kind: "active", entitlement };
}
/** Whether `state` grants anything. The only question a feature gate should ask. */
export function isActive(state) {
    return state.kind === "active";
}
/**
 * Whether `feature` is granted at `now`.
 *
 * Returns false for an inactive entitlement regardless of what the map says, and
 * false for a key this build does not recognise: a caller could otherwise pass
 * an arbitrary string and be granted whatever the server sent.
 */
export function hasFeature(entitlement, feature, now) {
    if (!isActive(stateAt(entitlement, now)))
        return false;
    if (!ALL_FEATURES.includes(feature))
        return false;
    return entitlement.features.get(feature) === true;
}
/** The grant for `limit` at `now`, or undefined when inactive, absent, or unknown. */
export function limitOf(entitlement, limit, now) {
    if (!isActive(stateAt(entitlement, now)))
        return undefined;
    if (!ALL_LIMITS.includes(limit))
        return undefined;
    return entitlement.limits.get(limit);
}
/** Feature keys the server sent that this build does not recognise. */
export function unknownFeatures(entitlement) {
    return [...entitlement.features.keys()].filter((key) => !ALL_FEATURES.includes(key));
}
/** Limit keys the server sent that this build does not recognise. */
export function unknownLimits(entitlement) {
    return [...entitlement.limits.keys()].filter((key) => !ALL_LIMITS.includes(key));
}
/**
 * Return the entitlement carried by an account-context response.
 *
 * Returns undefined for a context with no entitlement, which is the
 * never-activated case rather than a lapsed one.
 */
export function entitlementFromAccountContext(context) {
    if (typeof context !== "object" || context === null)
        return undefined;
    const raw = context.entitlement;
    if (raw === null || raw === undefined)
        return undefined;
    return entitlementFromWire(raw);
}
/** Classify an account-context response at `now`. */
export function licenseStateFromAccountContext(context, now) {
    const entitlement = entitlementFromAccountContext(context);
    return entitlement ? stateAt(entitlement, now) : { kind: "not_activated" };
}
