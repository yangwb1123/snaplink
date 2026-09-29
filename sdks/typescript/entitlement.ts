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

import type { CommerceEntitlement, CommerceLimitGrant, CommercePlanRef } from "./client.js";

/** A stable product capability identifier, mirroring `commerce.FeatureKey`. */
export type Feature =
  | "core_sso"
  | "multi_tenant"
  | "audit_governance"
  | "notifications"
  | "im"
  | "account"
  | "vault"
  | "scim"
  | "federation"
  | "high_availability";

/** Every feature key the server currently defines, in declaration order. */
export const ALL_FEATURES: readonly Feature[] = [
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

/** A stable quota dimension, mirroring `commerce.LimitKey`. */
export type Limit =
  | "users"
  | "clients"
  | "sessions"
  | "token_rate"
  | "storage_bytes"
  | "storage_objects";

/** Every limit key the server currently defines, in declaration order. */
export const ALL_LIMITS: readonly Limit[] = [
  "users",
  "clients",
  "sessions",
  "token_rate",
  "storage_bytes",
  "storage_objects",
];

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
export type LicenseState =
  | { kind: "not_activated"; reason?: undefined; until?: undefined; entitlement?: undefined }
  | { kind: "inactive"; reason: InactiveReason; until?: number; entitlement?: undefined }
  | { kind: "active"; reason?: undefined; until?: undefined; entitlement: Entitlement };

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
  plan: { id: string; version: number };
  revision: number;
  active: boolean;
  features: Map<string, boolean>;
  limits: Map<string, LimitGrant>;
  effectiveAt: number;
  expiresAt?: number;
  generatedAt: number;
}

/**
 * Accepts the RFC 3339 form Go's `time.Time` serialises, a Unix-seconds integer
 * as a fixture or hand-written file may use, and null.
 */
function parseTimestamp(value: unknown): number | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
  if (typeof value !== "string") return undefined;
  const text = value.trim();
  if (text === "") return undefined;
  if (/^-?\d+$/.test(text)) return Number.parseInt(text, 10);
  const parsed = Date.parse(text);
  if (Number.isNaN(parsed)) return undefined;
  return Math.trunc(parsed / 1000);
}

function toLimitGrant(value: unknown): LimitGrant {
  if (typeof value !== "object" || value === null) return { soft: 0, hard: 0, unlimited: false };
  const raw = value as Partial<CommerceLimitGrant>;
  return {
    soft: typeof raw.soft === "number" ? raw.soft : 0,
    hard: typeof raw.hard === "number" ? raw.hard : 0,
    unlimited: raw.unlimited === true,
  };
}

/** Build a typed entitlement from the wire shape. */
export function entitlementFromWire(raw: unknown): Entitlement {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("entitlement must be an object");
  }
  const wire = raw as CommerceEntitlement;
  const features = new Map<string, boolean>();
  for (const [key, flag] of Object.entries(wire.features ?? {})) {
    features.set(key, flag === true);
  }
  const limits = new Map<string, LimitGrant>();
  for (const [key, grant] of Object.entries(wire.limits ?? {})) {
    limits.set(key, toLimitGrant(grant));
  }
  const plan: CommercePlanRef | undefined = wire.plan;
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
export function unixNow(): number {
  return Math.trunc(Date.now() / 1000);
}

/**
 * Classify the entitlement at `now`.
 *
 * Mirrors `commerce.EntitlementSnapshot.effective` exactly: the `expires_at`
 * boundary is exclusive, so an entitlement whose window closes at `t` is already
 * inactive at `t`.
 */
export function stateAt(entitlement: Entitlement, now: number): LicenseState {
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
export function isActive(state: LicenseState): boolean {
  return state.kind === "active";
}

/**
 * Whether `feature` is granted at `now`.
 *
 * Returns false for an inactive entitlement regardless of what the map says, and
 * false for a key this build does not recognise: a caller could otherwise pass
 * an arbitrary string and be granted whatever the server sent.
 */
export function hasFeature(entitlement: Entitlement, feature: Feature, now: number): boolean {
  if (!isActive(stateAt(entitlement, now))) return false;
  if (!ALL_FEATURES.includes(feature)) return false;
  return entitlement.features.get(feature) === true;
}

/** The grant for `limit` at `now`, or undefined when inactive, absent, or unknown. */
export function limitOf(entitlement: Entitlement, limit: Limit, now: number): LimitGrant | undefined {
  if (!isActive(stateAt(entitlement, now))) return undefined;
  if (!ALL_LIMITS.includes(limit)) return undefined;
  return entitlement.limits.get(limit);
}

/** Feature keys the server sent that this build does not recognise. */
export function unknownFeatures(entitlement: Entitlement): string[] {
  return [...entitlement.features.keys()].filter(
    (key) => !ALL_FEATURES.includes(key as Feature),
  );
}

/** Limit keys the server sent that this build does not recognise. */
export function unknownLimits(entitlement: Entitlement): string[] {
  return [...entitlement.limits.keys()].filter((key) => !ALL_LIMITS.includes(key as Limit));
}

/**
 * Return the entitlement carried by an account-context response.
 *
 * Returns undefined for a context with no entitlement, which is the
 * never-activated case rather than a lapsed one.
 */
export function entitlementFromAccountContext(context: unknown): Entitlement | undefined {
  if (typeof context !== "object" || context === null) return undefined;
  const raw = (context as { entitlement?: unknown }).entitlement;
  if (raw === null || raw === undefined) return undefined;
  return entitlementFromWire(raw);
}

/** Classify an account-context response at `now`. */
export function licenseStateFromAccountContext(
  context: unknown,
  now: number,
): LicenseState {
  const entitlement = entitlementFromAccountContext(context);
  return entitlement ? stateAt(entitlement, now) : { kind: "not_activated" };
}
