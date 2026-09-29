// Cross-language conformance for the entitlement layer.
//
// The cases in `ops/build/sdk-conformance/entitlement.json` are the shared
// contract, so a change to the fixture changes what every SDK is held to. The
// fixture stores Unix seconds and string-keyed maps to stay readable from any
// language; `entitlementFromWire` is the only place that mapping happens.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ALL_FEATURES,
  ALL_LIMITS,
  entitlementFromAccountContext,
  entitlementFromWire,
  hasFeature,
  isActive,
  licenseStateFromAccountContext,
  limitOf,
  stateAt,
  unknownFeatures,
} from "./index.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REFERENCE_NOW = 1_700_000_000;

const fixture = JSON.parse(
  readFileSync(join(HERE, "..", "..", "ops", "build", "sdk-conformance", "entitlement.json"), "utf-8"),
);

function findCase(id) {
  const found = fixture.cases.find((entry) => entry.id === id);
  assert.ok(found, `the fixture must contain ${id}`);
  return found;
}

const nowOf = (entry) => entry.now ?? REFERENCE_NOW;
const contextFor = (entry) => ({
  product_id: "product-a",
  tenant_id: "tenant-a",
  entitlement: entry.entitlement,
});

test("fixture is reachable and populated", () => {
  assert.ok(fixture.cases.length > 0, "the shared fixture must not be empty");
});

test("every case classifies as the contract requires", () => {
  for (const entry of fixture.cases) {
    const state = licenseStateFromAccountContext(contextFor(entry), nowOf(entry));
    assert.equal(state.kind, entry.expect_state, `${entry.id} classified as ${state.kind}`);
    if (entry.expect_inactive_reason) {
      assert.equal(state.reason, entry.expect_inactive_reason, `${entry.id} reason`);
    }
  }
});

test("a present entitlement is not necessarily effective", () => {
  for (const entry of fixture.cases) {
    const now = nowOf(entry);
    const entitlement = entitlementFromAccountContext(contextFor(entry));
    const grants = entitlement ? isActive(stateAt(entitlement, now)) : false;
    if (entitlement && !grants) {
      assert.notEqual(entry.expect_state, "active", `${entry.id} grants while the contract says otherwise`);
    }
  }
});

test("the expiry boundary is exclusive", () => {
  const entry = findCase("exactly_at_expiry");
  const entitlement = entitlementFromAccountContext(contextFor(entry));
  const expiresAt = entry.entitlement.expires_at;
  assert.ok(isActive(stateAt(entitlement, expiresAt - 1)), "one second before expiry must still grant");
  assert.ok(!isActive(stateAt(entitlement, expiresAt)), "the expiry second itself must not grant");
});

test("feature lookups match the contract", () => {
  for (const entry of fixture.cases) {
    const entitlement = entitlementFromAccountContext(contextFor(entry));
    for (const [key, want] of Object.entries(entry.expect_features ?? {})) {
      const got = entitlement ? hasFeature(entitlement, key, nowOf(entry)) : false;
      assert.equal(got, want, `${entry.id}/${key}`);
    }
  }
});

test("limit lookups match the contract", () => {
  for (const entry of fixture.cases) {
    const entitlement = entitlementFromAccountContext(contextFor(entry));
    for (const [key, want] of Object.entries(entry.expect_limits ?? {})) {
      const grant = entitlement ? limitOf(entitlement, key, nowOf(entry)) : undefined;
      if (grant === undefined) {
        if (entitlement && isActive(stateAt(entitlement, nowOf(entry)))) {
          assert.fail(`${entry.id} lost an active limit ${key}`);
        }
        continue;
      }
      assert.equal(grant.soft, want.soft ?? 0, `${entry.id}/${key} soft`);
      assert.equal(grant.hard, want.hard ?? 0, `${entry.id}/${key} hard`);
      assert.equal(grant.unlimited, want.unlimited ?? false, `${entry.id}/${key} unlimited`);
    }
  }
});

test("an absent entitlement is never unlimited", () => {
  const context = { product_id: "p", tenant_id: "t", entitlement: null };
  assert.equal(licenseStateFromAccountContext(context, REFERENCE_NOW).kind, "not_activated");
  assert.equal(entitlementFromAccountContext(context), undefined);
});

test("every defined key exists", () => {
  assert.equal(ALL_FEATURES.length, 10, "the server defines ten feature keys");
  assert.equal(ALL_LIMITS.length, 6, "the server defines six limit keys");
});

test("RFC 3339 and Unix seconds parse identically", () => {
  const base = { active: true, features: {}, limits: {} };
  const fromString = entitlementFromWire({
    ...base,
    effective_at: "2023-11-14T22:13:19Z",
    expires_at: "2023-11-14T22:13:20Z",
  });
  const fromNumber = entitlementFromWire({ ...base, effective_at: 1699999999, expires_at: 1700000000 });
  assert.equal(fromString.effectiveAt, fromNumber.effectiveAt, "effective_at");
  assert.equal(fromString.expiresAt, fromNumber.expiresAt, "expires_at");
  assert.equal(stateAt(fromString, REFERENCE_NOW).kind, stateAt(fromNumber, REFERENCE_NOW).kind);
});

test("a missing or malformed timestamp is treated as absent", () => {
  const base = { active: true, features: {}, limits: {} };
  assert.equal(entitlementFromWire(base).expiresAt, undefined, "missing");
  assert.equal(entitlementFromWire({ ...base, expires_at: "nonsense" }).expiresAt, undefined, "malformed");
  assert.equal(entitlementFromWire({ ...base, effective_at: null }).effectiveAt, 0, "null");
});

test("an unrecognised key is preserved but grants nothing", () => {
  const entitlement = entitlementFromWire({
    active: true,
    effective_at: 1_600_000_000,
    features: { core_sso: true, telemetry_magic: true },
    limits: {},
  });
  assert.deepEqual(unknownFeatures(entitlement), ["telemetry_magic"]);
  assert.ok(hasFeature(entitlement, "core_sso", REFERENCE_NOW), "known keys still resolve");
  assert.ok(!hasFeature(entitlement, "telemetry_magic", REFERENCE_NOW), "an unknown key must not grant");
});
