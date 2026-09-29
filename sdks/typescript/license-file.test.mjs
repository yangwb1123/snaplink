// Cross-language conformance for entitlement-file verification.
//
// The cases in `ops/build/sdk-conformance/license_file.json` are the shared
// contract. The verifier here is deterministic and injected, deliberately not a
// vendor key: these tests are about the verification outcome, not the provenance
// of the trust root.
//
// The verifier is injected because this package takes no dependency and WebCrypto
// Ed25519 is still unevenly deployed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  addLicenseBase64Key,
  licenseFileState,
  licenseTrustFromKey,
  LicenseError,
  trustKeyIds,
  vendorPinnedTrust,
  verifyLicenseFile,
} from "./index.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REFERENCE_NOW = 1_700_000_000;
const KEY_ID = "vendor-2026";

const PUBLIC = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString("base64");
const SIGNATURE = Buffer.from(Array.from({ length: 64 }, (_, i) => i)).toString("base64");

/** A deterministic stand-in: accepts only the exact payload it was bound to. */
function verifierFor(signed) {
  const calls = [];
  const verifier = async (_key, payload, signature) => {
    calls.push({ payload, signature });
    return Buffer.compare(Buffer.from(payload), Buffer.from(signed)) === 0;
  };
  verifier.calls = calls;
  return verifier;
}

function payload(expiresAt = null) {
  const value = {
    tenant_id: "tenant-a",
    subscription_id: "sub-a",
    plan: { id: "enterprise", version: 1 },
    revision: 1,
    active: true,
    features: { core_sso: true, scim: true, high_availability: true },
    limits: { storage_bytes: { soft: 0, hard: 0, unlimited: true } },
    effective_at: 1_600_000_000,
    generated_at: 1_600_000_000,
  };
  if (expiresAt !== null) value.expires_at = expiresAt;
  return Buffer.from(JSON.stringify(value)).toString("base64");
}

function envelope(body, signature = SIGNATURE, keyId = KEY_ID, algorithm = "Ed25519", version = 1) {
  return JSON.stringify({ version, algorithm, key_id: keyId, payload: body, signature });
}

function trustFor(signed, keyId = KEY_ID) {
  const verifier = verifierFor(signed);
  return { trust: licenseTrustFromKey(keyId, PUBLIC, verifier), verifier };
}

function decode(value) {
  return Buffer.from(value, "base64").toString("utf-8");
}

test("a correctly signed file verifies offline", async () => {
  const body = payload(1_900_000_000);
  const { trust, verifier } = trustFor(decode(body));
  const file = await verifyLicenseFile(envelope(body), trust);
  assert.equal(file.keyId, KEY_ID);
  assert.equal(verifier.calls.length, 1, "the verifier must be consulted exactly once");
  assert.equal(licenseFileState(file, REFERENCE_NOW).kind, "active");
});

test("a tampered payload never verifies", async () => {
  const signed = decode(payload(1_900_000_000));
  const tampered = signed.replace('"scim"', '"SCIM"');
  assert.notEqual(signed, tampered, "the payload must actually differ");
  const { trust } = trustFor(signed);
  await assert.rejects(() => verifyLicenseFile(envelope(Buffer.from(tampered).toString("base64")), trust), {
    code: "license_signature_invalid",
  });
});

test("an untrusted key is refused", async () => {
  const body = payload(1_900_000_000);
  const { trust } = trustFor(decode(body));
  await assert.rejects(() => verifyLicenseFile(envelope(body, SIGNATURE, "someone-elses-key"), trust), {
    code: "license_untrusted_key",
  });
});

test("a caller pinned key is accepted", async () => {
  const body = payload(1_900_000_000);
  const { trust } = trustFor(decode(body), "oem-2026");
  const file = await verifyLicenseFile(envelope(body, SIGNATURE, "oem-2026"), trust);
  assert.equal(file.keyId, "oem-2026");
});

test("an expired file is inactive rather than an error", async () => {
  const body = payload(1_800_000_000);
  const { trust } = trustFor(decode(body));
  const file = await verifyLicenseFile(envelope(body), trust);
  assert.equal(licenseFileState(file, 1_800_000_001).kind, "inactive");
  assert.equal(licenseFileState(file, 1_800_000_001).reason, "expired");
  assert.equal(licenseFileState(file, 1_799_999_999).kind, "active");
});

test("a malformed envelope is an error not an empty entitlement", async () => {
  const { trust } = trustFor(decode(payload()));
  for (const raw of ["", "not json", "{}", '{"version":1}', "[]"]) {
    await assert.rejects(() => verifyLicenseFile(raw, trust), { code: "license_malformed" });
  }
});

test("an unsupported algorithm is rejected before verification", async () => {
  const body = payload(1_900_000_000);
  const { trust, verifier } = trustFor(decode(body));
  for (const algorithm of ["none", "HS256", "Ed448", ""]) {
    await assert.rejects(() => verifyLicenseFile(envelope(body, SIGNATURE, KEY_ID, algorithm), trust), {
      code: "license_algorithm_unsupported",
    });
  }
  assert.equal(verifier.calls.length, 0, "no signature work may happen before the algorithm gate");
});

test("an unsupported envelope version is rejected", async () => {
  const body = payload();
  const { trust } = trustFor(decode(body));
  await assert.rejects(() => verifyLicenseFile(envelope(body, SIGNATURE, KEY_ID, "Ed25519", 99), trust), {
    code: "license_algorithm_unsupported",
  });
});

test("an empty or unconfigured trust root never verifies", async () => {
  const body = payload(1_900_000_000);
  const empty = licenseTrustFromKey(KEY_ID, PUBLIC, verifierFor(decode(body)));
  await assert.rejects(() => verifyLicenseFile(envelope(body), { keys: new Map(), verifier: empty.verifier }), {
    code: "license_trust_unconfigured",
  });
  assert.throws(() => vendorPinnedTrust(), { code: "license_trust_unconfigured" });
});

test("a malformed trust key is rejected rather than stored", () => {
  const keys = new Map();
  assert.throws(() => addLicenseBase64Key(keys, "bad", "not base64!!"), { code: "license_malformed" });
  assert.throws(() => addLicenseBase64Key(keys, "short", Buffer.alloc(8).toString("base64")), {
    code: "license_malformed",
  });
  assert.equal(keys.size, 0, "a rejected key must not widen trust");
});

test("a rejecting verifier is treated as not verified", async () => {
  const body = payload(1_900_000_000);
  const boom = async () => {
    throw new Error("backend unavailable");
  };
  const trust = licenseTrustFromKey(KEY_ID, PUBLIC, boom);
  await assert.rejects(() => verifyLicenseFile(envelope(body), trust), {
    code: "license_signature_invalid",
  });
});

test("trust diagnostics expose only key ids", () => {
  const { trust } = trustFor(decode(payload()));
  assert.deepEqual(trustKeyIds(trust), [KEY_ID]);
});

test("every fixture case is implemented here", () => {
  const fixture = JSON.parse(
    readFileSync(join(HERE, "..", "..", "ops", "build", "sdk-conformance", "license_file.json"), "utf-8"),
  );
  const implemented = new Set([
    "valid_signature",
    "tampered_payload",
    "signature_from_wrong_key",
    "caller_pinned_key",
    "expired_entitlement",
    "malformed_envelope",
    "unsupported_algorithm",
  ]);
  for (const testCase of fixture.cases) {
    assert.ok(implemented.has(testCase.id), `fixture case ${testCase.id} has no test here`);
  }
});
