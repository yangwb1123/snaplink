// Local verification of a signed commercial entitlement file.
//
// `docs/commercial-model.md` requires that offline and private deployments gate
// paid features from a signed file, and that authentication never calls a
// vendor licensing service on a login path. The second clause is only
// satisfiable if the SDK can verify the file itself: without a local verifier an
// air-gapped deployment has to call `/api/v1/me/account-context`, which puts a
// vendor on the login path and violates the rule this module exists to satisfy.
//
// Verification is entirely local. It performs no network I/O on any path,
// including login.
//
// # Trust roots
//
// The signing private key never enters this package, the repository, or CI, and
// is never transmitted here; only the payload and its signature are. A trust
// root is always supplied by the caller, which is what makes OEM and private-CA
// deployments possible. `vendorPinnedTrust` is the slot for Snaplink's own root
// and reports `license_trust_unconfigured` until a release populates it, rather
// than carrying a placeholder key that would read as vendor authority while
// verifying nothing.
//
// # Why a verifier is supplied
//
// WebCrypto gained Ed25519 only recently and is still unevenly deployed, so this
// package does not assume it. A `LicenseVerifier` is supplied instead: a
// function over the raw public key, the payload bytes, and the signature.
// `navigator.subtle` in a supported runtime, or `@noble/ed25519`, both drop in
// without this package taking a dependency:
//
//     import * as ed from "@noble/curves/ed25519";
//     const verify: LicenseVerifier = async (key, payload, signature) =>
//       ed.verify(signature, payload, key);
//
// Everything except that one primitive — envelope parsing, the algorithm and
// version gate, the key-id lookup, the no-downgrade policy, and the three-state
// classification — is identical in every SDK and is what the shared conformance
// fixture pins.
import { entitlementFromWire, stateAt, } from "./entitlement.js";
/** The only algorithm this build accepts. */
export const ALGORITHM = "Ed25519";
/** The only envelope version this build accepts. */
export const VERSION = 1;
/** Raw Ed25519 public key length in bytes. */
export const PUBLIC_KEY_BYTES = 32;
/** Raw Ed25519 signature length in bytes. */
export const SIGNATURE_BYTES = 64;
/** An entitlement-file verification failure. */
export class LicenseError extends Error {
    code;
    constructor(code, message) {
        super(`${code}: ${message}`);
        this.code = code;
        this.name = "LicenseError";
    }
}
function base64ToBytes(encoded, name) {
    let binary;
    try {
        binary = atob(encoded.trim());
    }
    catch (cause) {
        throw new LicenseError("license_malformed", `${name} is not base64: ${String(cause)}`);
    }
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
}
function bytesToBase64(bytes) {
    let binary = "";
    for (const byte of bytes)
        binary += String.fromCharCode(byte);
    return btoa(binary);
}
/**
 * Add a trusted raw 32-byte Ed25519 public key.
 *
 * A key of the wrong length is rejected rather than stored, so a typo cannot
 * silently widen or narrow trust.
 */
export function addLicenseKey(trust, keyId, publicKey) {
    if (keyId === "")
        throw new LicenseError("license_malformed", "key id is required");
    if (publicKey.length !== PUBLIC_KEY_BYTES) {
        throw new LicenseError("license_malformed", `key ${keyId} is not ${PUBLIC_KEY_BYTES} bytes`);
    }
    trust.set(keyId, new Uint8Array(publicKey));
}
/** Add a trusted base64 standard-encoded Ed25519 public key. */
export function addLicenseBase64Key(trust, keyId, encoded) {
    addLicenseKey(trust, keyId, base64ToBytes(encoded, `key ${keyId}`));
}
/** Build a trust root holding a single key. */
export function licenseTrustFromKey(keyId, publicKey, verifier) {
    const keys = new Map();
    addLicenseBase64Key(keys, keyId, publicKey);
    return { keys, verifier };
}
/**
 * Snaplink's own pinned trust root.
 *
 * Deliberately not a placeholder key: a hardcoded constant that verifies nothing
 * would read as vendor authority while granting nothing. A release populates
 * this from the real key and the supplied verifier.
 */
export function vendorPinnedTrust() {
    throw new LicenseError("license_trust_unconfigured", "no vendor trust root is configured in this build");
}
/** The trusted key identifiers, sorted, for diagnostics. */
export function trustKeyIds(trust) {
    return [...trust.keys.keys()].sort();
}
const REQUIRED_ENVELOPE_FIELDS = ["version", "algorithm", "key_id", "payload", "signature"];
function decodeBase64Strict(encoded, name) {
    if (typeof encoded !== "string") {
        throw new LicenseError("license_malformed", `${name} must be a string`);
    }
    const trimmed = encoded.trim();
    if (trimmed === "" || !/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
        throw new LicenseError("license_malformed", `${name} is not base64`);
    }
    return base64ToBytes(trimmed, name);
}
/**
 * Verify `raw` against `trust` and decode the entitlement it carries.
 *
 * The declared algorithm and version are checked before any signature work, so
 * "none" and friends are refused rather than tolerated. Any failure throws; this
 * function never returns an inactive or free-tier entitlement in place of a
 * rejected file.
 *
 * Asynchronous because a verifier may be backed by WebCrypto, which is async
 * and would otherwise force a dependency on a synchronous implementation.
 */
export async function verifyLicenseFile(raw, trust) {
    if (!trust || trust.keys.size === 0 || typeof trust.verifier !== "function") {
        throw new LicenseError("license_trust_unconfigured", "no trust root was supplied");
    }
    const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
    let envelope;
    try {
        envelope = JSON.parse(text);
    }
    catch (cause) {
        throw new LicenseError("license_malformed", String(cause));
    }
    if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) {
        throw new LicenseError("license_malformed", "envelope must be an object");
    }
    const record = envelope;
    const missing = REQUIRED_ENVELOPE_FIELDS.filter((field) => !(field in record));
    if (missing.length > 0) {
        throw new LicenseError("license_malformed", `envelope is missing ${missing.join(", ")}`);
    }
    if (record.version !== VERSION) {
        throw new LicenseError("license_algorithm_unsupported", `envelope version ${String(record.version)}`);
    }
    if (record.algorithm !== ALGORITHM) {
        throw new LicenseError("license_algorithm_unsupported", String(record.algorithm));
    }
    const keyId = String(record.key_id);
    const key = trust.keys.get(keyId);
    if (key === undefined) {
        throw new LicenseError("license_untrusted_key", keyId);
    }
    const payload = decodeBase64Strict(record.payload, "payload");
    const signature = decodeBase64Strict(record.signature, "signature");
    if (signature.length !== SIGNATURE_BYTES) {
        throw new LicenseError("license_malformed", `signature is not ${SIGNATURE_BYTES} bytes`);
    }
    let verified;
    try {
        verified = await trust.verifier(key, payload, signature);
    }
    catch {
        throw new LicenseError("license_signature_invalid", "verifier failed");
    }
    if (!verified) {
        throw new LicenseError("license_signature_invalid", "signature did not verify");
    }
    let entitlement;
    try {
        entitlement = entitlementFromWire(JSON.parse(new TextDecoder().decode(payload)));
    }
    catch (cause) {
        throw new LicenseError("license_malformed", `payload is not an entitlement: ${String(cause)}`);
    }
    return { entitlement, keyId };
}
/**
 * Classify a verified file's entitlement at `now`.
 *
 * The three-state classification is identical to the online path, so a
 * deployment that moves between the two does not change behaviour.
 */
export function licenseFileState(file, now) {
    return stateAt(file.entitlement, now);
}
/** Re-exported so a caller can build a file from bytes it already parsed. */
export { bytesToBase64 };
