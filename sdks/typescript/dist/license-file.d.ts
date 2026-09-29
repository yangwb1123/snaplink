import { type Entitlement, type LicenseState as LicenseStateValue } from "./entitlement.js";
/** The only algorithm this build accepts. */
export declare const ALGORITHM = "Ed25519";
/** The only envelope version this build accepts. */
export declare const VERSION = 1;
/** Raw Ed25519 public key length in bytes. */
export declare const PUBLIC_KEY_BYTES = 32;
/** Raw Ed25519 signature length in bytes. */
export declare const SIGNATURE_BYTES = 64;
/**
 * The stable code for an entitlement-file failure.
 *
 * These originate in the SDK, never on the wire, and are namespaced so a caller
 * cannot confuse them with a network failure. None is recoverable by retrying.
 */
export type LicenseErrorCode = "license_malformed" | "license_algorithm_unsupported" | "license_signature_invalid" | "license_untrusted_key" | "license_trust_unconfigured";
/** An entitlement-file verification failure. */
export declare class LicenseError extends Error {
    readonly code: LicenseErrorCode;
    constructor(code: LicenseErrorCode, message: string);
}
declare function bytesToBase64(bytes: Uint8Array): string;
/**
 * A verifier answers one question: does this signature cover these bytes?
 * It must resolve false rather than reject for a bad signature.
 */
export type LicenseVerifier = (publicKey: Uint8Array, payload: Uint8Array, signature: Uint8Array) => boolean | Promise<boolean>;
/** Public keys an entitlement file may be signed by. */
export interface LicenseTrust {
    readonly keys: ReadonlyMap<string, Uint8Array>;
    readonly verifier: LicenseVerifier;
}
/**
 * Add a trusted raw 32-byte Ed25519 public key.
 *
 * A key of the wrong length is rejected rather than stored, so a typo cannot
 * silently widen or narrow trust.
 */
export declare function addLicenseKey(trust: Map<string, Uint8Array>, keyId: string, publicKey: Uint8Array): void;
/** Add a trusted base64 standard-encoded Ed25519 public key. */
export declare function addLicenseBase64Key(trust: Map<string, Uint8Array>, keyId: string, encoded: string): void;
/** Build a trust root holding a single key. */
export declare function licenseTrustFromKey(keyId: string, publicKey: string, verifier: LicenseVerifier): LicenseTrust;
/**
 * Snaplink's own pinned trust root.
 *
 * Deliberately not a placeholder key: a hardcoded constant that verifies nothing
 * would read as vendor authority while granting nothing. A release populates
 * this from the real key and the supplied verifier.
 */
export declare function vendorPinnedTrust(): never;
/** The trusted key identifiers, sorted, for diagnostics. */
export declare function trustKeyIds(trust: LicenseTrust): string[];
/** A verified commercial entitlement read from a local file. */
export interface EntitlementFile {
    readonly entitlement: Entitlement;
    readonly keyId: string;
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
export declare function verifyLicenseFile(raw: Uint8Array | string, trust: LicenseTrust): Promise<EntitlementFile>;
/**
 * Classify a verified file's entitlement at `now`.
 *
 * The three-state classification is identical to the online path, so a
 * deployment that moves between the two does not change behaviour.
 */
export declare function licenseFileState(file: EntitlementFile, now: number): LicenseStateValue;
/** Re-exported so a caller can build a file from bytes it already parsed. */
export { bytesToBase64 };
export type { Entitlement };
