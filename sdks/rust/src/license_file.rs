//! Local verification of a signed commercial entitlement file.
//!
//! `docs/commercial-model.md` requires that offline and private deployments gate
//! paid features from a signed file, and that authentication never calls a
//! vendor licensing service on a login path. The second clause is only
//! satisfiable if the SDK can verify the file itself: without a local verifier
//! an air-gapped deployment has to call `/api/v1/me/account-context`, which puts
//! a vendor on the login path and violates the rule this module exists to
//! satisfy.
//!
//! Verification is entirely local. It performs no network I/O on any path,
//! including login.
//!
//! # Trust roots
//!
//! The signing private key never enters this crate, the repository, or CI, and is
//! never transmitted here; only the payload and its signature are. A trust root
//! is always supplied by the caller through [`LicenseTrust`], which is what makes
//! OEM and private-CA deployments possible. [`LicenseTrust::vendor_pinned`] is
//! the slot for Snaplink's own root and reports
//! [`LicenseError::TrustUnconfigured`] until a release populates it, rather than
//! carrying a placeholder key that would look authoritative while verifying
//! nothing.
//!
//! # Envelope
//!
//! ```json
//! {
//!   "version": 1,
//!   "algorithm": "Ed25519",
//!   "key_id": "vendor-2026",
//!   "payload": "<base64 standard of the entitlement JSON bytes>",
//!   "signature": "<base64 standard of the Ed25519 signature over those bytes>"
//! }
//! ```
//!
//! The signature covers the decoded payload bytes, not a re-serialisation of
//! them, so verification cannot depend on a canonicalisation rule that two
//! implementations might disagree about.

use crate::entitlement::{Entitlement, LicenseState};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The only algorithm this build accepts.
pub const ALGORITHM: &str = "Ed25519";
/// The only envelope version this build accepts.
pub const VERSION: u32 = 1;

/// Failures specific to entitlement-file verification.
///
/// Distinct from the server error vocabulary: these originate in the SDK, never
/// on the wire, and are namespaced so a caller cannot confuse them with a
/// network failure. None of them is recoverable by retrying.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LicenseError {
    /// The envelope could not be decoded.
    #[error("entitlement file is malformed: {0}")]
    Malformed(String),
    /// The envelope declared an algorithm or version this build does not accept.
    ///
    /// Reported before any signature work, so `algorithm: "none"` is refused
    /// rather than tolerated.
    #[error("entitlement file algorithm is not supported: {0}")]
    AlgorithmUnsupported(String),
    /// The signature did not verify against the trusted key.
    #[error("entitlement file signature did not verify")]
    SignatureInvalid,
    /// No trusted key matches the file's `key_id`.
    #[error("entitlement file names an untrusted key id: {0}")]
    UntrustedKey(String),
    /// The requested trust root is not available in this build.
    #[error("no trust root is configured for entitlement-file verification")]
    TrustUnconfigured,
}

/// A set of public keys an entitlement file may be signed by.
///
/// A file names the `key_id` it was signed with, so a deployment can hold a
/// current and a next key during rotation without weakening verification.
#[derive(Clone, Default)]
pub struct LicenseTrust {
    keys: Vec<(String, VerifyingKey)>,
}

impl std::fmt::Debug for LicenseTrust {
    /// Prints key identifiers only. Public keys are not secret, but a trust root
    /// has no business appearing in a log line.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<&str> = self.keys.iter().map(|(id, _)| id.as_str()).collect();
        formatter
            .debug_struct("LicenseTrust")
            .field("key_ids", &ids)
            .finish()
    }
}

impl LicenseTrust {
    /// An empty trust root. Every file will be rejected until a key is added.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Add a trusted key.
    ///
    /// `public_key` is the raw 32-byte Ed25519 public key, base64 encoded as it
    /// appears in a key listing. A key that fails to decode is rejected rather
    /// than stored, so a typo cannot silently widen or narrow trust.
    pub fn add_key(
        &mut self,
        key_id: impl Into<String>,
        public_key: &str,
    ) -> Result<(), LicenseError> {
        let key_id = key_id.into();
        let raw = BASE64
            .decode(public_key.trim())
            .map_err(|error| LicenseError::Malformed(format!("key {key_id} is not base64: {error}")))?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| LicenseError::Malformed(format!("key {key_id} is not 32 bytes")))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|error| LicenseError::Malformed(format!("key {key_id} is not a valid Ed25519 point: {error}")))?;
        self.keys.retain(|(existing, _)| existing != &key_id);
        self.keys.push((key_id, key));
        Ok(())
    }

    /// Convenience constructor for a single trusted key.
    pub fn from_key(key_id: &str, public_key: &str) -> Result<Self, LicenseError> {
        let mut trust = LicenseTrust::empty();
        trust.add_key(key_id, public_key)?;
        Ok(trust)
    }

    /// Snaplink's own pinned trust root.
    ///
    /// Reports [`LicenseError::TrustUnconfigured`] in this build. It is
    /// deliberately not a placeholder key: a hardcoded constant that verifies
    /// nothing would read as vendor authority while granting nothing.
    pub fn vendor_pinned() -> Result<Self, LicenseError> {
        Err(LicenseError::TrustUnconfigured)
    }

    /// Whether any key is trusted.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The trusted key identifiers, sorted, for diagnostics. A trust root has
    /// no business appearing in a log line, so no key material is printed.
    pub fn key_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.keys.iter().map(|(id, _)| id.as_str()).collect();
        ids.sort_unstable();
        ids
    }

    fn lookup(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys
            .iter()
            .find(|(existing, _)| existing == key_id)
            .map(|(_, key)| key)
    }
}

/// The on-disk envelope.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Envelope {
    version: u32,
    algorithm: String,
    key_id: String,
    payload: String,
    signature: String,
}

/// A verified commercial entitlement read from a local file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntitlementFile {
    /// The entitlement carried by the file.
    pub entitlement: Entitlement,
    /// The `key_id` whose signature verified.
    pub key_id: String,
}

impl EntitlementFile {
    /// Verify `bytes` against `trust` and decode the entitlement it carries.
    ///
    /// Checks the declared algorithm and version before touching the signature,
    /// then verifies against the key the file names. Any failure is an error;
    /// this function never returns an inactive or free-tier entitlement in
    /// place of a rejected file.
    pub fn verify(bytes: &[u8], trust: &LicenseTrust) -> Result<Self, LicenseError> {
        if trust.is_empty() {
            return Err(LicenseError::TrustUnconfigured);
        }
        let envelope: Envelope = serde_json::from_slice(bytes)
            .map_err(|error| LicenseError::Malformed(error.to_string()))?;
        if envelope.version != VERSION {
            return Err(LicenseError::AlgorithmUnsupported(format!(
                "envelope version {}",
                envelope.version
            )));
        }
        if envelope.algorithm != ALGORITHM {
            return Err(LicenseError::AlgorithmUnsupported(envelope.algorithm.clone()));
        }
        let key = trust
            .lookup(&envelope.key_id)
            .ok_or_else(|| LicenseError::UntrustedKey(envelope.key_id.clone()))?;
        let payload = BASE64
            .decode(envelope.payload.trim())
            .map_err(|error| LicenseError::Malformed(format!("payload is not base64: {error}")))?;
        let signature_bytes = BASE64
            .decode(envelope.signature.trim())
            .map_err(|error| LicenseError::Malformed(format!("signature is not base64: {error}")))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|error| LicenseError::Malformed(format!("signature is malformed: {error}")))?;
        key.verify_strict(&payload, &signature)
            .map_err(|_| LicenseError::SignatureInvalid)?;
        let entitlement: Entitlement = serde_json::from_slice(&payload)
            .map_err(|error| LicenseError::Malformed(format!("payload is not an entitlement: {error}")))?;
        Ok(EntitlementFile {
            entitlement,
            key_id: envelope.key_id,
        })
    }

    /// Classify the file's entitlement at `now`, given in Unix seconds.
    ///
    /// The three-state classification is identical to the online path, so a
    /// deployment that moves between the two does not change behaviour.
    pub fn state_at(&self, now: i64) -> LicenseState {
        self.entitlement.state_at(now)
    }
}
