package snaplink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// This file provides local verification of a signed commercial entitlement
// file. docs/commercial-model.md requires that offline and private deployments
// gate paid features from a signed file, and that authentication never calls a
// vendor licensing service on a login path. The second clause is only
// satisfiable if the SDK can verify the file itself: without a local verifier
// an air-gapped deployment has to call /api/v1/me/account-context, which puts a
// vendor on the login path and violates the rule this file exists to satisfy.
//
// Verification is entirely local and performs no network I/O on any path,
// including login.
//
// The signing private key never enters this package, the repository, or CI, and
// is never transmitted here; only the payload and its signature are. A trust
// root is always supplied by the caller, which is what makes OEM and
// private-CA deployments possible. VendorPinnedTrust is the slot for Snaplink's
// own root and reports an unconfigured error until a release populates it,
// rather than carrying a placeholder key that would look authoritative while
// verifying nothing.
//
// Only one step needs a primitive: checking a signature. Everything else --
// envelope parsing, the algorithm and version gate, the key-id lookup, the
// no-downgrade policy, and the three-state classification -- is identical in
// every SDK and is what the shared conformance fixture pins.

// The only algorithm and envelope version this build accepts.
const (
	LicenseAlgorithm = "Ed25519"
	LicenseVersion   = 1
)

// LicenseErrorCode is the stable code for an entitlement-file failure. These
// originate in the SDK, never on the wire, and are namespaced so a caller
// cannot confuse them with a network failure. None is recoverable by retrying.
type LicenseErrorCode string

// The entitlement-file error vocabulary.
const (
	LicenseMalformed            LicenseErrorCode = "license_malformed"
	LicenseAlgorithmUnsupported LicenseErrorCode = "license_algorithm_unsupported"
	LicenseSignatureInvalid     LicenseErrorCode = "license_signature_invalid"
	LicenseUntrustedKey         LicenseErrorCode = "license_untrusted_key"
	LicenseTrustUnconfigured    LicenseErrorCode = "license_trust_unconfigured"
)

// LicenseError is an entitlement-file verification failure.
type LicenseError struct {
	Code    LicenseErrorCode
	Message string
}

func (e *LicenseError) Error() string {
	return fmt.Sprintf("snaplink: %s: %s", e.Code, e.Message)
}

func licenseErrorf(code LicenseErrorCode, format string, args ...any) *LicenseError {
	return &LicenseError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// LicenseTrust is a set of public keys an entitlement file may be signed by.
//
// A file names the key_id it was signed with, so a deployment can hold a
// current and a next key during rotation without weakening verification.
type LicenseTrust struct {
	keys map[string]ed25519.PublicKey
}

// NewLicenseTrust returns an empty trust root. Every file is rejected until a
// key is added.
func NewLicenseTrust() *LicenseTrust {
	return &LicenseTrust{keys: map[string]ed25519.PublicKey{}}
}

// AddKey trusts a raw 32-byte Ed25519 public key.
//
// A key that fails to decode is rejected rather than stored, so a typo cannot
// silently widen or narrow trust.
func (t *LicenseTrust) AddKey(keyID string, publicKey []byte) error {
	if keyID == "" {
		return licenseErrorf(LicenseMalformed, "key id is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return licenseErrorf(LicenseMalformed, "key %s is not %d bytes", keyID, ed25519.PublicKeySize)
	}
	if t.keys == nil {
		t.keys = map[string]ed25519.PublicKey{}
	}
	stored := make(ed25519.PublicKey, len(publicKey))
	copy(stored, publicKey)
	t.keys[keyID] = stored
	return nil
}

// AddBase64Key trusts a base64 standard-encoded Ed25519 public key.
func (t *LicenseTrust) AddBase64Key(keyID, encoded string) error {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return licenseErrorf(LicenseMalformed, "key %s is not base64: %v", keyID, err)
	}
	return t.AddKey(keyID, raw)
}

// LicenseTrustFromKey is a convenience constructor for a single trusted key.
func LicenseTrustFromKey(keyID, encoded string) (*LicenseTrust, error) {
	trust := NewLicenseTrust()
	if err := trust.AddBase64Key(keyID, encoded); err != nil {
		return nil, err
	}
	return trust, nil
}

// VendorPinnedTrust is Snaplink's own pinned trust root.
//
// It is deliberately not a placeholder key: a hardcoded constant that verifies
// nothing would read as vendor authority while granting nothing. A release
// populates it from the real key.
func VendorPinnedTrust() (*LicenseTrust, error) {
	return nil, licenseErrorf(LicenseTrustUnconfigured, "no vendor trust root is configured in this build")
}

// IsEmpty reports whether any key is trusted.
func (t *LicenseTrust) IsEmpty() bool { return len(t.keys) == 0 }

// KeyIDs returns the trusted key identifiers, sorted, for diagnostics.
func (t *LicenseTrust) KeyIDs() []string {
	ids := make([]string, 0, len(t.keys))
	for id := range t.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (t *LicenseTrust) lookup(keyID string) (ed25519.PublicKey, bool) {
	key, ok := t.keys[keyID]
	return key, ok
}

// LicenseFile is a verified commercial entitlement read from a local file.
type LicenseFile struct {
	Entitlement *Entitlement
	KeyID       string
}

type licenseEnvelope struct {
	// Pointers so a structurally incomplete envelope is reported as malformed
	// rather than silently reading as version 0 with an empty algorithm. The
	// other SDKs report a missing field as malformed, and the shared fixture
	// holds them to one answer.
	Version   *int    `json:"version"`
	Algorithm *string `json:"algorithm"`
	KeyID     *string `json:"key_id"`
	Payload   *string `json:"payload"`
	Signature *string `json:"signature"`
}

// parseLicenseEnvelope decodes the envelope and applies the shape gate.
//
// A structurally incomplete envelope is reported as malformed rather than
// silently reading as version 0 with an empty algorithm: the other SDKs report a
// missing field as malformed, and the shared fixture holds them to one answer.
func parseLicenseEnvelope(raw []byte) (*licenseEnvelope, error) {
	var envelope licenseEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, licenseErrorf(LicenseMalformed, "%v", err)
	}
	if envelope.Version == nil || envelope.Algorithm == nil || envelope.KeyID == nil ||
		envelope.Payload == nil || envelope.Signature == nil {
		return nil, licenseErrorf(LicenseMalformed, "envelope is missing a required field")
	}
	if *envelope.Version != LicenseVersion {
		return nil, licenseErrorf(LicenseAlgorithmUnsupported, "envelope version %d", *envelope.Version)
	}
	if *envelope.Algorithm != LicenseAlgorithm {
		return nil, licenseErrorf(LicenseAlgorithmUnsupported, "%s", *envelope.Algorithm)
	}
	return &envelope, nil
}

// decodeLicenseMaterial decodes the base64 payload and signature and checks the
// signature length.
func decodeLicenseMaterial(envelope *licenseEnvelope) ([]byte, []byte, error) {
	payload, err := base64.StdEncoding.DecodeString(*envelope.Payload)
	if err != nil {
		return nil, nil, licenseErrorf(LicenseMalformed, "payload is not base64: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(*envelope.Signature)
	if err != nil {
		return nil, nil, licenseErrorf(LicenseMalformed, "signature is not base64: %v", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, nil, licenseErrorf(LicenseMalformed, "signature is not %d bytes", ed25519.SignatureSize)
	}
	return payload, signature, nil
}

// VerifyLicenseFile verifies raw against trust and decodes the entitlement it
// carries.
//
// The declared algorithm and version are checked before any signature work, so
// "none" and friends are refused rather than tolerated. Any failure is an
// error; this function never returns an inactive or free-tier entitlement in
// place of a rejected file.
func VerifyLicenseFile(raw []byte, trust *LicenseTrust) (*LicenseFile, error) {
	if trust == nil || trust.IsEmpty() {
		return nil, licenseErrorf(LicenseTrustUnconfigured, "no trust root was supplied")
	}
	envelope, err := parseLicenseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	key, ok := trust.lookup(*envelope.KeyID)
	if !ok {
		return nil, licenseErrorf(LicenseUntrustedKey, "%s", *envelope.KeyID)
	}
	payload, signature, err := decodeLicenseMaterial(envelope)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, payload, signature) {
		return nil, licenseErrorf(LicenseSignatureInvalid, "signature did not verify")
	}
	entitlement, err := NewEntitlement(payload)
	if err != nil {
		return nil, licenseErrorf(LicenseMalformed, "payload is not an entitlement: %v", err)
	}
	return &LicenseFile{Entitlement: entitlement, KeyID: *envelope.KeyID}, nil
}

// StateAt classifies the file's entitlement at now.
//
// The three-state classification is identical to the online path, so a
// deployment that moves between the two does not change behaviour.
func (f *LicenseFile) StateAt(now time.Time) LicenseState {
	return f.Entitlement.StateAt(now)
}
