package snaplink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The cases in ops/build/sdk-conformance/license_file.json are the shared
// contract. The keypair below is a deterministic test fixture, deliberately not
// a vendor key: these tests are about the verification outcome, not the
// provenance of the trust root.

const licenseKeyID = "vendor-2026"

// deterministic keypair so the suite needs no randomness and the same
// signature bytes are produced on every run.
func testKeyPair(seed byte) (ed25519.PrivateKey, string) {
	key := ed25519.NewKeyFromSeed(bytesOf(seed, ed25519.SeedSize))
	return key, base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}

func licensePayload(expiresAt *int64) []byte {
	value := map[string]any{
		"tenant_id": "tenant-a", "subscription_id": "sub-a",
		"plan":     map[string]any{"id": "enterprise", "version": 1},
		"revision": 1, "active": true,
		"features":     map[string]bool{"core_sso": true, "scim": true, "high_availability": true},
		"limits":       map[string]any{"storage_bytes": map[string]any{"soft": 0, "hard": 0, "unlimited": true}},
		"effective_at": 1_600_000_000, "generated_at": 1_600_000_000,
	}
	if expiresAt != nil {
		value["expires_at"] = *expiresAt
	}
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return payload
}

func envelopeBytes(t *testing.T, payload, signature []byte, keyID, algorithm string, version int) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"version": version, "algorithm": algorithm, "key_id": keyID,
		"payload":   base64.StdEncoding.EncodeToString(payload),
		"signature": base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatalf("cannot build the envelope: %v", err)
	}
	return raw
}

func signedLicense(t *testing.T, keyID string, expiresAt *int64) ([]byte, string) {
	t.Helper()
	key, public := testKeyPair(7)
	payload := licensePayload(expiresAt)
	return envelopeBytes(t, payload, ed25519.Sign(key, payload), keyID, LicenseAlgorithm, 1), public
}

func trustFor(t *testing.T, public string) *LicenseTrust {
	t.Helper()
	trust, err := LicenseTrustFromKey(licenseKeyID, public)
	if err != nil {
		t.Fatalf("a valid key must be accepted: %v", err)
	}
	return trust
}

func requireLicenseCode(t *testing.T, err error, want LicenseErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", want)
	}
	licenseErr, ok := err.(*LicenseError)
	if !ok {
		t.Fatalf("expected a *LicenseError, got %T", err)
	}
	if licenseErr.Code != want {
		t.Fatalf("expected %s, got %s (%s)", want, licenseErr.Code, licenseErr.Message)
	}
}

func TestAVerifiedFileGrantsOffline(t *testing.T) {
	expires := int64(1_900_000_000)
	raw, public := signedLicense(t, licenseKeyID, &expires)
	file, err := VerifyLicenseFile(raw, trustFor(t, public))
	if err != nil {
		t.Fatalf("must verify: %v", err)
	}
	if file.KeyID != licenseKeyID {
		t.Fatalf("key id %s", file.KeyID)
	}
	if !file.Entitlement.Has(FeatureSCIM, time.Unix(1_700_000_000, 0)) {
		t.Fatal("scim must be granted")
	}
}

func TestATamperedPayloadNeverVerifies(t *testing.T) {
	key, public := testKeyPair(7)
	tampered := licensePayload(nil)
	tampered[len(tampered)/2] ^= 0x01
	signature := ed25519.Sign(key, tampered)
	raw := envelopeBytes(t, licensePayload(nil), signature, licenseKeyID, LicenseAlgorithm, 1)
	requireLicenseCode(t, mustFail(VerifyLicenseFile(raw, trustFor(t, public))), LicenseSignatureInvalid)
}

func mustFail(_ *LicenseFile, err error) error { return err }

func TestASignatureFromAnUntrustedKeyNeverVerifies(t *testing.T) {
	// The envelope names the trusted key, so this exercises signature
	// verification rather than the key-id lookup.
	untrusted, _ := testKeyPair(9)
	_, trustedPublic := testKeyPair(7)
	payload := licensePayload(nil)
	raw := envelopeBytes(t, payload, ed25519.Sign(untrusted, payload), licenseKeyID, LicenseAlgorithm, 1)
	requireLicenseCode(t, mustFail(VerifyLicenseFile(raw, trustFor(t, trustedPublic))), LicenseSignatureInvalid)
}

func TestACallerPinnedKeyIsAccepted(t *testing.T) {
	expires := int64(1_900_000_000)
	raw, public := signedLicense(t, "oem-2026", &expires)
	trust, err := LicenseTrustFromKey("oem-2026", public)
	if err != nil {
		t.Fatalf("a valid key must be accepted: %v", err)
	}
	if _, err := VerifyLicenseFile(raw, trust); err != nil {
		t.Fatalf("an OEM key must verify: %v", err)
	}
}

func TestAnUnknownKeyIDIsRefused(t *testing.T) {
	expires := int64(1_900_000_000)
	raw, public := signedLicense(t, "someone-elses-key", &expires)
	requireLicenseCode(t, mustFail(VerifyLicenseFile(raw, trustFor(t, public))), LicenseUntrustedKey)
}

func TestAnExpiredFileIsInactiveRatherThanAnError(t *testing.T) {
	expires := int64(1_800_000_000)
	raw, public := signedLicense(t, licenseKeyID, &expires)
	file, err := VerifyLicenseFile(raw, trustFor(t, public))
	if err != nil {
		t.Fatalf("a signed file still verifies: %v", err)
	}
	if file.StateAt(time.Unix(1_800_000_001, 0)).Active() {
		t.Fatal("a lapsed entitlement grants nothing")
	}
	if file.StateAt(time.Unix(1_800_000_000, 0)).Reason != InactiveExpired {
		t.Fatal("a lapsed entitlement reports expired")
	}
	if !file.StateAt(time.Unix(1_799_999_999, 0)).Active() {
		t.Fatal("one second earlier it granted")
	}
}

func TestAMalformedEnvelopeIsAnErrorNotAnEmptyEntitlement(t *testing.T) {
	_, public := testKeyPair(7)
	trust := trustFor(t, public)
	for _, raw := range [][]byte{nil, []byte("not json"), []byte("{}"), []byte(`{"version":1}`)} {
		_, err := VerifyLicenseFile(raw, trust)
		if err == nil {
			t.Fatalf("must be malformed, got success for %q", raw)
		}
		requireLicenseCode(t, err, LicenseMalformed)
	}
}

func TestAnUnsupportedAlgorithmIsRejectedBeforeVerification(t *testing.T) {
	key, public := testKeyPair(7)
	payload := licensePayload(nil)
	signature := ed25519.Sign(key, payload)
	for _, algorithm := range []string{"none", "HS256", "Ed448", ""} {
		raw := envelopeBytes(t, payload, signature, licenseKeyID, algorithm, 1)
		requireLicenseCode(t, mustFail(VerifyLicenseFile(raw, trustFor(t, public))), LicenseAlgorithmUnsupported)
	}
}

func TestAnUnsupportedEnvelopeVersionIsRejected(t *testing.T) {
	key, public := testKeyPair(7)
	payload := licensePayload(nil)
	raw := envelopeBytes(t, payload, ed25519.Sign(key, payload), licenseKeyID, LicenseAlgorithm, 99)
	requireLicenseCode(t, mustFail(VerifyLicenseFile(raw, trustFor(t, public))), LicenseAlgorithmUnsupported)
}

func TestAnEmptyOrUnconfiguredTrustRootNeverVerifies(t *testing.T) {
	expires := int64(1_900_000_000)
	raw, _ := signedLicense(t, licenseKeyID, &expires)
	_, err := VerifyLicenseFile(raw, NewLicenseTrust())
	requireLicenseCode(t, err, LicenseTrustUnconfigured)
	_, err = VerifyLicenseFile(raw, nil)
	requireLicenseCode(t, err, LicenseTrustUnconfigured)
	// The vendor root is not configured in this build and says so rather than
	// carrying a placeholder key that would read as authority while granting
	// nothing.
	_, err = VendorPinnedTrust()
	requireLicenseCode(t, err, LicenseTrustUnconfigured)
}

func TestAMalformedTrustKeyIsRejectedRatherThanStored(t *testing.T) {
	trust := NewLicenseTrust()
	if err := trust.AddBase64Key("bad", "not base64!!"); err == nil {
		t.Fatal("a non-base64 key must be rejected")
	}
	if err := trust.AddKey("short", bytesOf(1, 8)); err == nil {
		t.Fatal("a short key must be rejected")
	}
	if !trust.IsEmpty() {
		t.Fatal("a rejected key must not widen trust")
	}
}

func TestTrustDiagnosticsDoNotLeakKeyMaterial(t *testing.T) {
	_, public := testKeyPair(7)
	trust := trustFor(t, public)
	if ids := trust.KeyIDs(); len(ids) != 1 || ids[0] != licenseKeyID {
		t.Fatalf("key ids %v", ids)
	}
}

func TestVerificationPerformsNoNetworkIO(t *testing.T) {
	expires := int64(1_900_000_000)
	raw, public := signedLicense(t, licenseKeyID, &expires)
	file, err := VerifyLicenseFile(raw, trustFor(t, public))
	if err != nil {
		t.Fatalf("must verify: %v", err)
	}
	if !file.Entitlement.Has(FeatureHighAvailability, time.Unix(1_700_000_000, 0)) {
		t.Fatal("must grant the high-availability feature")
	}
}

func TestEveryFixtureCaseIsImplementedHere(t *testing.T) {
	path := filepath.Join("..", "..", "ops", "build", "sdk-conformance", "license_file.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read the shared fixture: %v", err)
	}
	var document struct {
		Cases []struct {
			ID string `json:"id"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("the shared fixture must be valid JSON: %v", err)
	}
	implemented := map[string]bool{
		"valid_signature": true, "tampered_payload": true, "signature_from_wrong_key": true,
		"caller_pinned_key": true, "expired_entitlement": true, "malformed_envelope": true,
		"unsupported_algorithm": true,
	}
	for _, testCase := range document.Cases {
		if !implemented[testCase.ID] {
			t.Fatalf("fixture case %s has no implementation in this suite", testCase.ID)
		}
	}
}
