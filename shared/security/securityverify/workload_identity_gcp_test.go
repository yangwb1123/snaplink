package securityverify

import (
	"context"
	"errors"
	"testing"
	"time"
)

// --- gcpClaimsMapper ---

func TestGCPClaimsMapper_ServiceAccountEmailIsSubject(t *testing.T) {
	t.Parallel()
	id, err := gcpClaimsMapper(map[string]any{
		"sub":   "1234567890",
		"email": "sa@my-project.iam.gserviceaccount.com",
	})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if id.Subject != "sa@my-project.iam.gserviceaccount.com" {
		t.Errorf("subject = %q, want the service-account email", id.Subject)
	}
	if id.Attributes[AttrGCPServiceAccount] != "sa@my-project.iam.gserviceaccount.com" {
		t.Errorf("gcp_service_account attribute missing/wrong: %v", id.Attributes)
	}
}

func TestGCPClaimsMapper_FallsBackToSubWithoutEmail(t *testing.T) {
	t.Parallel()
	// Not every metadata-identity caller is service-account-bound; the
	// mapper must still produce SOME stable subject.
	id, err := gcpClaimsMapper(map[string]any{"sub": "999"})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if id.Subject != "999" {
		t.Errorf("subject = %q, want fallback to sub", id.Subject)
	}
	if _, ok := id.Attributes[AttrGCPServiceAccount]; ok {
		t.Errorf("gcp_service_account attribute should be absent without an email claim")
	}
}

func TestGCPClaimsMapper_MissingSubRejected(t *testing.T) {
	t.Parallel()
	if _, err := gcpClaimsMapper(map[string]any{"email": "x@y.iam.gserviceaccount.com"}); err == nil {
		t.Fatal("expected error for a token with no sub claim")
	}
}

func TestGCPClaimsMapper_ComputeEngineAttributes(t *testing.T) {
	t.Parallel()
	id, err := gcpClaimsMapper(map[string]any{
		"sub":   "1",
		"email": "sa@my-project.iam.gserviceaccount.com",
		"google": map[string]any{
			"compute_engine": map[string]any{
				"project_id":    "my-project",
				"instance_name": "vm-1",
				"zone":          "us-central1-a",
			},
		},
	})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if id.AccountID != "my-project" {
		t.Errorf("AccountID = %q, want my-project", id.AccountID)
	}
	if id.Attributes[AttrGCPProjectID] != "my-project" {
		t.Errorf("gcp_project_id attribute missing")
	}
	if id.Attributes[AttrGCPInstanceName] != "vm-1" {
		t.Errorf("gcp_instance_name attribute missing")
	}
	if id.Attributes[AttrGCPZone] != "us-central1-a" {
		t.Errorf("gcp_zone attribute missing")
	}
}

func TestGCPClaimsMapper_ComputeEngineBlockOptional(t *testing.T) {
	t.Parallel()
	// Absence of the nested google.compute_engine block is NOT a failure —
	// only GCE/GKE-node-issued tokens carry it.
	id, err := gcpClaimsMapper(map[string]any{"sub": "1", "email": "sa@x.iam.gserviceaccount.com"})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if id.AccountID != "" {
		t.Errorf("AccountID = %q, want empty without a compute_engine block", id.AccountID)
	}
}

// --- NewGCPWorkloadIdentityValidator end-to-end ---

func gcpTestClaims(sub, email, aud string, exp time.Duration) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   GCPIssuer,
		"sub":   sub,
		"email": email,
		"aud":   aud,
		"iat":   now.Unix(),
		"exp":   now.Add(exp).Unix(),
	}
}

func TestGCPWorkloadIdentityValidator_HappyPath(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "gcp-1")
	srv := jwksTestServer(t, jwk)
	v, err := NewGCPWorkloadIdentityValidator(NewHTTPJWKSSource(srv.URL))
	if err != nil {
		t.Fatalf("new gcp validator: %v", err)
	}
	if v.Name() != string(CloudProviderGCP) {
		t.Fatalf("Name() = %q, want %q", v.Name(), CloudProviderGCP)
	}

	const aud = "https://sso.example.test"
	claims := gcpTestClaims("1234567890", "sa@my-project.iam.gserviceaccount.com", aud, time.Hour)
	tok := signWITestToken(t, priv, "gcp-1", claims)

	id, err := v.Validate(context.Background(), tok, aud)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if id.Subject != "sa@my-project.iam.gserviceaccount.com" {
		t.Errorf("subject = %q", id.Subject)
	}
	if id.Provider != CloudProviderGCP {
		t.Errorf("provider = %q, want gcp", id.Provider)
	}
}

func TestGCPWorkloadIdentityValidator_WrongIssuerRejected(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "gcp-2")
	srv := jwksTestServer(t, jwk)
	v, err := NewGCPWorkloadIdentityValidator(NewHTTPJWKSSource(srv.URL))
	if err != nil {
		t.Fatalf("new gcp validator: %v", err)
	}

	const aud = "https://sso.example.test"
	claims := gcpTestClaims("1", "sa@x.iam.gserviceaccount.com", aud, time.Hour)
	claims["iss"] = "https://not-google.example.com"
	tok := signWITestToken(t, priv, "gcp-2", claims)

	if _, err := v.Validate(context.Background(), tok, aud); !errors.Is(err, ErrWorkloadIdentityInvalid) {
		t.Fatalf("wrong issuer: err = %v, want ErrWorkloadIdentityInvalid", err)
	}
}

func TestGCPWorkloadIdentityValidator_NilSourceDefaultsToRealGoogleEndpoint(t *testing.T) {
	t.Parallel()
	// Passing nil must not panic or error — it should default to the real
	// Google JWKS endpoint rather than leaving the validator unusable. This
	// test does NOT reach the network (no Validate call); it only proves
	// construction succeeds.
	v, err := NewGCPWorkloadIdentityValidator(nil)
	if err != nil {
		t.Fatalf("new gcp validator with nil source: %v", err)
	}
	if v.Name() != string(CloudProviderGCP) {
		t.Errorf("Name() = %q, want gcp", v.Name())
	}
}
