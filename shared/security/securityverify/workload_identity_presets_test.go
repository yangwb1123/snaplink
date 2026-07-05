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

// --- awsClaimsMapper ---

func TestAWSClaimsMapper_ServiceAccountSubjectAccepted(t *testing.T) {
	t.Parallel()
	id, err := awsClaimsMapper(map[string]any{"sub": "system:serviceaccount:default:my-sa"})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if id.Subject != "system:serviceaccount:default:my-sa" {
		t.Errorf("subject = %q, want the raw system:serviceaccount sub", id.Subject)
	}
}

func TestAWSClaimsMapper_MissingSubRejected(t *testing.T) {
	t.Parallel()
	if _, err := awsClaimsMapper(map[string]any{}); err == nil {
		t.Fatal("expected error for a token with no sub claim")
	}
}

func TestAWSClaimsMapper_NonServiceAccountSubRejected(t *testing.T) {
	t.Parallel()
	// A `sub` that isn't Kubernetes-service-account-shaped is NOT this
	// preset's identity shape — reject rather than silently accept an
	// arbitrary string as a "stable" subject.
	if _, err := awsClaimsMapper(map[string]any{"sub": "arn:aws:iam::123456789012:role/my-role"}); err == nil {
		t.Fatal("expected error for a non system:serviceaccount sub")
	}
}

func TestAWSClaimsMapper_KubernetesAttributes(t *testing.T) {
	t.Parallel()
	id, err := awsClaimsMapper(map[string]any{
		"sub": "system:serviceaccount:default:my-sa",
		"kubernetes.io": map[string]any{
			"namespace": "default",
			"serviceaccount": map[string]any{
				"name": "my-sa",
				"uid":  "abc-123",
			},
		},
	})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if id.Attributes[AttrAWSNamespace] != "default" {
		t.Errorf("aws_eks_namespace attribute missing/wrong: %v", id.Attributes)
	}
	if id.Attributes[AttrAWSServiceAccountName] != "my-sa" {
		t.Errorf("aws_eks_service_account attribute missing/wrong: %v", id.Attributes)
	}
	if id.Attributes[AttrAWSServiceAccountUID] != "abc-123" {
		t.Errorf("aws_eks_service_account_uid attribute missing/wrong: %v", id.Attributes)
	}
}

func TestAWSClaimsMapper_KubernetesBlockOptional(t *testing.T) {
	t.Parallel()
	// Absence of the nested kubernetes.io block is NOT a failure — the sub
	// claim alone is sufficient to identify the workload.
	id, err := awsClaimsMapper(map[string]any{"sub": "system:serviceaccount:default:my-sa"})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if len(id.Attributes) != 0 {
		t.Errorf("Attributes = %v, want empty without a kubernetes.io block", id.Attributes)
	}
}

// --- NewAWSWorkloadIdentityValidator construction ---

func TestNewAWSWorkloadIdentityValidator_RequiresIssuer(t *testing.T) {
	t.Parallel()
	if _, err := NewAWSWorkloadIdentityValidator("", NewHTTPJWKSSource("https://example.test/jwks")); err == nil {
		t.Fatal("expected error for an empty issuer")
	}
}

func TestNewAWSWorkloadIdentityValidator_DerivesJWKSURLFromIssuer(t *testing.T) {
	t.Parallel()
	const issuer = "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE"
	v, err := NewAWSWorkloadIdentityValidator(issuer, nil)
	if err != nil {
		t.Fatalf("new aws validator: %v", err)
	}
	src, ok := v.source.(*HTTPJWKSSource)
	if !ok {
		t.Fatalf("source = %T, want *HTTPJWKSSource", v.source)
	}
	want := issuer + "/.well-known/jwks.json"
	if src.url != want {
		t.Errorf("derived jwks url = %q, want %q", src.url, want)
	}
}

func TestNewAWSWorkloadIdentityValidator_TrimsTrailingSlashFromIssuer(t *testing.T) {
	t.Parallel()
	v, err := NewAWSWorkloadIdentityValidator("https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE/", nil)
	if err != nil {
		t.Fatalf("new aws validator: %v", err)
	}
	if v.issuer != "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE" {
		t.Errorf("issuer = %q, want trailing slash trimmed", v.issuer)
	}
}

// --- NewAWSWorkloadIdentityValidator end-to-end ---

func awsTestClaims(iss, sub, aud string, exp time.Duration) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": iss,
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(exp).Unix(),
		"kubernetes.io": map[string]any{
			"namespace": "default",
			"serviceaccount": map[string]any{
				"name": "my-sa",
				"uid":  "abc-123",
			},
		},
	}
}

func TestAWSWorkloadIdentityValidator_HappyPath(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "aws-1")
	srv := jwksTestServer(t, jwk)
	const issuer = "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE"
	v, err := NewAWSWorkloadIdentityValidator(issuer, NewHTTPJWKSSource(srv.URL))
	if err != nil {
		t.Fatalf("new aws validator: %v", err)
	}
	if v.Name() != string(CloudProviderAWS) {
		t.Fatalf("Name() = %q, want %q", v.Name(), CloudProviderAWS)
	}

	const aud = "https://sso.example.test"
	claims := awsTestClaims(issuer, "system:serviceaccount:default:my-sa", aud, time.Hour)
	tok := signWITestToken(t, priv, "aws-1", claims)

	id, err := v.Validate(context.Background(), tok, aud)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if id.Subject != "system:serviceaccount:default:my-sa" {
		t.Errorf("subject = %q", id.Subject)
	}
	if id.Provider != CloudProviderAWS {
		t.Errorf("provider = %q, want aws", id.Provider)
	}
	if id.Attributes[AttrAWSServiceAccountName] != "my-sa" {
		t.Errorf("aws_eks_service_account attribute missing: %v", id.Attributes)
	}
}

func TestAWSWorkloadIdentityValidator_WrongIssuerRejected(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "aws-2")
	srv := jwksTestServer(t, jwk)
	const issuer = "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE"
	v, err := NewAWSWorkloadIdentityValidator(issuer, NewHTTPJWKSSource(srv.URL))
	if err != nil {
		t.Fatalf("new aws validator: %v", err)
	}

	const aud = "https://sso.example.test"
	// Signed for a DIFFERENT EKS cluster's issuer — must not be accepted by
	// a validator configured for `issuer`, proving per-cluster issuer
	// binding actually gates acceptance (the whole point of AWS requiring
	// an operator-supplied issuer instead of a fixed global one).
	claims := awsTestClaims("https://oidc.eks.us-west-2.amazonaws.com/id/DIFFERENT", "system:serviceaccount:default:my-sa", aud, time.Hour)
	tok := signWITestToken(t, priv, "aws-2", claims)

	if _, err := v.Validate(context.Background(), tok, aud); !errors.Is(err, ErrWorkloadIdentityInvalid) {
		t.Fatalf("wrong issuer: err = %v, want ErrWorkloadIdentityInvalid", err)
	}
}

func TestAWSWorkloadIdentityValidator_NonServiceAccountSubjectRejected(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "aws-3")
	srv := jwksTestServer(t, jwk)
	const issuer = "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE"
	v, err := NewAWSWorkloadIdentityValidator(issuer, NewHTTPJWKSSource(srv.URL))
	if err != nil {
		t.Fatalf("new aws validator: %v", err)
	}

	const aud = "https://sso.example.test"
	claims := awsTestClaims(issuer, "not-a-service-account", aud, time.Hour)
	tok := signWITestToken(t, priv, "aws-3", claims)

	if _, err := v.Validate(context.Background(), tok, aud); !errors.Is(err, ErrWorkloadIdentityInvalid) {
		t.Fatalf("non-service-account sub: err = %v, want ErrWorkloadIdentityInvalid", err)
	}
}
