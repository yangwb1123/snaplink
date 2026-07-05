package defaultimpl_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/protocols/oidc"
)

// signingUsageValue returns sso_signing_key_usage_total{alg,kid}, or 0 if the
// series hasn't been observed.
func signingUsageValue(t *testing.T, m *metrics.Metrics, alg, kid string) float64 {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metrics.NameSigningUsageTotal {
			continue
		}
		for _, mm := range mf.GetMetric() {
			var gotAlg, gotKid string
			for _, lp := range mm.GetLabel() {
				switch lp.GetName() {
				case metrics.LabelAlg:
					gotAlg = lp.GetValue()
				case metrics.LabelKid:
					gotKid = lp.GetValue()
				}
			}
			if gotAlg == alg && gotKid == kid {
				return mm.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// TestEd25519_SigningUsageMetrics proves every signing entry point
// (Issue/IssueIDToken/IssueLogoutToken/SignJWT) bumps the per-(alg,kid)
// signing-usage counter exactly once per successful sign, and that JWKS —
// which also calls currentKey() but never signs — does NOT.
func TestEd25519_SigningUsageMetrics(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("test-iss"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
		defaultimpl.WithEd25519Metrics(m),
	)
	kid := iss.KeyID()
	ctx := context.Background()

	if _, err := iss.Issue(ctx, &sso.Subject{ID: "u"}, []string{"read"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := iss.IssueIDToken(ctx, &oidc.IDTokenRequest{Subject: "u", Audience: "client"}); err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	if _, err := iss.IssueLogoutToken(ctx, &sso.LogoutTokenRequest{Subject: "u", Audience: "client"}); err != nil {
		t.Fatalf("IssueLogoutToken: %v", err)
	}
	if _, err := iss.SignJWT(ctx, "secevent+jwt", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	// JWKS never signs — must not be counted.
	if _, err := iss.JWKS(ctx); err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	if got := signingUsageValue(t, m, "eddsa", kid); got != 4 {
		t.Errorf("sso_signing_key_usage_total{alg=eddsa,kid=%s} = %v, want 4", kid, got)
	}
}

// TestEd25519_SigningUsageMetrics_NilIsNoop proves omitting WithEd25519Metrics
// (or passing nil) never panics and registers no series.
func TestEd25519_SigningUsageMetrics_NilIsNoop(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Metrics(nil))
	if _, err := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, []string{"read"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
}

func TestECDSA_SigningUsageMetrics(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	iss := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAIssuer("test-iss"),
		defaultimpl.WithECDSAMetrics(m),
	)
	kid := iss.KeyID()
	ctx := context.Background()

	if _, err := iss.Issue(ctx, &sso.Subject{ID: "u"}, []string{"read"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := iss.IssueIDToken(ctx, &oidc.IDTokenRequest{Subject: "u", Audience: "client"}); err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	if _, err := iss.IssueLogoutToken(ctx, &sso.LogoutTokenRequest{Subject: "u", Audience: "client"}); err != nil {
		t.Fatalf("IssueLogoutToken: %v", err)
	}
	if _, err := iss.SignJWT(ctx, "secevent+jwt", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("SignJWT: %v", err)
	}

	if got := signingUsageValue(t, m, "es256", kid); got != 4 {
		t.Errorf("sso_signing_key_usage_total{alg=es256,kid=%s} = %v, want 4", kid, got)
	}
}

func TestRSA_SigningUsageMetrics(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	iss := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("test-iss"),
		defaultimpl.WithRSAAlg("PS256"),
		defaultimpl.WithRSAMetrics(m),
	)
	kid := iss.KeyID()
	ctx := context.Background()

	if _, err := iss.Issue(ctx, &sso.Subject{ID: "u"}, []string{"read"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := iss.IssueIDToken(ctx, &oidc.IDTokenRequest{Subject: "u", Audience: "client"}); err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	if _, err := iss.IssueLogoutToken(ctx, &sso.LogoutTokenRequest{Subject: "u", Audience: "client"}); err != nil {
		t.Fatalf("IssueLogoutToken: %v", err)
	}
	if _, err := iss.SignJWT(ctx, "secevent+jwt", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("SignJWT: %v", err)
	}

	// alg label is lowercased regardless of the RS256/PS256 header spelling.
	if got := signingUsageValue(t, m, "ps256", kid); got != 4 {
		t.Errorf("sso_signing_key_usage_total{alg=ps256,kid=%s} = %v, want 4", kid, got)
	}
}
