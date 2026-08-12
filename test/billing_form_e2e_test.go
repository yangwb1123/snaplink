package ssotest

// B4-4 consumer pin (requirements §7 clause 5, R7.2): the billing module's
// REAL mints — NewOAuthTokenSource as wired at cmd/snaplink-billing/relay.go
// (audit identity snaplink-relay) and quota_relay.go (quota identity
// snaplink-billing-quota-relay), NewPlatformTokenSource at quota_relay.go
// (retention identity billing-retention-relay) — must mint over the form
// wire against a strict-mode server (sso.WithCredentialFormOnly(true)) with
// zero billing production changes. The option is opt-in default-off, so it
// is mandatory here, not robustness: without it the harness is the legacy
// dual-mode server and the form arm cannot fail.
//
// The JSON control arm is load-bearing (anti-vacuity): both sources hardcode
// the canonical form Content-Type, so strict and legacy servers answer 200
// to them alike. Bind precedes client auth (server_token.go), so the
// form-200 arm proves the credentials valid while the raw-JSON 415 arm
// isolates media-type enforcement; neither arm alone distinguishes CT
// rejection from credential rejection. mintCountingIssuer pins exactly three
// Issue calls after all arms — one per fresh source (three independent
// mutex+singleflight caches; a second call on one instance is zero HTTP) and
// none from the JSON arm.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Production identity wiring copied from cmd/snaplink-billing/
// config.example.env and ops/deploy/compose/config.yaml (the deploy tree
// that already ships require_form_content_type: true).
const (
	billingAuditClientID     = "snaplink-relay"
	billingAuditSecret       = "relay-local-only"
	billingAuditSourcePrefix = "snaplink-billing"
	billingAuditScope        = "audit:event:write"
	billingAuditResource     = "audit-governance"
	billingQuotaClientID     = "snaplink-billing-quota-relay"
	billingQuotaSecret       = "quota-local-only"
	billingQuotaSourcePrefix = "snaplink-billing-quota"
	billingQuotaResource     = "snaplink-sso-quota"
	billingRetentionClientID = "billing-retention-relay"
	billingRetentionSecret   = "retention-secret"
	billingRetentionResource = "audit-governance"
	billingE2ETenantID       = "tenant-a"
	billingE2ETokenPath      = "/token"
)

func TestBillingFormE2E(t *testing.T) {
	clients := defaultimpl.NewMemoryClientStore()
	for _, seed := range []*sso.Client{
		{ID: billingAuditClientID, Secret: billingAuditSecret, Active: true, TokenStrategy: "jwt"},
		{ID: billingQuotaClientID, Secret: billingQuotaSecret, Active: true, TokenStrategy: "jwt"},
		{ID: billingRetentionClientID, Secret: billingRetentionSecret, Active: true, TokenStrategy: "jwt"},
	} {
		clients.AddSeed(seed)
	}
	issuer := &mintCountingIssuer{
		TokenIssuer: defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute)),
	}
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCredentialFormOnly(true), // mandatory: opt-in default-off
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	httpClient := httpSrv.Client()
	ctx := context.Background()

	// Form arm 1: audit relay OAuth source (relay.go buildRelays wiring).
	auditSource, err := auditgovernance.NewOAuthTokenSource(auditgovernance.OAuthTokenConfig{
		TokenURL: httpSrv.URL + billingE2ETokenPath, ClientID: billingAuditClientID,
		ClientSecret: billingAuditSecret, SourcePrefix: billingAuditSourcePrefix,
		Scope: billingAuditScope, Resources: []string{billingAuditResource},
		Timeout: time.Second, AllowInsecureLoopback: true,
	}, httpClient)
	if err != nil {
		t.Fatalf("NewOAuthTokenSource(audit): %v", err)
	}
	auditSourceID, err := auditgovernance.TenantSourceID(billingAuditSourcePrefix, billingE2ETenantID)
	if err != nil {
		t.Fatal(err)
	}
	auditToken, err := auditSource.AccessToken(ctx, auditgovernance.SourceBinding{
		TenantID: billingE2ETenantID, SourceSystem: auditSourceID,
	})
	if err != nil {
		t.Fatalf("audit relay AccessToken against strict server: %v", err)
	}
	assertBillingMint(t, "audit relay", auditToken)

	// Form arm 2: quota OAuth source (quota_relay.go buildQuotaTokenSource
	// wiring).
	quotaSource, err := auditgovernance.NewOAuthTokenSource(auditgovernance.OAuthTokenConfig{
		TokenURL: httpSrv.URL + billingE2ETokenPath, ClientID: billingQuotaClientID,
		ClientSecret: billingQuotaSecret, SourcePrefix: billingQuotaSourcePrefix,
		Scope: core.ScopeTenantQuotaProjectionWrite, Resources: []string{billingQuotaResource},
		Timeout: time.Second, AllowInsecureLoopback: true,
	}, httpClient)
	if err != nil {
		t.Fatalf("NewOAuthTokenSource(quota): %v", err)
	}
	quotaSourceID, err := auditgovernance.TenantSourceID(billingQuotaSourcePrefix, billingE2ETenantID)
	if err != nil {
		t.Fatal(err)
	}
	quotaToken, err := quotaSource.AccessToken(ctx, auditgovernance.SourceBinding{
		TenantID: billingE2ETenantID, SourceSystem: quotaSourceID,
	})
	if err != nil {
		t.Fatalf("quota relay AccessToken against strict server: %v", err)
	}
	assertBillingMint(t, "quota relay", quotaToken)

	// Form arm 3: retention PlatformTokenSource (quota_relay.go
	// withRetentionProjection wiring).
	retentionSource, err := auditgovernance.NewPlatformTokenSource(auditgovernance.PlatformTokenConfig{
		TokenURL: httpSrv.URL + billingE2ETokenPath, ClientID: billingRetentionClientID,
		ClientSecret: billingRetentionSecret, Resource: billingRetentionResource,
		Scope: auditgovernance.PlatformRetentionScope, Timeout: time.Second,
		AllowInsecureLoopback: true,
	}, httpClient)
	if err != nil {
		t.Fatalf("NewPlatformTokenSource: %v", err)
	}
	retentionToken, err := retentionSource.PlatformToken(ctx)
	if err != nil {
		t.Fatalf("retention PlatformToken against strict server: %v", err)
	}
	assertBillingMint(t, "retention", retentionToken)

	// JSON control arm: raw JSON POST to the same TokenURL with the same
	// BasicAuth credentials as the quota source — bind precedes client auth,
	// so a 415 here is media-type enforcement, never a credential oracle,
	// and the mint count proves the arm minted nothing.
	status, raw, hdr := rawPost(t, httpSrv, billingE2ETokenPath, "application/json",
		`{"grant_type":"client_credentials"}`,
		func(r *http.Request) { r.SetBasicAuth(billingQuotaClientID, billingQuotaSecret) })
	assert415(t, status, raw, hdr)

	// Exactly three mints: one per fresh source; the JSON arm minted none
	// (no cache masking — a second call on any one source is zero HTTP).
	if got := issuer.mints.Load(); got != 3 {
		t.Fatalf("Issue calls = %d, want exactly 3 (one per identity, none from the JSON arm)", got)
	}
}

func assertBillingMint(t *testing.T, identity, token string) {
	t.Helper()
	if token == "" {
		t.Fatalf("%s minted an empty token", identity)
	}
	// The mint came from the JWT issuer — a Bearer-shaped token.
	if !strings.Contains(token, ".") {
		t.Errorf("%s token %q does not look like a JWT", identity, token)
	}
}
