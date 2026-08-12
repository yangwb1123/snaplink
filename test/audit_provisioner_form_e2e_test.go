package ssotest

// B4-4 consumer pin (T-8(e) / case 17): the audit provisioner's REAL
// PlatformTokenSource mints client_credentials over the form wire with
// the Content-Type header — so the strict server (415 for JSON/missing
// CT) must serve it a 200 with a non-empty Bearer token. The module
// itself (cmd/snaplink-audit-provisioner) needs zero changes; this test
// proves the compose flip (ops/deploy/compose/config.yaml) is a no-op
// for the provisioner identity wired by ops/deploy/audit-provisioner/
// settings.env (client snaplink-audit-provisioner, resource
// audit-governance, default PlatformProvisioningScope).

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	provisionerClientID = "snaplink-audit-provisioner"
	provisionerSecret   = "provisioner-local-secret"
	provisionerResource = "audit-governance"
)

func TestAuditProvisionerPlatformTokenSourceStrictServer(t *testing.T) {
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: provisionerClientID, Secret: provisionerSecret, Active: true,
		TokenStrategy: "jwt",
	})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCredentialFormOnly(true),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	source, err := auditgovernance.NewPlatformTokenSource(auditgovernance.PlatformTokenConfig{
		TokenURL:              httpSrv.URL + "/token",
		ClientID:              provisionerClientID,
		ClientSecret:          provisionerSecret,
		Resource:              provisionerResource,
		AllowInsecureLoopback: true,
	}, httpSrv.Client())
	if err != nil {
		t.Fatalf("NewPlatformTokenSource: %v", err)
	}

	// No Scope → defaultPlatformTokenConfig pins
	// PlatformProvisioningScope (audit:platform:cross_tenant
	// audit:policy:read audit:policy:write).
	token, err := source.PlatformToken(context.Background())
	if err != nil {
		t.Fatalf("PlatformToken: %v", err)
	}
	if token == "" {
		t.Fatal("empty platform token from strict server")
	}
	// The mint came from the JWT issuer — a Bearer-shaped token.
	if !strings.Contains(token, ".") {
		t.Errorf("token %q does not look like a JWT", token)
	}
}
