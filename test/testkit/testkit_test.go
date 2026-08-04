package testkit_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
	"github.com/yangwb1123/snaplink/test/testkit"
)

// TestHarness_LoginAndValidateOverJWKS is the canonical consumer flow: mint a
// REAL token via Login, then validate it the way a downstream resource server
// would — ssoclient/remote against the live JWKS. This exercises the actual
// signature + JWKS path the dev-bypass stubs skip.
func TestHarness_LoginAndValidateOverJWKS(t *testing.T) {
	h := testkit.NewServer()
	defer h.Close()

	res, err := h.Login(context.Background(), testkit.DefaultUsername, testkit.DefaultPassword, "openid")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("login returned no access token")
	}

	auth := remote.NewAuthClient(remote.NewJWKSCache(h.JWKSURL()), remote.WithIssuer(testkit.DefaultIssuer))
	sub, err := auth.ValidateToken(context.Background(), res.AccessToken)
	if err != nil {
		t.Fatalf("downstream ValidateToken over JWKS: %v", err)
	}
	if sub.ID != testkit.DefaultUsername {
		t.Errorf("validated subject = %q, want %q", sub.ID, testkit.DefaultUsername)
	}
}

func TestHarness_CustomUserAndClient(t *testing.T) {
	h := testkit.NewServer(
		testkit.WithClient("my-client", "my-secret", "openid", "profile"),
		testkit.WithUser("bob", "hunter2"),
	)
	defer h.Close()

	if _, err := h.Login(context.Background(), "bob", "hunter2"); err != nil {
		t.Fatalf("custom user login: %v", err)
	}
	// The seed default user is replaced once WithUser is supplied.
	if _, err := h.Login(context.Background(), testkit.DefaultUsername, testkit.DefaultPassword); err == nil {
		t.Error("default user should be absent once WithUser is used")
	}
}

func TestHarness_BadCredentialsRejected(t *testing.T) {
	h := testkit.NewServer()
	defer h.Close()
	if _, err := h.Login(context.Background(), testkit.DefaultUsername, "wrong-password"); err == nil {
		t.Error("a wrong password must fail login")
	}
}

// TestHarness_DirectIssuerMint shows a test minting a token straight off the
// exposed Issuer (no HTTP) and validating it over JWKS — useful when a test
// needs a token with a specific subject/claims it controls.
func TestHarness_DirectIssuerMint(t *testing.T) {
	h := testkit.NewServer()
	defer h.Close()
	tok, err := h.Issuer.Issue(context.Background(), &sso.Subject{
		ID:       "direct-subject",
		ClientID: testkit.DefaultClientID,
	}, []string{"openid"})
	if err != nil {
		t.Fatalf("direct Issue: %v", err)
	}
	auth := remote.NewAuthClient(remote.NewJWKSCache(h.JWKSURL()), remote.WithIssuer(testkit.DefaultIssuer))
	sub, err := auth.ValidateToken(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("validate directly-minted token: %v", err)
	}
	if sub.ID != "direct-subject" {
		t.Errorf("subject = %q, want direct-subject", sub.ID)
	}
}
