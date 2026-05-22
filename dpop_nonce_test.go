package sso_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

func newDPoPNonceHarness(t *testing.T, provider sso.DPoPNonceProvider) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: dpopUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: dpopClient, Secret: dpopSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != dpopPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: dpopUser, Provider: "password"}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(
			defaultimpl.WithEd25519Issuer("https://sso.test"),
			defaultimpl.WithEd25519TokenTTL(time.Minute),
		)),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDPoPNonceProvider(provider),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestHMACNonceProvider_IssueVerifyRoundtrip(t *testing.T) {
	p, err := sso.NewHMACNonceProvider(time.Minute)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	n, err := p.Issue()
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := p.Verify(n); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestHMACNonceProvider_RejectsTampered(t *testing.T) {
	p, _ := sso.NewHMACNonceProvider(time.Minute)
	n, _ := p.Issue()
	// Flip the first char so the random-prefix byte changes — any
	// alternative base64url char at index 0 invalidates the MAC.
	// (Avoid flipping the LAST char: in base64url without padding,
	// the final char's two trailing bits are unused, so a flip
	// affecting only those bits decodes to the same byte sequence.
	// The Verify-side Strict() decoder catches that case, but the
	// test stays cleaner if it mutates a position whose every bit
	// is significant.)
	bad := "B" + n[1:]
	if bad == n {
		bad = "C" + n[1:]
	}
	if err := p.Verify(bad); err == nil {
		t.Fatal("Verify accepted tampered nonce")
	}
}

// TestHMACNonceProvider_RejectsLastCharTrailingBitMutation locks in
// the Strict() guard on the wire — flipping the last char to one
// that decodes to the same byte (only the unused trailing bits
// differ) must NOT pass Verify, even though the recomputed MAC
// would match. The original non-Strict decoder had this hole and
// allowed a tamperer to trivially mutate one char without
// detection, making the nonce string non-canonical.
func TestHMACNonceProvider_RejectsLastCharTrailingBitMutation(t *testing.T) {
	p, _ := sso.NewHMACNonceProvider(time.Minute)
	// Loop until we issue a nonce ending in 'A' (low-4-bits-of-last-
	// byte = 0). Then 'B' as the substitute decodes to the same
	// byte (low 4 bits unchanged) but with the unused trailing bits
	// non-zero. Strict() must reject. The loop cap is generous —
	// 1/16 chance per Issue means we hit one quickly.
	var n string
	for i := 0; i < 256; i++ {
		candidate, _ := p.Issue()
		if candidate[len(candidate)-1] == 'A' {
			n = candidate
			break
		}
	}
	if n == "" {
		t.Skip("could not issue a nonce ending in 'A' within 256 tries; vanishingly rare but acceptable to skip")
	}
	bad := n[:len(n)-1] + "B"
	if err := p.Verify(bad); err == nil {
		t.Fatal("Verify accepted mutation that flipped only unused trailing bits — Strict() guard regressed")
	}
}

func TestHMACNonceProvider_RejectsExpired(t *testing.T) {
	p, _ := sso.NewHMACNonceProvider(10 * time.Millisecond)
	n, _ := p.Issue()
	time.Sleep(150 * time.Millisecond)
	if err := p.Verify(n); err == nil {
		t.Fatal("Verify accepted expired nonce")
	}
}

func TestHMACNonceProvider_RejectsMalformed(t *testing.T) {
	p, _ := sso.NewHMACNonceProvider(time.Minute)
	for _, bad := range []string{"", "!!!not-base64!!!", "short"} {
		if err := p.Verify(bad); err == nil {
			t.Errorf("Verify(%q) returned nil, want error", bad)
		}
	}
}

func TestHMACNonceProvider_CrossKeyIsolation(t *testing.T) {
	// Different keys → nonce from one MUST NOT verify with the other.
	p1, _ := sso.NewHMACNonceProvider(time.Minute)
	p2, _ := sso.NewHMACNonceProvider(time.Minute)
	n, _ := p1.Issue()
	if err := p2.Verify(n); err == nil {
		t.Fatal("p2 accepted nonce from p1 — keys must be isolated")
	}
}

func TestHMACNonceProvider_KeyedConstructorAllowsSharedKey(t *testing.T) {
	// Multi-replica use case: same key → both providers accept each
	// other's nonces.
	key := []byte("shared-replica-key-32-bytes-foob")
	p1, err := sso.NewHMACNonceProviderWithKey(key, time.Minute)
	if err != nil {
		t.Fatalf("p1: %v", err)
	}
	p2, err := sso.NewHMACNonceProviderWithKey(key, time.Minute)
	if err != nil {
		t.Fatalf("p2: %v", err)
	}
	n, _ := p1.Issue()
	if err := p2.Verify(n); err != nil {
		t.Fatalf("shared-key cross-verify: %v", err)
	}
}

func TestHMACNonceProvider_KeyTooShort(t *testing.T) {
	if _, err := sso.NewHMACNonceProviderWithKey([]byte("too-short"), time.Minute); err == nil {
		t.Fatal("expected error on short key, got nil")
	}
}

func TestDPoPNonce_TokenEndpointChallengesWithoutNonce(t *testing.T) {
	provider, _ := sso.NewHMACNonceProvider(time.Minute)
	srv := newDPoPNonceHarness(t, provider)

	priv, x := dpopGenKey(t)
	proof := signDPoPProof(t, priv, x, "POST", srv.URL+"/token")
	form := "grant_type=client_credentials&client_id=" + dpopClient + "&client_secret=" + dpopSecret
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (use_dpop_nonce)", resp.StatusCode)
	}
	if got := resp.Header.Get(sso.HeaderDPoPNonce); got == "" {
		t.Fatalf("DPoP-Nonce header empty on challenge")
	}
}

func TestDPoPNonce_TokenEndpointAcceptsValidNonceRetry(t *testing.T) {
	provider, _ := sso.NewHMACNonceProvider(time.Minute)
	srv := newDPoPNonceHarness(t, provider)

	// Step 1: nonce-less request to harvest a nonce.
	priv, x := dpopGenKey(t)
	proof1 := signDPoPProof(t, priv, x, "POST", srv.URL+"/token")
	form := "grant_type=client_credentials&client_id=" + dpopClient + "&client_secret=" + dpopSecret
	req1, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.Header.Set("DPoP", proof1)
	resp1, _ := http.DefaultClient.Do(req1)
	nonce := resp1.Header.Get(sso.HeaderDPoPNonce)
	resp1.Body.Close()
	if nonce == "" {
		t.Fatal("step 1 yielded no nonce")
	}

	// Step 2: retry with the nonce embedded in the proof.
	proof2 := signDPoPProof(t, priv, x, "POST", srv.URL+"/token", func(p map[string]any) {
		p["nonce"] = nonce
	})
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("DPoP", proof2)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("step 2 status=%d want 200 with valid nonce", resp2.StatusCode)
	}
}

func TestDPoPNonce_TokenEndpointRejectsTamperedNonce(t *testing.T) {
	provider, _ := sso.NewHMACNonceProvider(time.Minute)
	srv := newDPoPNonceHarness(t, provider)

	priv, x := dpopGenKey(t)
	proof := signDPoPProof(t, priv, x, "POST", srv.URL+"/token", func(p map[string]any) {
		p["nonce"] = "obviously-not-a-real-nonce"
	})
	form := "grant_type=client_credentials&client_id=" + dpopClient + "&client_secret=" + dpopSecret
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (tampered nonce → fresh challenge)", resp.StatusCode)
	}
	if got := resp.Header.Get(sso.HeaderDPoPNonce); got == "" {
		t.Fatal("DPoP-Nonce missing on tampered-nonce challenge")
	}
}

func TestDPoPNonce_DisabledByDefaultLeavesLegacyPathIntact(t *testing.T) {
	// No WithDPoPNonceProvider → original two-step flow still works
	// with no nonce demanded.
	srv := newDPoPHarness(t)
	priv, x := dpopGenKey(t)
	_ = loginForDPoP(t, srv)
	proof := signDPoPProof(t, priv, x, "POST", srv.URL+"/token")
	status, _ := callTokenWithDPoP(t, srv, proof)
	if status != http.StatusOK {
		t.Fatalf("legacy DPoP path status=%d want 200", status)
	}
}
