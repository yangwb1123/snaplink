package remote_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/ssoclient"
	"github.com/snaplink/sso/ssoclient/remote"
)

// Interface satisfaction guards.
var _ ssoclient.AuthClient = (*remote.AuthClient)(nil)

// signerAndCache returns:
//   - the SDK-side Ed25519 issuer (produces tokens to verify)
//   - a JWKS test server scoped to its public key
//   - the remote AuthClient configured against that server
func signerAndCache(t *testing.T) (*defaultimpl.Ed25519JWTIssuer, *remote.AuthClient, func()) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(priv),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	url, _, stop := jwksServerWithKid(t, pub, iss.KeyID())

	cache := remote.NewJWKSCache(url, remote.WithJWKSRefreshInterval(time.Hour))
	client := remote.NewAuthClient(cache)

	return iss, client, func() {
		cache.Close()
		stop()
	}
}

// jwksServerWithKid is jwksServer parametrized by kid (the SDK issuer
// derives kid from the public key, so we need to match).
func jwksServerWithKid(t *testing.T, pub ed25519.PublicKey, kid string) (string, *int, func()) {
	t.Helper()
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		body := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"` + kid +
			`","x":"` + b64url(pub) + `"}]}`
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(mux)
	return srv.URL + "/.well-known/jwks.json", &hits, srv.Close
}

func b64url(b []byte) string {
	// minimal base64url no-padding encoder. Mirrors what we use in the SDK.
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 0, (len(b)*8+5)/6)
	var buf uint32
	var bits uint
	for _, x := range b {
		buf = (buf << 8) | uint32(x)
		bits += 8
		for bits >= 6 {
			bits -= 6
			out = append(out, tbl[(buf>>bits)&0x3f])
		}
	}
	if bits > 0 {
		out = append(out, tbl[(buf<<(6-bits))&0x3f])
	}
	return string(out)
}

func TestRemoteAuth_ValidateRoundtrip(t *testing.T) {
	iss, client, stop := signerAndCache(t)
	defer stop()

	tok, err := iss.Issue(context.Background(), &sso.Subject{
		ID:     "user-1",
		Claims: map[string]string{"email": "u@example.com"},
	}, []string{"read", "write"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	subj, err := client.ValidateToken(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if subj.ID != "user-1" {
		t.Errorf("Subject.ID = %q", subj.ID)
	}
	if subj.Attrs["email"] != "u@example.com" {
		t.Errorf("attrs lost: %+v", subj.Attrs)
	}
	if len(subj.Scopes) != 2 {
		t.Errorf("scopes = %v", subj.Scopes)
	}
}

func TestRemoteAuth_RejectsTamperedSignature(t *testing.T) {
	iss, client, stop := signerAndCache(t)
	defer stop()
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)

	// Replace the signature segment entirely with another valid-shape one
	// that won't verify. 86 base64url chars = 64 raw bytes of zero.
	zeros := strings.Repeat("A", 86)
	parts := strings.Split(tok.AccessToken, ".")
	bad := parts[0] + "." + parts[1] + "." + zeros

	if _, err := client.ValidateToken(context.Background(), bad); err == nil {
		t.Fatal("tampered signature should fail")
	}
}

func TestRemoteAuth_RejectsMalformedToken(t *testing.T) {
	_, client, stop := signerAndCache(t)
	defer stop()
	for _, s := range []string{"", "abc", "a.b", "a.b.c.d"} {
		if _, err := client.ValidateToken(context.Background(), s); err == nil {
			t.Errorf("ValidateToken(%q) should fail", s)
		}
	}
}

func TestRemoteAuth_RejectsUnknownKid(t *testing.T) {
	// Issue a token from a DIFFERENT issuer whose kid the JWKS doesn't know.
	_, client, stop := signerAndCache(t)
	defer stop()

	other := defaultimpl.NewEd25519JWTIssuer()
	tok, _ := other.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)
	if _, err := client.ValidateToken(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("unknown kid should fail")
	}
}

func TestRemoteAuth_RejectsExpired(t *testing.T) {
	// Issuer with 1ns TTL → instantly expired.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Key(priv),
		defaultimpl.WithEd25519TokenTTL(time.Nanosecond),
	)
	url, _, stop := jwksServerWithKid(t, pub, iss.KeyID())
	defer stop()
	cache := remote.NewJWKSCache(url, remote.WithJWKSRefreshInterval(time.Hour))
	defer cache.Close()
	client := remote.NewAuthClient(cache)

	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)
	time.Sleep(2 * time.Millisecond)
	if _, err := client.ValidateToken(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("expired token should fail")
	}
}

func TestRemoteAuth_LogoutWithoutURLIsNoop(t *testing.T) {
	_, client, stop := signerAndCache(t)
	defer stop()
	// No WithLogoutURL configured → Logout is silent no-op.
	if err := client.Logout(context.Background(), &ssoclient.LogoutRequest{AccessToken: "x"}); err != nil {
		t.Fatalf("Logout without URL: %v", err)
	}
}

func TestRemoteAuth_LogoutCallsConfiguredURL(t *testing.T) {
	calls := 0
	var sawAuth, sawSession string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		sawAuth = r.Header.Get("Authorization")
		// Body is JSON {"session_id":"..."}; cheap parse via substring.
		buf := make([]byte, 200)
		n, _ := r.Body.Read(buf)
		body := string(buf[:n])
		if strings.Contains(body, "sess-1") {
			sawSession = "sess-1"
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, baseClient, stop := signerAndCache(t)
	defer stop()
	_ = baseClient

	// Construct a fresh one with the logout URL set.
	cache := remote.NewJWKSCache("http://unused")
	defer cache.Close()
	client := remote.NewAuthClient(cache, remote.WithLogoutURL(srv.URL))

	if err := client.Logout(context.Background(), &ssoclient.LogoutRequest{
		AccessToken: "tok-123", SessionID: "sess-1",
	}); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 server call, got %d", calls)
	}
	if sawAuth != "Bearer tok-123" {
		t.Errorf("bearer header missing: %q", sawAuth)
	}
	if sawSession != "sess-1" {
		t.Error("session_id not in body")
	}
}
