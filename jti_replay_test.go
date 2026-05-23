package sso_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// newJARHarnessWithReplay wires the same components as the standard
// JAR harness but also installs a security.JTIReplayStore so we can drive
// RFC 9101 §10.8 replay-defense scenarios.
func newJARHarnessWithReplay(t *testing.T) *jarHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: jarUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    jarClient,
		Secret:                "jar-secret",
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{jarRedirectURI, jarRedirectAlt},
		JWKS: []sso.JWK{{
			Kty: "OKP", Crv: "Ed25519",
			Kid: jarKid,
			Alg: "EdDSA",
			Use: "sig",
			X:   base64.RawURLEncoding.EncodeToString(pub),
		}},
	})
	pwAuth := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == jarUser && p == jarPassword {
				return &sso.AuthResult{UserID: jarUser}, nil
			}
			return nil, errors.New("bad")
		},
	))

	server := sso.NewServer(
		sso.WithIssuer(jarASIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithJTIReplayStore(defaultimpl.NewMemoryJTIReplayStore()),
	)
	httpSrv := httptest.NewServer(server.Handler())
	t.Cleanup(httpSrv.Close)
	return &jarHarness{srv: httpSrv, signKey: priv, pubKey: pub}
}

func TestJAR_ReplayDetectionRejectsSecondUse(t *testing.T) {
	h := newJARHarnessWithReplay(t)
	now := time.Now().Unix()
	jwt := h.signJAR(t, map[string]any{
		"iss":                   jarClient,
		"aud":                   jarASIssuer,
		"iat":                   now,
		"exp":                   now + 60,
		"jti":                   "replay-target-1",
		"client_id":             jarClient,
		"response_type":         "code",
		"redirect_uri":          jarRedirectURI,
		"code_challenge":        jarPKCEInJWT,
		"code_challenge_method": "plain",
	}, jarKid)

	// First sighting: accepted.
	status, body := h.loginJAR(t, jwt)
	if status != http.StatusOK {
		t.Fatalf("first use status=%d body=%v", status, body)
	}

	// Second sighting (replay): MUST be rejected with
	// invalid_request_object — the spec's RECOMMENDED defense
	// against an attacker capturing and re-submitting a valid
	// authorization request JWT.
	status, body = h.loginJAR(t, jwt)
	if status != http.StatusBadRequest {
		t.Fatalf("replay status=%d want 400 body=%v", status, body)
	}
	if body["error"] != sso.ErrInvalidRequestObject {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidRequestObject)
	}
}

func TestJAR_ReplayDefenseOffWithoutStore(t *testing.T) {
	// The default harness has NO replay store wired. RFC 9101 §10.8
	// makes the defense a SHOULD not MUST, so deployments that
	// haven't opted in stay compatible — the same JWT can be
	// presented twice. (Once one is committed somewhere durable like
	// an authorization code, the single-use code semantics provide
	// effective replay defense; the JAR-jti store catches replays
	// BEFORE the code is minted.)
	h := newJARHarness(t)
	now := time.Now().Unix()
	jwt := h.signJAR(t, map[string]any{
		"iss":                   jarClient,
		"aud":                   jarASIssuer,
		"iat":                   now,
		"exp":                   now + 60,
		"jti":                   "no-store-jti",
		"client_id":             jarClient,
		"response_type":         "code",
		"redirect_uri":          jarRedirectURI,
		"code_challenge":        jarPKCEInJWT,
		"code_challenge_method": "plain",
	}, jarKid)
	status1, _ := h.loginJAR(t, jwt)
	status2, _ := h.loginJAR(t, jwt)
	if status1 != http.StatusOK || status2 != http.StatusOK {
		t.Errorf("with no replay store both attempts should succeed; got %d/%d", status1, status2)
	}
}

func TestJAR_ReplayDetectionSkipsWhenJTIAbsent(t *testing.T) {
	// JWT has no jti at all → replay store cannot key on anything
	// → both attempts accepted. RFC 9101 makes jti optional; we
	// don't synthesize one because that would mask client
	// misconfiguration and the protection wouldn't actually apply.
	h := newJARHarnessWithReplay(t)
	now := time.Now().Unix()
	jwt := h.signJAR(t, map[string]any{
		"iss": jarClient,
		"aud": jarASIssuer,
		"iat": now,
		"exp": now + 60,
		// no jti
		"client_id":             jarClient,
		"response_type":         "code",
		"redirect_uri":          jarRedirectURI,
		"code_challenge":        jarPKCEInJWT,
		"code_challenge_method": "plain",
	}, jarKid)
	status1, _ := h.loginJAR(t, jwt)
	status2, _ := h.loginJAR(t, jwt)
	if status1 != http.StatusOK || status2 != http.StatusOK {
		t.Errorf("jti absent should bypass replay defense; got %d/%d", status1, status2)
	}
}

func TestMemoryJTIReplayStore_FirstSightingThenReplay(t *testing.T) {
	store := defaultimpl.NewMemoryJTIReplayStore()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Minute)

	first, err := store.MarkSeen(ctx, "abc", deadline)
	if err != nil {
		t.Fatalf("first MarkSeen err=%v", err)
	}
	if !first {
		t.Errorf("first sighting should report firstSighting=true")
	}

	second, err := store.MarkSeen(ctx, "abc", deadline)
	if err != nil {
		t.Fatalf("second MarkSeen err=%v", err)
	}
	if second {
		t.Errorf("replay should report firstSighting=false")
	}
}

func TestMemoryJTIReplayStore_ExpiredEntryAcceptsResubmission(t *testing.T) {
	store := defaultimpl.NewMemoryJTIReplayStore()
	ctx := context.Background()

	// Mark with an already-elapsed expiry; the store records a
	// 1-second floor so the immediate replay still fails — then
	// after the floor elapses, the same jti can be reused.
	if _, err := store.MarkSeen(ctx, "drift", time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("initial MarkSeen err=%v", err)
	}
	// Wait past the 1-second floor.
	time.Sleep(1100 * time.Millisecond)
	first, err := store.MarkSeen(ctx, "drift", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("post-expiry MarkSeen err=%v", err)
	}
	if !first {
		t.Errorf("expired entry should permit a new firstSighting; got %v", first)
	}
}

func TestMemoryJTIReplayStore_EmptyJTIAlwaysAccepts(t *testing.T) {
	// Empty jti SHOULD short-circuit per the contract — never
	// silently used as a "wildcard never-replay" key.
	store := defaultimpl.NewMemoryJTIReplayStore()
	ctx := context.Background()
	a, _ := store.MarkSeen(ctx, "", time.Now().Add(time.Minute))
	b, _ := store.MarkSeen(ctx, "", time.Now().Add(time.Minute))
	if !a || !b {
		t.Errorf("empty jti must always accept; got %v / %v", a, b)
	}
}
