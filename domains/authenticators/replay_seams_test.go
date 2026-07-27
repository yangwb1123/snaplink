package authenticators_test

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/security"
)

// signKeyPair reproduces a client's signed (key_id, nonce, timestamp) tuple.
func signKeyPair(t *testing.T, priv ed25519.PrivateKey, keyID, nonce string, ts time.Time) (sig, tsStr string) {
	t.Helper()
	tsStr = strconv.FormatInt(ts.Unix(), 10)
	raw := ed25519.Sign(priv, authenticators.CanonicalKeyPairMessage(keyID, nonce, tsStr))
	return base64.RawURLEncoding.EncodeToString(raw), tsStr
}

// keypairReq builds the credential map the authenticator expects.
func keypairReq(keyID, nonce, sig, ts string) *sso.AuthRequest {
	return &sso.AuthRequest{Credential: map[string]string{
		"key_id":    keyID,
		"nonce":     nonce,
		"timestamp": ts,
		"signature": sig,
	}}
}

// erroringReplayStore wraps the real memory store but forces MarkSeen to fail.
// It is a fault-injection fixture (NOT a behavioral mock) used to prove the
// fail-OPEN path: a degraded replay backend must never block a valid login.
type erroringReplayStore struct{}

func (erroringReplayStore) MarkSeen(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("replay backend down")
}

var _ security.JTIReplayStore = erroringReplayStore{}

// ---------- KeyPair nonce replay ----------

func TestKeyPairNonceReplay_RejectedWithStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	resolver := authenticators.NewMemoryPublicKeyStore()
	resolver.Register("svc-1", pub, &sso.Subject{ID: "svc-1"})

	a := authenticators.NewKeyPairAuthenticator(resolver, time.Minute,
		authenticators.WithKeyPairNonceStore(defaultimpl.NewMemoryJTIReplayStore()))

	sig, ts := signKeyPair(t, priv, "svc-1", "nonce-A", time.Now())

	if _, err := a.Authenticate(ctx, keypairReq("svc-1", "nonce-A", sig, ts)); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	// Exact same signed request resubmitted within the clock-skew window.
	if _, err := a.Authenticate(ctx, keypairReq("svc-1", "nonce-A", sig, ts)); err == nil {
		t.Fatal("replay of same nonce within window must be rejected")
	}
}

func TestKeyPairNonceReplay_AllowedWithoutStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	resolver := authenticators.NewMemoryPublicKeyStore()
	resolver.Register("svc-1", pub, &sso.Subject{ID: "svc-1"})

	// No nonce store wired -> historical bounded-window-only behavior.
	a := authenticators.NewKeyPairAuthenticator(resolver, time.Minute)

	sig, ts := signKeyPair(t, priv, "svc-1", "nonce-A", time.Now())
	if _, err := a.Authenticate(ctx, keypairReq("svc-1", "nonce-A", sig, ts)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := a.Authenticate(ctx, keypairReq("svc-1", "nonce-A", sig, ts)); err != nil {
		t.Fatalf("without a store, replay must still succeed (byte-identical): %v", err)
	}
}

func TestKeyPairNonceReplay_FreshNonceStillAuthenticates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	resolver := authenticators.NewMemoryPublicKeyStore()
	resolver.Register("svc-1", pub, &sso.Subject{ID: "svc-1"})

	a := authenticators.NewKeyPairAuthenticator(resolver, time.Minute,
		authenticators.WithKeyPairNonceStore(defaultimpl.NewMemoryJTIReplayStore()))

	sig1, ts1 := signKeyPair(t, priv, "svc-1", "nonce-A", time.Now())
	if _, err := a.Authenticate(ctx, keypairReq("svc-1", "nonce-A", sig1, ts1)); err != nil {
		t.Fatalf("nonce-A: %v", err)
	}
	// A DIFFERENT nonce is not a replay and must authenticate.
	sig2, ts2 := signKeyPair(t, priv, "svc-1", "nonce-B", time.Now())
	if _, err := a.Authenticate(ctx, keypairReq("svc-1", "nonce-B", sig2, ts2)); err != nil {
		t.Fatalf("fresh nonce must authenticate: %v", err)
	}
}

func TestKeyPairNonceReplay_FailOpenOnStoreError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	resolver := authenticators.NewMemoryPublicKeyStore()
	resolver.Register("svc-1", pub, &sso.Subject{ID: "svc-1"})

	a := authenticators.NewKeyPairAuthenticator(resolver, time.Minute,
		authenticators.WithKeyPairNonceStore(erroringReplayStore{}))

	sig, ts := signKeyPair(t, priv, "svc-1", "nonce-A", time.Now())
	if _, err := a.Authenticate(ctx, keypairReq("svc-1", "nonce-A", sig, ts)); err != nil {
		t.Fatalf("store error must fail open (allow valid login): %v", err)
	}
}

// ---------- TOTP code reuse ----------

func TestTOTPCodeReuse_RejectedWithStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := authenticators.NewMemoryTOTPStore()
	secret, _ := authenticators.GenerateTOTPSecret()
	store.Set("alice", secret)

	a := authenticators.NewTOTPAuthenticator(store,
		authenticators.WithTOTPConsumedStore(defaultimpl.NewMemoryJTIReplayStore()))

	code := currentTOTPCode(t, a, secret)
	req := &sso.AuthRequest{Credential: map[string]string{"username": "alice", "code": code}}

	if _, err := a.Authenticate(ctx, req); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	if _, err := a.Authenticate(ctx, req); err == nil {
		t.Fatal("reuse of same code/step must be rejected with a consumed store wired")
	}
}

func TestTOTPCodeReuse_AllowedWithoutStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := authenticators.NewMemoryTOTPStore()
	secret, _ := authenticators.GenerateTOTPSecret()
	store.Set("alice", secret)

	a := authenticators.NewTOTPAuthenticator(store) // no consumed store

	code := currentTOTPCode(t, a, secret)
	req := &sso.AuthRequest{Credential: map[string]string{"username": "alice", "code": code}}

	if _, err := a.Authenticate(ctx, req); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := a.Authenticate(ctx, req); err != nil {
		t.Fatalf("without a store, reuse within the window must still succeed: %v", err)
	}
}

func TestTOTPCodeReuse_FailOpenOnStoreError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := authenticators.NewMemoryTOTPStore()
	secret, _ := authenticators.GenerateTOTPSecret()
	store.Set("alice", secret)

	a := authenticators.NewTOTPAuthenticator(store,
		authenticators.WithTOTPConsumedStore(erroringReplayStore{}))

	code := currentTOTPCode(t, a, secret)
	req := &sso.AuthRequest{Credential: map[string]string{"username": "alice", "code": code}}

	if _, err := a.Authenticate(ctx, req); err != nil {
		t.Fatalf("store error must fail open (allow valid code): %v", err)
	}
	// A confirmed prior consume is fail-CLOSED, but a store ERROR keeps
	// letting a valid code through — the user is never locked out.
	if _, err := a.Authenticate(ctx, req); err != nil {
		t.Fatalf("store error must keep failing open: %v", err)
	}
}

// currentTOTPCode derives the live 6-digit RFC 6238 code for secret directly
// (HMAC-SHA1 over the 30s step counter), the same primitive the authenticator
// computes internally. Asserting it round-trips through the real VerifyCode
// keeps the test bound to the authenticator's own logic, not a re-derivation.
func currentTOTPCode(t *testing.T, a *authenticators.TOTPAuthenticator, secret []byte) string {
	t.Helper()
	step := time.Now().Unix() / 30
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	code := fmt.Sprintf("%06d", bin%1_000_000)
	if !a.VerifyCode(secret, code) {
		t.Fatalf("derived code %q rejected by authenticator", code)
	}
	return code
}
