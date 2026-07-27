package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildauthn"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// These tests pin Bug 3: the SDK exposes WithKeyPairNonceStore /
// WithTOTPConsumedStore, but the shipped cmd binary used to construct the
// keypair + TOTP authenticators WITHOUT them, leaving the default binary
// replay-vulnerable. The regression is at the WIRING layer (build_stores.go),
// so these drive the authenticator that serverbuildauthn.BuildAuthenticators actually returns
// and assert a replay of the same nonce / code is rejected with NO replay
// store configured anywhere — i.e. the defense is on by default.

// findAuth returns the first built authenticator with the given canonical name.
func findAuth(t *testing.T, auths []sso.Authenticator, name string) sso.Authenticator {
	t.Helper()
	for _, a := range auths {
		if a.Name() == name {
			return a
		}
	}
	t.Fatalf("authenticator %q not built", name)
	return nil
}

// TestBuildAuthenticators_KeyPairNonceReplayWiredByDefault proves the
// cmd-built keypair authenticator rejects a replayed (key_id, nonce,
// timestamp) tuple even though the config opts into NOTHING extra — the
// nonce store is wired by default.
func TestBuildAuthenticators_KeyPairNonceReplayWiredByDefault(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	path := filepath.Join(t.TempDir(), "svc.pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Authenticators.KeyPair = &config.KeyPairConfig{
		Enabled: true,
		PublicKeys: []config.KeyPairPublicKeyConfig{{
			KeyID: "svc-1", PublicKeyFile: path, SubjectID: "subject-1",
		}},
	}
	auths, _, _, _, err := serverbuildauthn.BuildAuthenticators(cfg, quietLogger(), nil, nil, nil)
	if err != nil {
		t.Fatalf("serverbuildauthn.BuildAuthenticators: %v", err)
	}
	a := findAuth(t, auths, "keypair")

	ctx := context.Background()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(priv, authenticators.CanonicalKeyPairMessage("svc-1", "nonce-A", ts)))
	req := func() *sso.AuthRequest {
		return &sso.AuthRequest{Credential: map[string]string{
			"key_id": "svc-1", "nonce": "nonce-A", "timestamp": ts, "signature": sig,
		}}
	}

	if _, err := a.Authenticate(ctx, req()); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	// Same signed request replayed within the clock-skew window MUST be
	// rejected because cmd wires the nonce store by default.
	if _, err := a.Authenticate(ctx, req()); err == nil {
		t.Fatal("default cmd binary accepted a keypair nonce replay (Bug 3 regression)")
	}
}

// TestBuildAuthenticators_TOTPConsumedWiredByDefault proves the cmd-built TOTP
// authenticator rejects reuse of the same code within its step window with no
// extra config — the consumed-code store is wired by default.
func TestBuildAuthenticators_TOTPConsumedWiredByDefault(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Authenticators.TOTP = &config.TOTPConfig{Enabled: true}
	// The cmd path builds its OWN secret store internally and surfaces it as the
	// unified MFAEnrollmentStore; enroll a secret through that store so the
	// authenticator can read it back at login, then drive a real login.
	_, _, totpAuth, enrollStore, err := serverbuildauthn.BuildAuthenticators(cfg, quietLogger(), nil, nil, nil)
	if err != nil {
		t.Fatalf("serverbuildauthn.BuildAuthenticators: %v", err)
	}
	if totpAuth == nil || enrollStore == nil {
		t.Fatal("totp authenticator / enrollment store not built")
	}
	ctx := context.Background()
	secret, err := authenticators.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("gen secret: %v", err)
	}
	writer, ok := enrollStore.(sso.TOTPEnrollmentWriter)
	if !ok {
		t.Fatalf("surfaced enrollment store %T is not a TOTPEnrollmentWriter", enrollStore)
	}
	if err := writer.AddTOTPFactor(ctx, "alice", "totp-1", "test", secret); err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	code := liveTOTPCode(t, totpAuth, secret)
	req := &sso.AuthRequest{Credential: map[string]string{"username": "alice", "code": code}}

	if _, err := totpAuth.Authenticate(ctx, req); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	if _, err := totpAuth.Authenticate(ctx, req); err == nil {
		t.Fatal("default cmd binary accepted a TOTP code reuse (Bug 3 regression)")
	}
}

// liveTOTPCode derives the current RFC 6238 code for secret and confirms the
// authenticator accepts it, binding the test to the authenticator's own logic.
func liveTOTPCode(t *testing.T, a *authenticators.TOTPAuthenticator, secret []byte) string {
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
