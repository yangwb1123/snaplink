package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	gw "github.com/go-webauthn/webauthn/webauthn"
)

// softwareAuthenticator is a minimal in-test FIDO2 authenticator: an ECDSA
// P-256 keypair that can mint VALID, signed assertion responses the real
// go-webauthn ValidateLogin accepts. It exists so the regression tests below
// exercise the actual library verification path (no mocks) — the only way to
// drive go-webauthn's UpdateCounter / shouldVerifyUser logic faithfully is to
// feed it a genuinely signed assertion.
type softwareAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
}

func newSoftwareAuthenticator(t *testing.T) *softwareAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("random cred id: %v", err)
	}
	return &softwareAuthenticator{key: key, credID: id}
}

// cosePublicKey returns the credential's public key as the CBOR-COSE blob
// go-webauthn's webauthncose.ParsePublicKey expects (the exact shape stored
// on gw.Credential.PublicKey).
func (a *softwareAuthenticator) cosePublicKey(t *testing.T) []byte {
	t.Helper()
	pub := a.key.PublicKey
	// pub.Bytes() is the uncompressed SEC1 encoding 0x04 || X(32) || Y(32)
	// (Go 1.25+, replacing the deprecated PublicKey.X/.Y). For P-256 each
	// coordinate is already the curve byte length, so no left-pad is needed.
	pubBytes, err := pub.Bytes()
	if err != nil {
		t.Fatalf("ecdsa public key bytes: %v", err)
	}
	x := pubBytes[1:33]
	y := pubBytes[33:65]
	cose := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: x,
		YCoord: y,
	}
	b, err := webauthncbor.Marshal(cose)
	if err != nil {
		t.Fatalf("marshal COSE key: %v", err)
	}
	return b
}

// credential builds the stored gw.Credential for this authenticator with the
// given starting signature counter. AttestationFormat "none"/Flags left zero
// model a typical platform passkey record.
func (a *softwareAuthenticator) credential(t *testing.T, startCounter uint32) *gw.Credential {
	t.Helper()
	return &gw.Credential{
		ID:        a.credID,
		PublicKey: a.cosePublicKey(t),
		Authenticator: gw.Authenticator{
			SignCount: startCounter,
		},
	}
}

// assertJSON produces the navigator.credentials.get() response JSON for the
// given session challenge, asserting signCount and the user-verified bit. It
// is a fully valid, signed assertion the real library accepts (modulo the UV /
// counter conditions under test). When userHandle is non-nil, it is included
// in the response — required for discoverable/conditional login tests.
func (a *softwareAuthenticator) assertJSON(t *testing.T, rpID, origin, challenge string, signCount uint32, userVerified bool, userHandle []byte) string {
	t.Helper()

	clientData := map[string]string{
		"type":      string(protocol.AssertCeremony),
		"challenge": challenge,
		"origin":    origin,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}

	authData := buildAuthenticatorData(rpID, signCount, userVerified)

	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	resp := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(a.credID),
		"rawId": base64.RawURLEncoding.EncodeToString(a.credID),
		"type":  string(protocol.PublicKeyCredentialType),
		"response": map[string]string{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
		},
	}
	if len(userHandle) > 0 {
		resp["response"].(map[string]string)["userHandle"] = base64.RawURLEncoding.EncodeToString(userHandle)
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}
	return string(b)
}

// buildAuthenticatorData lays out the 37-byte assertion authenticator data:
// SHA256(rpID)[32] | flags[1] | signCount[4]. UP is always set; UV is set per
// the userVerified arg. No attested-credential-data / extensions (assertion).
func buildAuthenticatorData(rpID string, signCount uint32, userVerified bool) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	flags := byte(protocol.FlagUserPresent)
	if userVerified {
		flags |= byte(protocol.FlagUserVerified)
	}
	out := make([]byte, 0, 37)
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], signCount)
	out = append(out, counter[:]...)
	return out
}

// enrollAuthenticator seeds a user backed by the given software authenticator
// with a known starting counter, returning the username.
func enrollAuthenticator(t *testing.T, h *Helper, name string, auth *softwareAuthenticator, startCounter uint32) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.users.CreateUser(ctx, name, name); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := h.users.AddCredential(ctx, name, auth.credential(t, startCounter)); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}
}

const (
	testRPID    = "example.com"
	testOrigin  = "https://sso.example.com"
	testRPName  = "Example AS"
	testUserUV  = "alice@example.com"
	testUserCnt = "bob@example.com"
)

func newUVHelper(t *testing.T, requireUV bool) *Helper {
	t.Helper()
	h, err := NewHelper(Config{
		RPID:                    testRPID,
		RPDisplayName:           testRPName,
		RPOrigins:               []string{testOrigin},
		RequireUserVerification: requireUV,
	}, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	return h
}

// sanity check: a fully valid, advancing-counter, UV assertion succeeds.
// Guards the test harness itself — if this fails the regression assertions
// below would pass for the wrong reason.
func TestFinishLogin_ValidAssertionSucceeds(t *testing.T) {
	h := newUVHelper(t, true)
	auth := newSoftwareAuthenticator(t)
	enrollAuthenticator(t, h, testUserUV, auth, 5)
	ctx := context.Background()

	_, sessionID, err := h.BeginLogin(ctx, testUserUV)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	session := mustPeekSession(t, h, ctx, testUserUV)

	// counter advances (6 > 5), UV present.
	body := auth.assertJSON(t, testRPID, testOrigin, session.Challenge, 6, true, nil)
	req := httptest.NewRequest("POST", "/webauthn/login/finish", strings.NewReader(body))
	user, cred, err := h.FinishLogin(ctx, sessionID, req)
	if err != nil {
		t.Fatalf("FinishLogin valid assertion: %v", err)
	}
	if user.Name != testUserUV {
		t.Fatalf("user = %q, want %q", user.Name, testUserUV)
	}
	if cred.Authenticator.SignCount != 6 {
		t.Fatalf("SignCount = %d, want 6 (advanced)", cred.Authenticator.SignCount)
	}
	if cred.Authenticator.CloneWarning {
		t.Fatal("CloneWarning set on a valid advancing-counter assertion")
	}
}

// Bug 1 regression: an assertion whose signature counter does NOT advance
// past the stored value (counter <= stored, non-zero) must be REJECTED with
// ErrClonedAuthenticator — go-webauthn only sets CloneWarning and returns no
// error, so without the wrapper gate this logs in undetected.
func TestFinishLogin_CounterRegressionRejected(t *testing.T) {
	h := newUVHelper(t, true)
	auth := newSoftwareAuthenticator(t)
	enrollAuthenticator(t, h, testUserUV, auth, 10)
	ctx := context.Background()

	_, sessionID, err := h.BeginLogin(ctx, testUserUV)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	session := mustPeekSession(t, h, ctx, testUserUV)

	// Replay/clone: present counter 10, equal to the stored 10 → no advance.
	body := auth.assertJSON(t, testRPID, testOrigin, session.Challenge, 10, true, nil)
	req := httptest.NewRequest("POST", "/webauthn/login/finish", strings.NewReader(body))
	_, _, err = h.FinishLogin(ctx, sessionID, req)
	if !errors.Is(err, ErrClonedAuthenticator) {
		t.Fatalf("got %v, want ErrClonedAuthenticator", err)
	}

	// And the stored counter must NOT have been re-persisted/regressed.
	stored, gerr := h.users.GetByName(ctx, testUserUV)
	if gerr != nil {
		t.Fatalf("GetByName: %v", gerr)
	}
	if stored.Credentials[0].Authenticator.SignCount != 10 {
		t.Fatalf("stored SignCount = %d, want 10 (unchanged)",
			stored.Credentials[0].Authenticator.SignCount)
	}
}

// Bug 1 negative: the all-zero-counter case (stored 0, asserted 0) is the
// common platform-passkey posture; go-webauthn exempts it from CloneWarning,
// so the wrapper MUST accept it. Confirms the gate does not over-reject.
func TestFinishLogin_ZeroCounterPasskeyAccepted(t *testing.T) {
	h := newUVHelper(t, true)
	auth := newSoftwareAuthenticator(t)
	enrollAuthenticator(t, h, testUserUV, auth, 0)
	ctx := context.Background()

	_, sessionID, err := h.BeginLogin(ctx, testUserUV)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	session := mustPeekSession(t, h, ctx, testUserUV)

	body := auth.assertJSON(t, testRPID, testOrigin, session.Challenge, 0, true, nil)
	req := httptest.NewRequest("POST", "/webauthn/login/finish", strings.NewReader(body))
	if _, _, err := h.FinishLogin(ctx, sessionID, req); err != nil {
		t.Fatalf("zero-counter passkey rejected: %v", err)
	}
}

// Bug 2 regression: with RequireUserVerification, an assertion that did NOT
// perform user verification (UV bit clear — mere user-presence) must be
// REJECTED. Before the fix shouldVerifyUser was always false and the UV bit
// went unchecked.
func TestFinishLogin_UserVerificationRequiredRejectsUVMissing(t *testing.T) {
	h := newUVHelper(t, true)
	auth := newSoftwareAuthenticator(t)
	enrollAuthenticator(t, h, testUserUV, auth, 1)
	ctx := context.Background()

	_, sessionID, err := h.BeginLogin(ctx, testUserUV)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	session := mustPeekSession(t, h, ctx, testUserUV)
	if session.UserVerification != protocol.VerificationRequired {
		t.Fatalf("session UV = %q, want %q (BeginLogin must pin UV when required)",
			session.UserVerification, protocol.VerificationRequired)
	}

	// Counter advances (2 > 1) so only the UV bit can cause rejection.
	body := auth.assertJSON(t, testRPID, testOrigin, session.Challenge, 2, false, nil)
	req := httptest.NewRequest("POST", "/webauthn/login/finish", strings.NewReader(body))
	_, _, err = h.FinishLogin(ctx, sessionID, req)
	if err == nil {
		t.Fatal("UV-not-performed assertion accepted under RequireUserVerification")
	}
	// The library surfaces "User verification required but flag not set"; the
	// wrapper wraps it. It must NOT be a clone warning (counter advanced).
	if errors.Is(err, ErrClonedAuthenticator) {
		t.Fatalf("got ErrClonedAuthenticator, want UV-enforcement failure: %v", err)
	}
}

// Bug 2 control: with RequireUserVerification, a UV-performed assertion is
// accepted — proving the gate rejects only the UV-missing case.
func TestFinishLogin_UserVerificationRequiredAcceptsUVPresent(t *testing.T) {
	h := newUVHelper(t, true)
	auth := newSoftwareAuthenticator(t)
	enrollAuthenticator(t, h, testUserUV, auth, 1)
	ctx := context.Background()

	_, sessionID, err := h.BeginLogin(ctx, testUserUV)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	session := mustPeekSession(t, h, ctx, testUserUV)

	body := auth.assertJSON(t, testRPID, testOrigin, session.Challenge, 2, true, nil)
	req := httptest.NewRequest("POST", "/webauthn/login/finish", strings.NewReader(body))
	if _, _, err := h.FinishLogin(ctx, sessionID, req); err != nil {
		t.Fatalf("UV-present assertion rejected: %v", err)
	}
}

// Bug 2: the MFA provider ALWAYS forces UV, independent of the Helper's
// primary-login RequireUserVerification setting. Build the Helper WITHOUT
// RequireUserVerification, drive the step-up via the MFA provider, and a
// UV-missing assertion must still be rejected.
func TestMFAProvider_AlwaysRequiresUserVerification(t *testing.T) {
	h := newUVHelper(t, false) // primary login does NOT require UV
	p, err := NewWebAuthnMFAProvider(h)
	if err != nil {
		t.Fatalf("NewWebAuthnMFAProvider: %v", err)
	}
	auth := newSoftwareAuthenticator(t)
	enrollAuthenticator(t, h, testUserCnt, auth, 1)
	ctx := context.Background()

	data, err := p.Begin(ctx, testUserCnt, MethodWebAuthn)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	sessionID := data["session"]

	// The begun session must demand UV even though the Helper does not.
	session := mustPeekSession(t, h, ctx, testUserCnt)
	if session.UserVerification != protocol.VerificationRequired {
		t.Fatalf("MFA session UV = %q, want %q", session.UserVerification, protocol.VerificationRequired)
	}

	// UV-missing assertion (counter advances) → Verify must fail.
	bad := auth.assertJSON(t, testRPID, testOrigin, session.Challenge, 2, false, nil)
	if err := p.Verify(ctx, testUserCnt, MethodWebAuthn, map[string]string{
		"session":   sessionID,
		"assertion": bad,
	}); err == nil {
		t.Fatal("MFA Verify accepted a UV-missing assertion — second factor must verify the user")
	}
}

// MFA control: a UV-performed assertion satisfies the MFA factor.
func TestMFAProvider_AcceptsUserVerifiedAssertion(t *testing.T) {
	h := newUVHelper(t, false)
	p, err := NewWebAuthnMFAProvider(h)
	if err != nil {
		t.Fatalf("NewWebAuthnMFAProvider: %v", err)
	}
	auth := newSoftwareAuthenticator(t)
	enrollAuthenticator(t, h, testUserCnt, auth, 1)
	ctx := context.Background()

	data, err := p.Begin(ctx, testUserCnt, MethodWebAuthn)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	session := mustPeekSession(t, h, ctx, testUserCnt)

	good := auth.assertJSON(t, testRPID, testOrigin, session.Challenge, 2, true, nil)
	if err := p.Verify(ctx, testUserCnt, MethodWebAuthn, map[string]string{
		"session":   data["session"],
		"assertion": good,
	}); err != nil {
		t.Fatalf("MFA Verify rejected a valid UV assertion: %v", err)
	}
}

// mustPeekSession re-derives the SessionData a BeginLogin just persisted. The
// MemorySessionStore's Take is single-use, so the tests can't read the stored
// session without consuming it; instead this rebuilds the same challenge by
// re-running the library's begin against a clone — but to stay faithful to the
// real session the helper instead reads the one in-flight session directly out
// of the memory store WITHOUT consuming it.
func mustPeekSession(t *testing.T, h *Helper, ctx context.Context, name string) *gw.SessionData {
	t.Helper()
	store, ok := h.sessions.(*MemorySessionStore)
	if !ok {
		t.Fatalf("session store is %T, want *MemorySessionStore", h.sessions)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	// Exactly one ceremony is in flight per test; return its data without
	// deleting the entry so FinishLogin can still consume it.
	var found *gw.SessionData
	for _, e := range store.sessions {
		if found != nil {
			t.Fatal("more than one in-flight session — test expects exactly one")
		}
		found = e.data
	}
	if found == nil {
		t.Fatal("no in-flight session found")
	}
	// The session already carries the challenge + UserID set by BeginLogin;
	// name/ctx are accepted for call-site symmetry with the store SPI.
	_ = name
	_ = ctx
	return found
}
