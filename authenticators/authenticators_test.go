package authenticators

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
)

// ---------- helpers ----------

func req(creds map[string]string) *sso.AuthRequest {
	return &sso.AuthRequest{Credential: creds}
}

// ---------- PasswordAuthenticator ----------

func TestPasswordAuthenticator_Success(t *testing.T) {
	v := PasswordVerifierFunc(func(_ context.Context, u, p string) (*sso.AuthResult, error) {
		if u == "alice" && p == "s3cret" {
			return &sso.AuthResult{UserID: "u-alice"}, nil
		}
		return nil, errors.New("nope")
	})
	a := NewPasswordAuthenticator(v)

	if a.Name() != MethodPassword {
		t.Fatalf("Name = %q", a.Name())
	}
	res, err := a.Authenticate(context.Background(), req(map[string]string{
		"username": "alice", "password": "s3cret",
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != "u-alice" {
		t.Errorf("UserID = %q", res.UserID)
	}
	if res.Provider != MethodPassword {
		t.Errorf("Provider default not applied: %q", res.Provider)
	}
	if len(res.AuthMethods) != 1 || res.AuthMethods[0] != AuthMethodPwd {
		t.Errorf("AuthMethods default not applied: %v", res.AuthMethods)
	}
}

func TestPasswordAuthenticator_PreservesVerifierProvider(t *testing.T) {
	// Verifier-set Provider / AuthMethods must NOT be overwritten.
	v := PasswordVerifierFunc(func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
		return &sso.AuthResult{UserID: "u", Provider: "custom", AuthMethods: []string{"mfa", "pwd"}}, nil
	})
	res, _ := NewPasswordAuthenticator(v).Authenticate(context.Background(),
		req(map[string]string{"username": "a", "password": "b"}))
	if res.Provider != "custom" {
		t.Errorf("Provider = %q, want custom (verifier wins)", res.Provider)
	}
	if len(res.AuthMethods) != 2 {
		t.Errorf("AuthMethods = %v, want passthrough", res.AuthMethods)
	}
}

func TestPasswordAuthenticator_MissingCredentials(t *testing.T) {
	a := NewPasswordAuthenticator(PasswordVerifierFunc(func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
		t.Fatal("verifier should not be called on empty creds")
		return nil, nil
	}))
	cases := []map[string]string{
		{"username": "", "password": "x"},
		{"username": "x", "password": ""},
		{},
	}
	for i, c := range cases {
		if _, err := a.Authenticate(context.Background(), req(c)); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestPasswordAuthenticator_VerifierError(t *testing.T) {
	a := NewPasswordAuthenticator(PasswordVerifierFunc(func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
		return nil, errors.New("bad creds")
	}))
	_, err := a.Authenticate(context.Background(), req(map[string]string{
		"username": "a", "password": "b",
	}))
	if err == nil || !strings.Contains(err.Error(), "bad creds") {
		t.Errorf("err = %v, want wrapped bad creds", err)
	}
}

func TestPasswordAuthenticator_CallbackAndLoginURL(t *testing.T) {
	a := NewPasswordAuthenticator(nil)
	if _, err := a.Callback(context.Background(), nil); err == nil {
		t.Error("Callback should not be supported")
	}
	if u := a.LoginURL("state"); u != "" {
		t.Errorf("LoginURL = %q, want empty", u)
	}
}

// ---------- PhoneAuthenticator ----------

type captureSMS struct {
	phone, code string
	err         error
}

func (c *captureSMS) Send(_ context.Context, phone, code string) error {
	c.phone, c.code = phone, code
	return c.err
}

func TestPhoneAuthenticator_RoundTrip(t *testing.T) {
	store := NewMemoryCodeStore()
	sms := &captureSMS{}
	a := NewPhoneAuthenticator(store, sms, WithPhoneCodeLength(8), WithPhoneCodeTTL(time.Minute))

	if a.Name() != MethodPhone {
		t.Fatalf("Name = %q", a.Name())
	}

	if err := a.SendCode(context.Background(), "+15551234567"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if sms.phone != "+15551234567" || len(sms.code) != 8 {
		t.Fatalf("SMS captured = (%q,%q), want (phone, 8-digit code)", sms.phone, sms.code)
	}

	res, err := a.Authenticate(context.Background(), req(map[string]string{
		"phone": "+15551234567", "code": sms.code,
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != subjectPrefixPhone+"+15551234567" {
		t.Errorf("UserID = %q", res.UserID)
	}
	if res.Provider != MethodPhone || res.AuthMethods[0] != AuthMethodSMS {
		t.Errorf("Provider/AuthMethods = %q/%v", res.Provider, res.AuthMethods)
	}

	// Code is consumed — second attempt fails.
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"phone": "+15551234567", "code": sms.code,
	})); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("expected ErrCodeInvalid on replay, got %v", err)
	}
}

func TestPhoneAuthenticator_SendCodeRejectsEmpty(t *testing.T) {
	a := NewPhoneAuthenticator(NewMemoryCodeStore(), &captureSMS{})
	if err := a.SendCode(context.Background(), ""); err == nil {
		t.Error("expected error on empty phone")
	}
}

func TestPhoneAuthenticator_MissingCreds(t *testing.T) {
	a := NewPhoneAuthenticator(NewMemoryCodeStore(), &captureSMS{})
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"phone": "+1", "code": ""})); err == nil {
		t.Error("expected error on missing code")
	}
}

func TestPhoneAuthenticator_WrongCode(t *testing.T) {
	store := NewMemoryCodeStore()
	a := NewPhoneAuthenticator(store, &captureSMS{})
	_ = a.SendCode(context.Background(), "+1")
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"phone": "+1", "code": "000000",
	})); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("expected ErrCodeInvalid, got %v", err)
	}
}

func TestPhoneAuthenticator_SMSErrorPropagates(t *testing.T) {
	a := NewPhoneAuthenticator(NewMemoryCodeStore(), &captureSMS{err: errors.New("sms down")})
	if err := a.SendCode(context.Background(), "+1"); err == nil || !strings.Contains(err.Error(), "sms down") {
		t.Errorf("err = %v, want wrapped sms down", err)
	}
}

func TestPhoneAuthenticator_DefaultsApplied(t *testing.T) {
	a := NewPhoneAuthenticator(NewMemoryCodeStore(), &captureSMS{})
	if a.codeLength != DefaultCodeLength {
		t.Errorf("codeLength = %d, want default %d", a.codeLength, DefaultCodeLength)
	}
	if a.ttl != DefaultPhoneCodeTTL {
		t.Errorf("ttl = %v, want default %v", a.ttl, DefaultPhoneCodeTTL)
	}
}

func TestPhoneAuthenticator_CallbackUnsupported(t *testing.T) {
	a := NewPhoneAuthenticator(NewMemoryCodeStore(), &captureSMS{})
	if _, err := a.Callback(context.Background(), nil); err == nil {
		t.Error("Callback should not be supported")
	}
	if u := a.LoginURL(""); u != "" {
		t.Errorf("LoginURL = %q", u)
	}
}

// ---------- EmailAuthenticator ----------

type captureEmail struct {
	to, code string
}

func (c *captureEmail) Send(_ context.Context, to, code string) error {
	c.to, c.code = to, code
	return nil
}

func TestEmailAuthenticator_RoundTrip(t *testing.T) {
	store := NewMemoryCodeStore()
	em := &captureEmail{}
	a := NewEmailAuthenticator(store, em, WithEmailCodeLength(4), WithEmailCodeTTL(2*time.Minute))

	if err := a.SendCode(context.Background(), "  Alice@Example.COM  "); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	// Normalized to lowercase + trimmed.
	if em.to != "alice@example.com" || len(em.code) != 4 {
		t.Fatalf("Email captured = (%q,%q)", em.to, em.code)
	}

	// Authenticate also normalizes — original casing should still work.
	res, err := a.Authenticate(context.Background(), req(map[string]string{
		"email": "ALICE@example.com", "code": em.code,
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != subjectPrefixEmail+"alice@example.com" {
		t.Errorf("UserID = %q", res.UserID)
	}
	if res.Provider != MethodEmail || res.AuthMethods[0] != AuthMethodEmailOTP {
		t.Errorf("Provider/AuthMethods = %q/%v", res.Provider, res.AuthMethods)
	}
}

func TestEmailAuthenticator_InvalidEmail(t *testing.T) {
	a := NewEmailAuthenticator(NewMemoryCodeStore(), &captureEmail{})
	for _, bad := range []string{"", "no-at-sign", "   "} {
		if err := a.SendCode(context.Background(), bad); err == nil {
			t.Errorf("SendCode(%q) should fail", bad)
		}
	}
}

func TestEmailAuthenticator_AuthenticateMissingCreds(t *testing.T) {
	a := NewEmailAuthenticator(NewMemoryCodeStore(), &captureEmail{})
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"email": "a@b.co"})); err == nil {
		t.Error("expected error on missing code")
	}
}

func TestEmailAuthenticator_CallbackUnsupported(t *testing.T) {
	a := NewEmailAuthenticator(NewMemoryCodeStore(), &captureEmail{})
	if _, err := a.Callback(context.Background(), nil); err == nil {
		t.Error("Callback should not be supported")
	}
	if u := a.LoginURL(""); u != "" {
		t.Errorf("LoginURL = %q", u)
	}
}

// ---------- TempTokenAuthenticator ----------

func TestTempTokenAuthenticator_RoundTrip(t *testing.T) {
	store := NewMemoryTempTokenStore()
	a := NewTempTokenAuthenticator(store, time.Minute)

	if a.Name() != MethodTempToken {
		t.Fatalf("Name = %q", a.Name())
	}

	token, err := a.Issue(context.Background(), &sso.Subject{ID: "u-bob", Claims: map[string]string{"role": "viewer"}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(token) < 16 {
		t.Errorf("token too short: %q", token)
	}

	res, err := a.Authenticate(context.Background(), req(map[string]string{"token": token}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != "u-bob" || res.Attributes["role"] != "viewer" {
		t.Errorf("result = %+v", res)
	}
	if res.AuthMethods[0] != AuthMethodOTPLink {
		t.Errorf("AuthMethods = %v", res.AuthMethods)
	}

	// Single-use: second consume must fail.
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"token": token})); err == nil {
		t.Error("expected error on token reuse")
	}
}

func TestTempTokenAuthenticator_DefaultTTL(t *testing.T) {
	a := NewTempTokenAuthenticator(NewMemoryTempTokenStore(), 0)
	if a.ttl != DefaultTempTokenTTL {
		t.Errorf("ttl = %v, want default %v", a.ttl, DefaultTempTokenTTL)
	}
}

func TestTempTokenAuthenticator_IssueRequiresSubject(t *testing.T) {
	a := NewTempTokenAuthenticator(NewMemoryTempTokenStore(), time.Minute)
	if _, err := a.Issue(context.Background(), nil); err == nil {
		t.Error("expected error on nil subject")
	}
	if _, err := a.Issue(context.Background(), &sso.Subject{}); err == nil {
		t.Error("expected error on empty subject ID")
	}
}

func TestTempTokenAuthenticator_AuthenticateMissingToken(t *testing.T) {
	a := NewTempTokenAuthenticator(NewMemoryTempTokenStore(), time.Minute)
	if _, err := a.Authenticate(context.Background(), req(map[string]string{})); err == nil {
		t.Error("expected error on missing token")
	}
}

func TestTempTokenAuthenticator_UnknownToken(t *testing.T) {
	a := NewTempTokenAuthenticator(NewMemoryTempTokenStore(), time.Minute)
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"token": "made-up"})); err == nil {
		t.Error("expected error on unknown token")
	}
}

func TestTempTokenAuthenticator_CallbackUnsupported(t *testing.T) {
	a := NewTempTokenAuthenticator(NewMemoryTempTokenStore(), time.Minute)
	if _, err := a.Callback(context.Background(), nil); err == nil {
		t.Error("Callback should not be supported")
	}
	if u := a.LoginURL(""); u != "" {
		t.Errorf("LoginURL = %q", u)
	}
}

// ---------- APIKeyAuthenticator ----------

func TestAPIKeyAuthenticator_RoundTrip(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	store.Register("k1", "secret-v1", &sso.Subject{ID: "svc-a", Claims: map[string]string{"team": "platform"}})
	a := NewAPIKeyAuthenticator(store)

	if a.Name() != MethodAPIKey {
		t.Fatalf("Name = %q", a.Name())
	}

	res, err := a.Authenticate(context.Background(), req(map[string]string{
		"key_id": "k1", "secret": "secret-v1",
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != "svc-a" || res.ExternalID != "k1" {
		t.Errorf("UserID/ExternalID = %q/%q", res.UserID, res.ExternalID)
	}
	if res.Attributes["team"] != "platform" {
		t.Errorf("attrs not passthrough: %v", res.Attributes)
	}
	if res.AuthMethods[0] != AuthMethodAPIKey {
		t.Errorf("AuthMethods = %v", res.AuthMethods)
	}
}

func TestAPIKeyAuthenticator_DefaultSubject(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	store.Register("k2", "s2", nil) // no subject provided
	a := NewAPIKeyAuthenticator(store)
	res, err := a.Authenticate(context.Background(), req(map[string]string{"key_id": "k2", "secret": "s2"}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	want := subjectPrefixAPIKey + "k2"
	if res.UserID != want {
		t.Errorf("UserID = %q, want %q", res.UserID, want)
	}
}

func TestAPIKeyAuthenticator_BadSecret(t *testing.T) {
	store := NewMemoryAPIKeyStore()
	store.Register("k", "right", &sso.Subject{ID: "s"})
	a := NewAPIKeyAuthenticator(store)
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"key_id": "k", "secret": "wrong"})); err == nil {
		t.Error("expected error on bad secret")
	}
}

func TestAPIKeyAuthenticator_UnknownKey(t *testing.T) {
	a := NewAPIKeyAuthenticator(NewMemoryAPIKeyStore())
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"key_id": "?", "secret": "?"})); err == nil {
		t.Error("expected error on unknown key")
	}
}

func TestAPIKeyAuthenticator_MissingCreds(t *testing.T) {
	a := NewAPIKeyAuthenticator(NewMemoryAPIKeyStore())
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"key_id": "k"})); err == nil {
		t.Error("expected error on missing secret")
	}
}

func TestAPIKeyAuthenticator_CallbackUnsupported(t *testing.T) {
	a := NewAPIKeyAuthenticator(NewMemoryAPIKeyStore())
	if _, err := a.Callback(context.Background(), nil); err == nil {
		t.Error("Callback should not be supported")
	}
	if u := a.LoginURL(""); u != "" {
		t.Errorf("LoginURL = %q", u)
	}
}

// ---------- KeyPairAuthenticator ----------

func signKeyPair(t *testing.T, priv ed25519.PrivateKey, keyID, nonce string, ts time.Time) (string, string) {
	t.Helper()
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	sig := ed25519.Sign(priv, CanonicalKeyPairMessage(keyID, nonce, tsStr))
	return base64.RawURLEncoding.EncodeToString(sig), tsStr
}

func TestKeyPairAuthenticator_RoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := NewMemoryPublicKeyStore()
	store.Register("svc-key-1", pub, &sso.Subject{ID: "svc-a", Claims: map[string]string{"team": "infra"}})

	a := NewKeyPairAuthenticator(store, time.Minute)
	if a.Name() != MethodKeyPair {
		t.Fatalf("Name = %q", a.Name())
	}

	sig, ts := signKeyPair(t, priv, "svc-key-1", "n0nce", time.Now())
	res, err := a.Authenticate(context.Background(), req(map[string]string{
		"key_id":    "svc-key-1",
		"nonce":     "n0nce",
		"timestamp": ts,
		"signature": sig,
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != "svc-a" || res.ExternalID != "svc-key-1" {
		t.Errorf("UserID/ExternalID = %q/%q", res.UserID, res.ExternalID)
	}
	if res.AuthMethods[0] != AuthMethodSig {
		t.Errorf("AuthMethods = %v", res.AuthMethods)
	}
	if res.Attributes["team"] != "infra" {
		t.Errorf("attrs = %v", res.Attributes)
	}
}

func TestKeyPairAuthenticator_DefaultSubject(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := NewMemoryPublicKeyStore()
	store.Register("k", pub, nil)
	a := NewKeyPairAuthenticator(store, time.Minute)
	sig, ts := signKeyPair(t, priv, "k", "n", time.Now())
	res, err := a.Authenticate(context.Background(), req(map[string]string{
		"key_id": "k", "nonce": "n", "timestamp": ts, "signature": sig,
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	want := subjectPrefixKeyPair + "k"
	if res.UserID != want {
		t.Errorf("UserID = %q, want %q", res.UserID, want)
	}
}

func TestKeyPairAuthenticator_DefaultClockSkew(t *testing.T) {
	a := NewKeyPairAuthenticator(NewMemoryPublicKeyStore(), 0)
	if a.maxClockSkew != DefaultKeyPairClockSkew {
		t.Errorf("maxClockSkew = %v, want default %v", a.maxClockSkew, DefaultKeyPairClockSkew)
	}
}

func TestKeyPairAuthenticator_StaleTimestamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := NewMemoryPublicKeyStore()
	store.Register("k", pub, &sso.Subject{ID: "s"})
	a := NewKeyPairAuthenticator(store, time.Second) // tight skew window
	sig, ts := signKeyPair(t, priv, "k", "n", time.Now().Add(-time.Hour))
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"key_id": "k", "nonce": "n", "timestamp": ts, "signature": sig,
	})); err == nil {
		t.Error("expected stale-timestamp error")
	}
}

func TestKeyPairAuthenticator_BadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	store := NewMemoryPublicKeyStore()
	store.Register("k", pub, &sso.Subject{ID: "s"})
	a := NewKeyPairAuthenticator(store, time.Minute)
	// Use a totally different key to sign.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	sig, ts := signKeyPair(t, otherPriv, "k", "n", time.Now())
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"key_id": "k", "nonce": "n", "timestamp": ts, "signature": sig,
	})); err == nil {
		t.Error("expected verification failure")
	}
}

func TestKeyPairAuthenticator_BadTimestampFormat(t *testing.T) {
	a := NewKeyPairAuthenticator(NewMemoryPublicKeyStore(), time.Minute)
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"key_id": "k", "nonce": "n", "timestamp": "not-a-number", "signature": "aaa",
	})); err == nil {
		t.Error("expected invalid-timestamp error")
	}
}

func TestKeyPairAuthenticator_MissingFields(t *testing.T) {
	a := NewKeyPairAuthenticator(NewMemoryPublicKeyStore(), time.Minute)
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"key_id": "k", "nonce": "n",
	})); err == nil {
		t.Error("expected missing-field error")
	}
}

func TestKeyPairAuthenticator_UnknownKeyID(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := NewKeyPairAuthenticator(NewMemoryPublicKeyStore(), time.Minute)
	sig, ts := signKeyPair(t, priv, "k", "n", time.Now())
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"key_id": "k", "nonce": "n", "timestamp": ts, "signature": sig,
	})); err == nil {
		t.Error("expected unknown-key error")
	}
}

func TestKeyPairAuthenticator_StdBase64SignatureAccepted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := NewMemoryPublicKeyStore()
	store.Register("k", pub, &sso.Subject{ID: "s"})
	a := NewKeyPairAuthenticator(store, time.Minute)

	ts := time.Now()
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	sig := ed25519.Sign(priv, CanonicalKeyPairMessage("k", "n", tsStr))
	stdB64 := base64.StdEncoding.EncodeToString(sig) // not URL-safe

	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"key_id": "k", "nonce": "n", "timestamp": tsStr, "signature": stdB64,
	})); err != nil {
		t.Errorf("std base64 should fall through: %v", err)
	}
}

func TestKeyPairAuthenticator_BadBase64(t *testing.T) {
	a := NewKeyPairAuthenticator(NewMemoryPublicKeyStore(), time.Minute)
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"key_id": "k", "nonce": "n", "timestamp": strconv.FormatInt(time.Now().Unix(), 10),
		"signature": "!!!not-base64!!!",
	})); err == nil {
		t.Error("expected base64 decode error")
	}
}

func TestKeyPairAuthenticator_CallbackUnsupported(t *testing.T) {
	a := NewKeyPairAuthenticator(NewMemoryPublicKeyStore(), time.Minute)
	if _, err := a.Callback(context.Background(), nil); err == nil {
		t.Error("Callback should not be supported")
	}
	if u := a.LoginURL(""); u != "" {
		t.Errorf("LoginURL = %q", u)
	}
}

func TestCanonicalKeyPairMessage_Stable(t *testing.T) {
	msg := CanonicalKeyPairMessage("k", "n", "1700000000")
	want := "k" + keyPairMessageSeparator + "n" + keyPairMessageSeparator + "1700000000"
	if string(msg) != want {
		t.Errorf("got %q want %q", msg, want)
	}
}

func TestParseEd25519PublicKeyPEM(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	parsed, err := ParseEd25519PublicKeyPEM(pemBlock)
	if err != nil {
		t.Fatalf("ParseEd25519PublicKeyPEM: %v", err)
	}
	if !parsed.Equal(pub) {
		t.Error("parsed key does not match original")
	}

	if _, err := ParseEd25519PublicKeyPEM([]byte("not pem")); err == nil {
		t.Error("expected error on non-PEM input")
	}

	// PEM that decodes but isn't an Ed25519 key.
	rsaPub := []byte("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n")
	if _, err := ParseEd25519PublicKeyPEM(rsaPub); err == nil {
		t.Error("expected error on malformed DER")
	}

	// PEM holding a non-Ed25519 key (ECDSA) → wrong-type branch.
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDer, _ := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	ecPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDer})
	if _, err := ParseEd25519PublicKeyPEM(ecPem); err == nil {
		t.Error("expected error on non-Ed25519 key type")
	}
}

// ---------- CertificateAuthenticator ----------

// issueCertChain mints a self-signed CA + a leaf cert signed by it. Returns
// the leaf in PEM form and a CertPool containing only the CA.
func issueCertChain(t *testing.T, cn string) (leafPEM []byte, roots *x509.CertPool) {
	t.Helper()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDer)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: []string{cn + "@example.com"},
		DNSNames:       []string{cn + ".example.com"},
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDer})

	roots = x509.NewCertPool()
	roots.AddCert(caCert)
	return leafPEM, roots
}

func TestCertificateAuthenticator_Success(t *testing.T) {
	leafPEM, roots := issueCertChain(t, "client-1")
	a := NewCertificateAuthenticator(roots)

	if a.Name() != MethodCertificate {
		t.Fatalf("Name = %q", a.Name())
	}

	res, err := a.Authenticate(context.Background(), req(map[string]string{
		"certificate": string(leafPEM),
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != subjectPrefixCert+"client-1" {
		t.Errorf("UserID = %q", res.UserID)
	}
	if res.ExternalID != "client-1" {
		t.Errorf("ExternalID = %q", res.ExternalID)
	}
	if res.Attributes["cn"] != "client-1" || res.Attributes["email"] != "client-1@example.com" {
		t.Errorf("attrs = %v", res.Attributes)
	}
	if res.AuthMethods[0] != AuthMethodX509 {
		t.Errorf("AuthMethods = %v", res.AuthMethods)
	}
}

func TestCertificateAuthenticator_CustomIdentity(t *testing.T) {
	leafPEM, roots := issueCertChain(t, "client-2")
	a := NewCertificateAuthenticator(roots, WithCertIdentity(func(c *x509.Certificate) *sso.Subject {
		return &sso.Subject{ID: "override:" + c.Subject.CommonName, Claims: map[string]string{"k": "v"}}
	}))
	res, err := a.Authenticate(context.Background(), req(map[string]string{
		"certificate": string(leafPEM),
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != "override:client-2" || res.Attributes["k"] != "v" {
		t.Errorf("override not applied: %+v", res)
	}
}

func TestCertificateAuthenticator_MissingPEM(t *testing.T) {
	a := NewCertificateAuthenticator(x509.NewCertPool())
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"certificate": ""})); err == nil {
		t.Error("expected error on empty certificate")
	}
}

func TestCertificateAuthenticator_BadPEM(t *testing.T) {
	a := NewCertificateAuthenticator(x509.NewCertPool())
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"certificate": "not pem"})); err == nil {
		t.Error("expected error on non-PEM input")
	}
}

func TestCertificateAuthenticator_BadDER(t *testing.T) {
	// Valid PEM envelope but garbage inside.
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0xFF, 0xFE, 0xFD}})
	a := NewCertificateAuthenticator(x509.NewCertPool())
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"certificate": string(bad)})); err == nil {
		t.Error("expected parse error")
	}
}

func TestCertificateAuthenticator_UntrustedRoot(t *testing.T) {
	leafPEM, _ := issueCertChain(t, "client-x")
	// Use an empty pool — the leaf's CA isn't trusted.
	a := NewCertificateAuthenticator(x509.NewCertPool())
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"certificate": string(leafPEM),
	})); err == nil {
		t.Error("expected verification failure on untrusted root")
	}
}

func TestCertificateAuthenticator_DefaultIdentity_FallsBackToEmail(t *testing.T) {
	// Hand-craft a cert with no CN, only an email SAN, so defaultIdentityFromCert
	// must pick the email.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDer, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDer)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(11),
		Subject:        pkix.Name{}, // no CN
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: []string{"only@example.com"},
	}
	leafDer, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDer})

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	a := NewCertificateAuthenticator(roots)

	res, err := a.Authenticate(context.Background(), req(map[string]string{
		"certificate": string(leafPEM),
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != subjectPrefixCert+"only@example.com" {
		t.Errorf("UserID = %q, want fallback to email", res.UserID)
	}
}

func TestCertificateAuthenticator_CallbackUnsupported(t *testing.T) {
	a := NewCertificateAuthenticator(x509.NewCertPool())
	if _, err := a.Callback(context.Background(), nil); err == nil {
		t.Error("Callback should not be supported")
	}
	if u := a.LoginURL(""); u != "" {
		t.Errorf("LoginURL = %q", u)
	}
}

// ---------- MemoryCodeStore ----------

func TestMemoryCodeStore_ConsumesOnSuccess(t *testing.T) {
	s := NewMemoryCodeStore()
	_ = s.Save(context.Background(), "k", "1234", time.Minute)
	if err := s.Verify(context.Background(), "k", "1234"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := s.Verify(context.Background(), "k", "1234"); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("second verify err = %v, want ErrCodeInvalid", err)
	}
}

func TestMemoryCodeStore_WrongCodeDoesNotConsume(t *testing.T) {
	s := NewMemoryCodeStore()
	_ = s.Save(context.Background(), "k", "1234", time.Minute)
	if err := s.Verify(context.Background(), "k", "9999"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("wrong code: err = %v", err)
	}
	// Correct code still works — wrong attempts must not consume the entry.
	if err := s.Verify(context.Background(), "k", "1234"); err != nil {
		t.Errorf("good code after bad attempt err = %v, want nil", err)
	}
}

func TestMemoryCodeStore_TTLExpiry(t *testing.T) {
	s := NewMemoryCodeStore()
	_ = s.Save(context.Background(), "k", "1234", time.Nanosecond)
	time.Sleep(2 * time.Millisecond)
	if err := s.Verify(context.Background(), "k", "1234"); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("expected ErrCodeInvalid on expiry, got %v", err)
	}
}

func TestMemoryCodeStore_UnknownKey(t *testing.T) {
	s := NewMemoryCodeStore()
	if err := s.Verify(context.Background(), "missing", "x"); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("err = %v", err)
	}
}

// ---------- GenerateNumericCode ----------

func TestGenerateNumericCode_LengthAndAlphabet(t *testing.T) {
	for _, n := range []int{1, 4, 6, 8, 32} {
		c, err := GenerateNumericCode(n)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if len(c) != n {
			t.Errorf("n=%d: got len %d", n, len(c))
		}
		for _, r := range c {
			if r < '0' || r > '9' {
				t.Errorf("n=%d: non-digit %q in %q", n, r, c)
			}
		}
	}
}

func TestGenerateNumericCode_RejectsNonPositive(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		if _, err := GenerateNumericCode(n); err == nil {
			t.Errorf("n=%d: expected error", n)
		}
	}
}
