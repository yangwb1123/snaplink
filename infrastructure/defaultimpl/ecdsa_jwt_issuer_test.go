package defaultimpl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oidc"
)

func TestECDSAJWT_RoundTrip(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAIssuer("test-iss"),
		defaultimpl.WithECDSATokenTTL(5*time.Minute),
	)
	tok, err := iss.Issue(context.Background(), &sso.Subject{
		ID:       "user-1",
		ClientID: "client-1",
		Claims:   map[string]string{"email": "u@example.com"},
	}, []string{"read", "write"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got := strings.Count(tok.AccessToken, "."); got != 2 {
		t.Fatalf("expected 3 JWT segments, got %d", got+1)
	}

	claims, err := iss.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Issuer != "test-iss" {
		t.Errorf("Issuer = %q", claims.Issuer)
	}
	if claims.Extra["email"] != "u@example.com" {
		t.Errorf("Extra lost: %v", claims.Extra)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "read" {
		t.Errorf("Scopes mismatch: %v", claims.Scopes)
	}
}

// TestECDSAJWT_RFC9068Claims locks the RFC 9068 §2.2 access-token claim
// requirements: client_id REQUIRED, jti auto-generated, auth_time + amr
// projected from the live event, at+jwt typ header.
func TestECDSAJWT_RFC9068Claims(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("rfc9068"))
	authTime := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	tok, err := iss.Issue(context.Background(), &sso.Subject{
		ID:       "sub-9068",
		ClientID: "the-client",
		AuthTime: authTime,
		AMR:      []string{"pwd", "otp"},
		ACR:      "urn:acr:high",
		SID:      "sess-1",
	}, []string{"openid"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	parts := strings.Split(tok.AccessToken, ".")
	var hdr struct{ Alg, Typ, Kid string }
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if err := json.Unmarshal(hb, &hdr); err != nil {
		t.Fatalf("header: %v", err)
	}
	if hdr.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", hdr.Alg)
	}
	if hdr.Typ != "at+jwt" {
		t.Errorf("typ = %q, want at+jwt", hdr.Typ)
	}
	if hdr.Kid == "" {
		t.Error("kid missing from header")
	}

	claims, err := iss.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.ClientID != "the-client" {
		t.Errorf("client_id = %q (RFC 9068 §2.2 REQUIRED)", claims.ClientID)
	}
	if claims.JTI == "" {
		t.Error("jti missing (RFC 9068 §2.2 REQUIRED)")
	}
	if !claims.AuthTime.Equal(authTime) {
		t.Errorf("auth_time = %v, want %v", claims.AuthTime, authTime)
	}
	if len(claims.AMR) != 2 || claims.AMR[0] != "pwd" {
		t.Errorf("amr = %v", claims.AMR)
	}
	if claims.ACR != "urn:acr:high" {
		t.Errorf("acr = %q", claims.ACR)
	}
	if claims.SID != "sess-1" {
		t.Errorf("sid = %q", claims.SID)
	}
}

func TestECDSAJWT_JWKS(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewECDSAJWTIssuer()
	jwks, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(jwks) != 1 {
		t.Fatalf("expected 1 JWK, got %d", len(jwks))
	}
	k := jwks[0]
	if k.Kty != "EC" {
		t.Errorf("kty = %q, want EC", k.Kty)
	}
	if k.Crv != "P-256" {
		t.Errorf("crv = %q, want P-256", k.Crv)
	}
	if k.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", k.Alg)
	}
	if k.Use != "sig" {
		t.Errorf("use = %q, want sig", k.Use)
	}
	if k.Kid == "" || k.Kid != iss.KeyID() {
		t.Errorf("kid = %q, want %q", k.Kid, iss.KeyID())
	}
	// x/y must each decode to exactly 32 bytes (P-256 affine coords).
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(xb) != 32 {
		t.Errorf("x decode: len=%d err=%v", len(xb), err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil || len(yb) != 32 {
		t.Errorf("y decode: len=%d err=%v", len(yb), err)
	}
	// The published point must match the issuer's actual public key.
	pub := iss.PublicKey()
	if pub.X.Cmp(bigFromBytes(xb)) != 0 || pub.Y.Cmp(bigFromBytes(yb)) != 0 { //nolint:staticcheck // raw EC coords required to verify published JWK X/Y
		t.Error("published JWK coords don't match issuer public key")
	}
}

func TestECDSAJWT_TamperedSignatureRejected(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewECDSAJWTIssuer()
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
	parts := strings.Split(tok.AccessToken, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[len(sig)-1] ^= 0xFF
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := iss.Validate(context.Background(), tampered); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

// TestECDSAJWT_AlgConfusion enumerates the alg-confusion negatives that
// MUST be rejected at the alg/typ allowlist BEFORE signature verify.
func TestECDSAJWT_AlgConfusion(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("ec"))
	good, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
	parts := strings.Split(good.AccessToken, ".")

	reencode := func(hdr map[string]any) string {
		hb, _ := json.Marshal(hdr)
		return base64.RawURLEncoding.EncodeToString(hb) + "." + parts[1] + "." + parts[2]
	}

	// alg=none.
	if _, err := iss.Validate(context.Background(), reencode(map[string]any{"alg": "none", "typ": "at+jwt"})); err == nil {
		t.Error("alg=none accepted")
	}
	// alg swapped to EdDSA (signature is still ECDSA — must fail at allowlist).
	if _, err := iss.Validate(context.Background(), reencode(map[string]any{"alg": "EdDSA", "typ": "at+jwt"})); err == nil {
		t.Error("alg=EdDSA accepted by ES256 issuer")
	}
	// alg swapped to RS256.
	if _, err := iss.Validate(context.Background(), reencode(map[string]any{"alg": "RS256", "typ": "at+jwt"})); err == nil {
		t.Error("alg=RS256 accepted by ES256 issuer")
	}
	// disallowed typ.
	if _, err := iss.Validate(context.Background(), reencode(map[string]any{"alg": "ES256", "typ": "bogus+jwt"})); err == nil {
		t.Error("disallowed typ accepted")
	}

	// A genuine EdDSA-signed token rejected by the ES256 issuer (the
	// cross-issuer strict-kid->alg property), and vice versa.
	edIss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("ed"))
	edTok, _ := edIss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
	if _, err := iss.Validate(context.Background(), edTok.AccessToken); err == nil {
		t.Error("ES256 issuer validated an EdDSA token")
	}
	if _, err := edIss.Validate(context.Background(), good.AccessToken); err == nil {
		t.Error("EdDSA issuer validated an ES256 token")
	}
}

func TestECDSAJWT_ExpiredRejected(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSATokenTTL(time.Millisecond))
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
	time.Sleep(5 * time.Millisecond)
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestECDSAJWT_IDTokenAndUserinfo(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer("op"))
	idt, err := iss.IssueIDToken(context.Background(), &oidc.IDTokenRequest{
		Subject:  "sub",
		Audience: "client",
		Nonce:    "n-1",
		TTL:      time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	if strings.Count(idt, ".") != 2 {
		t.Fatalf("id_token not a JWS: %q", idt)
	}
	var idHdr struct{ Alg, Typ string }
	hb, _ := base64.RawURLEncoding.DecodeString(strings.Split(idt, ".")[0])
	_ = json.Unmarshal(hb, &idHdr)
	if idHdr.Alg != "ES256" || idHdr.Typ != "JWT" {
		t.Errorf("id_token header alg=%q typ=%q", idHdr.Alg, idHdr.Typ)
	}

	ui, err := iss.SignUserInfo(context.Background(), "client", map[string]any{"sub": "sub", "name": "Jo"})
	if err != nil {
		t.Fatalf("SignUserInfo: %v", err)
	}
	if strings.Count(ui, ".") != 2 {
		t.Fatalf("userinfo not a JWS: %q", ui)
	}
}

// TestECDSAJWT_Rotation: a token minted by the old key still verifies
// after RotateKey demotes it to verify-only, and JWKS publishes both.
func TestECDSAJWT_Rotation(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewECDSAJWTIssuer()
	oldTok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
	oldKID := iss.KeyID()

	newKID, err := iss.RotateKey(nil)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if newKID == oldKID {
		t.Fatal("rotation produced same kid")
	}
	if _, err := iss.Validate(context.Background(), oldTok.AccessToken); err != nil {
		t.Fatalf("pre-rotation token rejected after rotation: %v", err)
	}
	newTok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
	if _, err := iss.Validate(context.Background(), newTok.AccessToken); err != nil {
		t.Fatalf("post-rotation token rejected: %v", err)
	}
	jwks, _ := iss.JWKS(context.Background())
	if len(jwks) != 2 {
		t.Fatalf("expected 2 JWKs after rotation, got %d", len(jwks))
	}
}

// TestECDSAJWT_ExternalSigner verifies the KMS/HSM seam: a signer holding
// the key out of band, with the public half supplied via the option.
func TestECDSAJWT_ExternalSigner(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iss := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAExternalSigner(extECSigner{priv}, &priv.PublicKey, "ext-kid"),
	)
	if iss.KeyID() != "ext-kid" {
		t.Errorf("kid = %q, want ext-kid", iss.KeyID())
	}
	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func bigFromBytes(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

type extECSigner struct{ priv *ecdsa.PrivateKey }

func (s extECSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	// Mirror softwareECDSASigner: SHA-256 digest, fixed-width R||S.
	sum := sha256Sum(message)
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, sum)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	ss.FillBytes(out[32:])
	return out, nil
}
