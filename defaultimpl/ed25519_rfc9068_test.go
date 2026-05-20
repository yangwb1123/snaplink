package defaultimpl_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens.
//
// Required by §2.1: header `typ` MUST be `at+jwt`.
// Required by §2.2: claims include `jti`, `client_id`, `iat`,
// `exp`, `iss`, `sub`, `aud`, optionally `auth_time` + `acr` +
// `amr` + `scope`.
// Required by §4: validation MUST enforce alg allowlist + typ
// allowlist.

// decodeJWTSegments splits a JWT and returns (header, payload) as
// decoded JSON maps. Fails the test on a malformed token.
func decodeJWTSegments(t *testing.T, jwt string) (header, payload map[string]any) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 segments: %q", jwt)
	}
	hraw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header decode: %v", err)
	}
	praw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	header = map[string]any{}
	payload = map[string]any{}
	if err := json.Unmarshal(hraw, &header); err != nil {
		t.Fatalf("header parse: %v", err)
	}
	if err := json.Unmarshal(praw, &payload); err != nil {
		t.Fatalf("payload parse: %v", err)
	}
	return header, payload
}

func TestRFC9068_HeaderTypIsAtJwt(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	tok, err := iss.Issue(context.Background(),
		&sso.Subject{ID: "u-1", ClientID: "web"}, []string{"read"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	header, _ := decodeJWTSegments(t, tok.AccessToken)
	if header["typ"] != "at+jwt" {
		t.Errorf("header typ = %v want \"at+jwt\" (RFC 9068 §2.1)", header["typ"])
	}
	if header["alg"] != "EdDSA" {
		t.Errorf("header alg = %v want \"EdDSA\"", header["alg"])
	}
}

func TestRFC9068_PayloadCarriesRequiredClaims(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.test"))
	authTime := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	tok, err := iss.Issue(context.Background(), &sso.Subject{
		ID: "u-1", ClientID: "web-app", AuthTime: authTime,
		AMR: []string{"password"}, ACR: "loa3",
	}, []string{"read", "write"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, payload := decodeJWTSegments(t, tok.AccessToken)

	// REQUIRED per §2.2.
	if payload["sub"] != "u-1" {
		t.Errorf("sub = %v", payload["sub"])
	}
	if payload["iss"] != "https://sso.test" {
		t.Errorf("iss = %v", payload["iss"])
	}
	if payload["client_id"] != "web-app" {
		t.Errorf("client_id = %v want \"web-app\" (RFC 9068 §2.2 REQUIRED)", payload["client_id"])
	}
	if _, ok := payload["jti"].(string); !ok || payload["jti"] == "" {
		t.Errorf("jti missing or empty: %v (RFC 9068 §2.2 REQUIRED)", payload["jti"])
	}
	if _, ok := payload["exp"]; !ok {
		t.Errorf("exp missing")
	}
	if _, ok := payload["iat"]; !ok {
		t.Errorf("iat missing")
	}

	// RECOMMENDED but populated here.
	if payload["scope"] != "read write" {
		t.Errorf("scope = %v want \"read write\"", payload["scope"])
	}
	if int64(payload["auth_time"].(float64)) != authTime.Unix() {
		t.Errorf("auth_time = %v want %d", payload["auth_time"], authTime.Unix())
	}
	if payload["acr"] != "loa3" {
		t.Errorf("acr = %v want \"loa3\"", payload["acr"])
	}
	amr, _ := payload["amr"].([]any)
	if len(amr) != 1 || amr[0] != "password" {
		t.Errorf("amr = %v want [\"password\"]", payload["amr"])
	}
}

func TestRFC9068_JTIIsUniquePerCall(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	subj := &sso.Subject{ID: "u-1", ClientID: "web"}

	const n = 50
	seen := make(map[string]struct{}, n)
	for i := range n {
		tok, err := iss.Issue(context.Background(), subj, []string{"read"})
		if err != nil {
			t.Fatalf("Issue[%d]: %v", i, err)
		}
		_, payload := decodeJWTSegments(t, tok.AccessToken)
		jti, _ := payload["jti"].(string)
		if jti == "" {
			t.Fatalf("Issue[%d]: jti missing", i)
		}
		if _, dup := seen[jti]; dup {
			t.Fatalf("Issue[%d]: jti %q already seen", i, jti)
		}
		seen[jti] = struct{}{}
	}
}

func TestRFC9068_ClientCredentialsOmitsAuthTime(t *testing.T) {
	// Machine-to-machine tokens (subject = client) have no end-user
	// auth event — auth_time / amr MUST stay omitted to avoid
	// fabricating a non-event.
	iss := defaultimpl.NewEd25519JWTIssuer()
	tok, err := iss.Issue(context.Background(), &sso.Subject{
		ID: "svc-1", ClientID: "svc-1",
		// no AuthTime, no AMR
	}, []string{"internal"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, payload := decodeJWTSegments(t, tok.AccessToken)
	if _, ok := payload["auth_time"]; ok {
		t.Errorf("auth_time present on client_credentials token: %v", payload["auth_time"])
	}
	if _, ok := payload["amr"]; ok {
		t.Errorf("amr present on client_credentials token: %v", payload["amr"])
	}
	if payload["client_id"] != "svc-1" {
		t.Errorf("client_id = %v want \"svc-1\"", payload["client_id"])
	}
}

func TestRFC9068_ValidateRejectsAlgNone(t *testing.T) {
	// alg=none is the canonical alg-confusion attack. Validate
	// MUST reject before signature verification even runs.
	iss := defaultimpl.NewEd25519JWTIssuer()
	hdr := `{"alg":"none","typ":"at+jwt","kid":"k"}`
	payload := `{"sub":"u-1","iss":"x","exp":99999999999}`
	jwt := base64.RawURLEncoding.EncodeToString([]byte(hdr)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload)) + "."

	if _, err := iss.Validate(context.Background(), jwt); err == nil {
		t.Fatal("expected Validate to reject alg=none, got nil")
	} else if !strings.Contains(err.Error(), "alg") {
		t.Errorf("expected alg-related error, got %v", err)
	}
}

func TestRFC9068_ValidateRejectsUnknownTyp(t *testing.T) {
	// A token shaped as e.g. typ=JWE or typ=foo+jwt MUST be
	// rejected — defends against passing an ID Token or
	// other-shape JWT off as an access token.
	priv, _ := generateEd25519KeyForTest(t)
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Key(priv))

	hdr := `{"alg":"EdDSA","typ":"unexpected","kid":"` + iss.KeyID() + `"}`
	payload := `{"sub":"u-1","exp":99999999999}`
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(hdr)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := ed25519.Sign(priv, []byte(signingInput))
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	if _, err := iss.Validate(context.Background(), jwt); err == nil {
		t.Fatal("expected Validate to reject unknown typ, got nil")
	} else if !strings.Contains(err.Error(), "typ") {
		t.Errorf("expected typ-related error, got %v", err)
	}
}

func TestRFC9068_ValidateAcceptsLegacyJWTTyp(t *testing.T) {
	// Tokens minted before the at+jwt switch (typ=JWT) MUST still
	// verify until their natural expiry — operators rolling forward
	// can't tolerate every in-flight token suddenly going invalid.
	priv, _ := generateEd25519KeyForTest(t)
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Key(priv))

	hdr := `{"alg":"EdDSA","typ":"JWT","kid":"` + iss.KeyID() + `"}`
	payload := `{"sub":"u-1","exp":99999999999,"iat":1}`
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(hdr)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := ed25519.Sign(priv, []byte(signingInput))
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	claims, err := iss.Validate(context.Background(), jwt)
	if err != nil {
		t.Fatalf("Validate rejected typ=JWT: %v (back-compat broken)", err)
	}
	if claims.Subject != "u-1" {
		t.Errorf("sub = %q", claims.Subject)
	}
}

func TestRFC9068_ValidatePopulatesAccessTokenClaims(t *testing.T) {
	// Round-trip: Issue → Validate yields the RFC 9068 claims on
	// the typed TokenClaims surface (so /introspect + permission
	// resolution can rely on them).
	iss := defaultimpl.NewEd25519JWTIssuer()
	authTime := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	tok, err := iss.Issue(context.Background(), &sso.Subject{
		ID: "u-1", ClientID: "web", AuthTime: authTime,
		AMR: []string{"password", "otp"}, ACR: "loa2",
	}, []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := iss.Validate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.ClientID != "web" {
		t.Errorf("ClientID = %q want \"web\"", claims.ClientID)
	}
	if claims.JTI == "" {
		t.Errorf("JTI missing on validated claims")
	}
	if !claims.AuthTime.Equal(authTime) {
		t.Errorf("AuthTime = %v want %v", claims.AuthTime, authTime)
	}
	if claims.ACR != "loa2" {
		t.Errorf("ACR = %q", claims.ACR)
	}
	if len(claims.AMR) != 2 || claims.AMR[0] != "password" || claims.AMR[1] != "otp" {
		t.Errorf("AMR = %v want [password otp]", claims.AMR)
	}
}

// ---- helpers ----

func generateEd25519KeyForTest(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv, pub
}
