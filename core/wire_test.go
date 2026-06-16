package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestTokenJSONRoundTrip pins the access-token response envelope: omitempty on
// refresh_token (absent for client_credentials) and the literal wire keys RPs
// parse.
func TestTokenJSONRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Unix(1700000000, 0).UTC()
	tok := Token{
		AccessToken: "at-abc",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       "openid profile",
		CreatedAt:   now,
	}
	out, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	if strings.Contains(string(out), "refresh_token") {
		t.Errorf("empty refresh_token should be omitted: %s", out)
	}

	var rt Token
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if rt.AccessToken != tok.AccessToken || rt.TokenType != tok.TokenType ||
		rt.ExpiresIn != tok.ExpiresIn || rt.Scope != tok.Scope || !rt.CreatedAt.Equal(now) {
		t.Errorf("Token round-trip mismatch: got %+v, want %+v", rt, tok)
	}

	// With a refresh token, the key is present.
	tok.RefreshToken = "rt-xyz"
	out2, _ := json.Marshal(tok)
	if !strings.Contains(string(out2), `"refresh_token":"rt-xyz"`) {
		t.Errorf("refresh_token should be present: %s", out2)
	}
}

// TestTokenClaimsConfirmationNotSerialized verifies the PoP confirmation
// thumbprints carry json:"-" so they never leak onto the wire even though
// they're part of the validated claim set.
func TestTokenClaimsConfirmationNotSerialized(t *testing.T) {
	t.Parallel()

	tc := TokenClaims{
		Subject:             "user-1",
		Issuer:              "https://issuer.example",
		Audience:            []string{"https://api.example"},
		ConfirmationJKT:     "jkt-thumb",
		ConfirmationX5TS256: "x5t-thumb",
	}
	out, err := json.Marshal(tc)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	s := string(out)
	if strings.Contains(s, "jkt-thumb") || strings.Contains(s, "x5t-thumb") {
		t.Errorf("confirmation thumbprints must not serialize: %s", s)
	}
}

// TestTokenClaimsAudienceArray confirms aud serializes as a JSON array (the
// internal representation is []string) and round-trips losslessly.
func TestTokenClaimsAudienceArray(t *testing.T) {
	t.Parallel()

	tc := TokenClaims{
		Subject:  "u",
		Audience: []string{"a", "b"},
	}
	out, err := json.Marshal(tc)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	if !strings.Contains(string(out), `"aud":["a","b"]`) {
		t.Errorf("aud should marshal as array: %s", out)
	}

	var rt TokenClaims
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if len(rt.Audience) != 2 || rt.Audience[0] != "a" || rt.Audience[1] != "b" {
		t.Errorf("aud round-trip = %v, want [a b]", rt.Audience)
	}
}

// TestConsentGrantJSON pins the persisted consent record shape.
func TestConsentGrantJSON(t *testing.T) {
	t.Parallel()

	g := ConsentGrant{
		UserID:    "u-1",
		ClientID:  "c-1",
		Scopes:    []string{"openid", "email"},
		GrantedAt: time.Unix(1700000000, 0).UTC(),
	}
	out, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	var rt ConsentGrant
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if rt.UserID != g.UserID || rt.ClientID != g.ClientID || len(rt.Scopes) != 2 || !rt.GrantedAt.Equal(g.GrantedAt) {
		t.Errorf("ConsentGrant round-trip = %+v, want %+v", rt, g)
	}
}

// TestTokenMetaOmitEmpty checks the admin token summary omits the optional
// fields when zero (a minimal JWT issuer can report just id + subject).
func TestTokenMetaOmitEmpty(t *testing.T) {
	t.Parallel()

	m := TokenMeta{TokenID: "jti-1", SubjectID: "u-1"}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	s := string(out)
	for _, k := range []string{"scopes", "issued_at_unix", "expires_at_unix", "strategy"} {
		if strings.Contains(s, k) {
			t.Errorf("empty %s should be omitted: %s", k, s)
		}
	}
	if !strings.Contains(s, `"token_id":"jti-1"`) || !strings.Contains(s, `"subject_id":"u-1"`) {
		t.Errorf("required keys missing: %s", s)
	}
}

// TestMFAEnrolledFactorJSON pins the non-sensitive factor metadata shape; the
// secret/material is never part of this struct.
func TestMFAEnrolledFactorJSON(t *testing.T) {
	t.Parallel()

	f := MFAEnrolledFactor{
		ID:      "f-1",
		Method:  "totp",
		AddedAt: time.Unix(1700000000, 0).UTC(),
	}
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	// Label is omitempty.
	if strings.Contains(string(out), "label") {
		t.Errorf("empty label should be omitted: %s", out)
	}

	var rt MFAEnrolledFactor
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if rt.ID != f.ID || rt.Method != f.Method || !rt.AddedAt.Equal(f.AddedAt) {
		t.Errorf("MFAEnrolledFactor round-trip = %+v, want %+v", rt, f)
	}
}

// TestJWKOmitEmpty verifies an Ed25519 (OKP) key omits the EC/RSA-only fields.
func TestJWKOmitEmpty(t *testing.T) {
	t.Parallel()

	j := JWK{Kty: "OKP", Crv: "Ed25519", X: "base64url", Kid: "k1", Alg: "EdDSA", Use: "sig"}
	out, err := json.Marshal(j)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	s := string(out)
	for _, ecRSA := range []string{`"y"`, `"n"`, `"e"`} {
		if strings.Contains(s, ecRSA) {
			t.Errorf("OKP key must omit %s: %s", ecRSA, s)
		}
	}

	var rt JWK
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if rt != j {
		t.Errorf("JWK round-trip = %+v, want %+v", rt, j)
	}
}

// TestClientSecretAndRATNeverSerialized: Secret and RegistrationAccessToken
// carry json:"-" — a Client marshaled into any admin/API response must never
// leak the shared secret or the management bearer.
func TestClientSecretAndRATNeverSerialized(t *testing.T) {
	t.Parallel()

	c := Client{
		ID:                      "c-1",
		Secret:                  "super-secret",
		RegistrationAccessToken: "rat-secret",
		Name:                    "App",
	}
	out, err := json.Marshal(&c)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	s := string(out)
	if strings.Contains(s, "super-secret") || strings.Contains(s, "rat-secret") {
		t.Errorf("Client must not serialize Secret/RAT: %s", s)
	}
}

// TestClientSetFingerprintDiscriminates exercises the discovery-relevant fields
// that flip the digest: RequirePAR, RequireSignedRequestObject,
// FrontchannelLogoutURI presence, and AllowedAuthorizationDetailsTypes. This
// also drives the boolToByte true/false branches in clientFingerprintEncoding.
func TestClientSetFingerprintDiscriminates(t *testing.T) {
	t.Parallel()

	base := func() *Client {
		return &Client{ID: "c", AllowedScopes: []string{"openid"}}
	}
	baseFP := ClientSetFingerprint([]*Client{base()})

	variants := []struct {
		name   string
		mutate func(*Client)
	}{
		{"require_par", func(c *Client) { c.RequirePAR = true }},
		{"require_signed_request", func(c *Client) { c.RequireSignedRequestObject = true }},
		{"frontchannel_logout", func(c *Client) { c.FrontchannelLogoutURI = "https://rp.example/flo" }},
		{"authz_detail_types", func(c *Client) { c.AllowedAuthorizationDetailsTypes = []string{"payment"} }},
		{"extra_scope", func(c *Client) { c.AllowedScopes = []string{"openid", "email"} }},
	}
	for _, v := range variants {
		v := v
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			c := base()
			v.mutate(c)
			if got := ClientSetFingerprint([]*Client{c}); got == baseFP {
				t.Errorf("%s did not flip the fingerprint (got base %q)", v.name, baseFP)
			}
		})
	}
}

// TestClientSetFingerprintCosmeticFLOEdit confirms only PRESENCE of the
// front-channel logout URI matters: changing the URI value (both non-empty)
// must NOT churn the digest.
func TestClientSetFingerprintCosmeticFLOEdit(t *testing.T) {
	t.Parallel()

	a := &Client{ID: "c", FrontchannelLogoutURI: "https://rp.example/a"}
	b := &Client{ID: "c", FrontchannelLogoutURI: "https://rp.example/b"}
	if ClientSetFingerprint([]*Client{a}) != ClientSetFingerprint([]*Client{b}) {
		t.Error("FLO URI value edit (both present) should not change the fingerprint")
	}
}

// TestClientSetFingerprintScopeOrderInsensitive: scope set membership, not
// order, drives the digest.
func TestClientSetFingerprintScopeOrderInsensitive(t *testing.T) {
	t.Parallel()

	a := &Client{ID: "c", AllowedScopes: []string{"openid", "email", "profile"}}
	b := &Client{ID: "c", AllowedScopes: []string{"profile", "openid", "email"}}
	if ClientSetFingerprint([]*Client{a}) != ClientSetFingerprint([]*Client{b}) {
		t.Error("scope reordering should not change the fingerprint")
	}
}

func TestBoolToByte(t *testing.T) {
	t.Parallel()

	if boolToByte(true) != 1 {
		t.Errorf("boolToByte(true) = %d, want 1", boolToByte(true))
	}
	if boolToByte(false) != 0 {
		t.Errorf("boolToByte(false) = %d, want 0", boolToByte(false))
	}
}
