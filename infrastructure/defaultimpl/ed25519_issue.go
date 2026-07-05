package defaultimpl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oidc"
)

func (j *Ed25519JWTIssuer) Issue(ctx context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error) {
	sgn, kid := j.currentKey()
	if subject == nil || subject.ID == "" {
		return nil, errors.New("ed25519: subject required")
	}
	now := time.Now()
	// Per-issuance TTL override (Client.AccessTokenTTL) wins over
	// the issuer's configured tokenTTL. Zero = use the issuer's
	// default — preserves backwards compatibility for callers
	// that don't set Subject.TTL.
	effectiveTTL := effectiveAccessTTL(subject, j.tokenTTL)
	expiresAt := now.Add(effectiveTTL)

	// RFC 9068 §2.1: header `typ` MUST be `at+jwt` to distinguish
	// access tokens from other JWT shapes (ID tokens, generic JWT)
	// so strict resource servers can reject misrouted tokens.
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTypAT, Kid: kid}

	// RFC 9068 §2.2 REQUIRES jti — a unique identifier per token,
	// suitable for replay tracking + revocation lookup. 16 bytes
	// = 128 bits = collision-free at any practical issue rate.
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("ed25519: generate jti: %w", err)
	}

	payload := buildAccessPayload(j.issuer, subject, scopes, jti, now, expiresAt)

	signingInput, err := jwtSigningInput(header, payload)
	if err != nil {
		return nil, err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return nil, fmt.Errorf("ed25519: sign access token: %w", err)
	}
	j.recordSigningUsage(kid)
	token := string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(sig)

	return &sso.Token{
		AccessToken: token,
		TokenType:   sso.TokenTypeBearer,
		ExpiresIn:   int(effectiveTTL.Seconds()),
		Scope:       payload.Scope,
		CreatedAt:   now,
	}, nil
}

// generateJTI mints a 16-byte (128-bit) base64url-encoded unique
// identifier for the `jti` claim per RFC 9068 §2.2.
func generateJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// IssueIDToken signs an OIDC ID Token using the same Ed25519 key as the
// access token issuer — by design, downstream relying parties verify
// both with one JWKS entry. ttl falls back to the issuer's tokenTTL
// when req.TTL is zero (matching access-token lifetime keeps
// expiration semantics consistent across the pair).
//
// All OIDC-mandated fields are stamped automatically (iss, sub, aud,
// exp, iat). Nonce / AuthTime / AMR / ACR / AZP / extra Claims are
// projected only when non-zero so the wire stays minimal — relying
// parties branch on field presence per OIDC Core §2.
func (j *Ed25519JWTIssuer) IssueIDToken(ctx context.Context, req *oidc.IDTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("ed25519: id token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = j.tokenTTL
	}
	now := time.Now()
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTyp, Kid: kid}
	payload := ed25519IDPayload{
		Iss:   j.issuer,
		Sub:   req.Subject,
		Aud:   req.Audience,
		Exp:   now.Add(ttl).Unix(),
		Iat:   now.Unix(),
		Nonce: req.Nonce,
		AMR:   req.AMR,
		ACR:   req.ACR,
		AZP:   req.AZP,
		SID:   req.SID,
		Extra: req.Claims,
	}
	if !req.AuthTime.IsZero() {
		payload.AuthTime = req.AuthTime.Unix()
	}
	// OIDC Core §3.1.3.6: bind the id_token to its companion access_token.
	payload.AtHash = accessTokenHash(jwtAlgEdDSA, req.AccessToken)
	// Native SSO 1.0 §3.1: ds_hash binds an accompanying device_secret, same
	// left-half-hash construction as at_hash. Empty secret omits the claim.
	payload.DsHash = accessTokenHash(jwtAlgEdDSA, req.DeviceSecret)
	signingInput, err := idTokenSigningInput(header, payload)
	if err != nil {
		return "", err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return "", fmt.Errorf("ed25519: sign id token: %w", err)
	}
	j.recordSigningUsage(kid)
	return string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// idTokenSigningInput is the ID-token mirror of jwtSigningInput — same
// JOSE encoding, but parametrized on the ID payload shape.
func idTokenSigningInput(header ed25519Header, payload ed25519IDPayload) ([]byte, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	return []byte(encoded), nil
}

func jwtSigningInput(header ed25519Header, payload ed25519Payload) ([]byte, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	return []byte(encoded), nil
}

// The compile-time check that this issuer satisfies caep.JWTSigner lives
// in the caep package's test (caep/jwtsigner_guard_test.go), NOT here:
// defaultimpl is the foundational signing primitive and must not import
// the peripheral caep subsystem (a backwards edge + future-cycle risk).
// Go's structural typing means SignJWT below already satisfies
// caep.JWTSigner without a guard in this package.

// SignJWT signs an arbitrary claims object as a compact JWS using the
// SAME Ed25519 key (and kid) as access + ID + logout tokens, stamping
// the supplied `typ` in the JOSE header. It is the generic-JWT seam the
// CAEP/SSF transmitter reuses to mint Security Event Tokens (RFC 8417,
// `typ: secevent+jwt`) without going through the access-token Issue path
// (which would stamp `typ: at+jwt` and an access-token claim shape).
// Because the signing key is the one already published in JWKS, an RP
// validates a SET with no new trust setup.
//
// claims is marshalled as-is — the caller owns the full payload shape
// (iss, jti, iat, aud, sub_id, events). No claim is injected here, so
// this method makes no policy decisions and stays a pure signing
// primitive. typ MUST be non-empty (an unset typ would let a SET be
// mistaken for another JWT shape on the wire).
func (j *Ed25519JWTIssuer) SignJWT(ctx context.Context, typ string, claims any) (string, error) {
	if typ == "" {
		return "", errors.New("ed25519: sign jwt requires a typ header")
	}
	sgn, kid := j.currentKey()
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: typ, Kid: kid}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := sgn.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("ed25519: sign jwt (typ=%s): %w", typ, err)
	}
	j.recordSigningUsage(kid)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// logoutTokenTyp is OIDC BCL 1.0 §2.4's REQUIRED `typ` header.
const logoutTokenTyp = "logout+jwt"

// backchannelLogoutEvent is the URI used as the key inside the
// `events` claim per OIDC BCL §2.4. Value is an empty object —
// the spec says "any non-null value MAY be used; this
// specification uses the empty JSON object {} ".
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// ed25519LogoutPayload is the BCL §2.4 claim set. `events` is a
// map[string]json.RawMessage so the conventional empty-object
// value (`{}`) marshals cleanly.
type ed25519LogoutPayload struct {
	Iss    string                     `json:"iss,omitempty"`
	Sub    string                     `json:"sub,omitempty"`
	Aud    string                     `json:"aud,omitempty"`
	Iat    int64                      `json:"iat,omitempty"`
	Exp    int64                      `json:"exp,omitempty"`
	JTI    string                     `json:"jti,omitempty"`
	Events map[string]json.RawMessage `json:"events,omitempty"`
	// `nonce` is intentionally omitted — OIDC BCL §2.4 forbids
	// it. `sid` is populated when the caller passes a session id
	// via LogoutTokenRequest.SID — RPs use it to invalidate the
	// specific session they received the matching id_token for,
	// rather than wiping every session for the subject.
	SID string `json:"sid,omitempty"`
}

// DefaultLogoutTokenTTL bounds the logout-token lifetime. Short
// (60s) per OIDC BCL §2.4 — the RP processes the notification on
// receipt; a stale logout token has no use.
const DefaultLogoutTokenTTL = 60 * time.Second

// IssueLogoutToken mints a Back-Channel Logout token per OIDC
// BCL 1.0 §2.4. Same signing key, same kid, same JWKS entry as
// access + ID tokens — RPs verify all three with one key
// lookup.
func (j *Ed25519JWTIssuer) IssueLogoutToken(ctx context.Context, req *sso.LogoutTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("ed25519: logout token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultLogoutTokenTTL
	}
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("ed25519: generate jti: %w", err)
	}
	now := time.Now()
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: logoutTokenTyp, Kid: kid}
	payload := ed25519LogoutPayload{
		Iss:    j.issuer,
		Sub:    req.Subject,
		Aud:    req.Audience,
		Iat:    now.Unix(),
		Exp:    now.Add(ttl).Unix(),
		JTI:    jti,
		Events: map[string]json.RawMessage{backchannelLogoutEvent: json.RawMessage("{}")},
		SID:    req.SID,
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig, err := sgn.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("ed25519: sign logout token: %w", err)
	}
	j.recordSigningUsage(kid)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
