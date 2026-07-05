package defaultimpl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oidc"
)

func (j *ECDSAJWTIssuer) Issue(ctx context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error) {
	sgn, kid := j.currentKey()
	if subject == nil || subject.ID == "" {
		return nil, errors.New("ecdsa: subject required")
	}
	now := time.Now()
	// Per-issuance TTL override (Client.AccessTokenTTL via Subject.TTL)
	// wins over the issuer default. Matches the Ed25519 issuer.
	effectiveTTL := effectiveAccessTTL(subject, j.tokenTTL)
	expiresAt := now.Add(effectiveTTL)

	// RFC 9068 §2.1: header typ MUST be at+jwt for access tokens.
	header := ecdsaHeader{Alg: jwtAlgES256, Typ: jwtTypAT, Kid: kid}

	// RFC 9068 §2.2 REQUIRES jti.
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("ecdsa: generate jti: %w", err)
	}

	// Reuse the Ed25519 issuer's payload shape — the JSON claim set is
	// algorithm-independent, so RFC 9068 §2.2 claim handling stays
	// byte-for-byte identical across signers.
	payload := buildAccessPayload(j.issuer, subject, scopes, jti, now, expiresAt)

	signingInput, err := ecdsaSigningInput(header, payload)
	if err != nil {
		return nil, err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: sign access token: %w", err)
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

// IssueIDToken signs an OIDC ID Token with the same ES256 key as the
// access token issuer.
func (j *ECDSAJWTIssuer) IssueIDToken(ctx context.Context, req *oidc.IDTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("ecdsa: id token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = j.tokenTTL
	}
	now := time.Now()
	header := ecdsaHeader{Alg: jwtAlgES256, Typ: jwtTyp, Kid: kid}
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
	payload.AtHash = accessTokenHash(jwtAlgES256, req.AccessToken)
	// Native SSO 1.0 §3.1: ds_hash binds an accompanying device_secret.
	payload.DsHash = accessTokenHash(jwtAlgES256, req.DeviceSecret)
	signingInput, err := ecdsaIDSigningInput(header, payload)
	if err != nil {
		return "", err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return "", fmt.Errorf("ecdsa: sign id token: %w", err)
	}
	j.recordSigningUsage(kid)
	return string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ecdsaSigningInput JOSE-encodes the access-token header + payload.
func ecdsaSigningInput(header ecdsaHeader, payload ed25519Payload) ([]byte, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)), nil
}

// ecdsaIDSigningInput is the ID-token mirror of ecdsaSigningInput.
func ecdsaIDSigningInput(header ecdsaHeader, payload ed25519IDPayload) ([]byte, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)), nil
}

// IssueLogoutToken mints an OIDC BCL 1.0 §2.4 Back-Channel Logout token
// with the same ES256 key as access + ID tokens.
func (j *ECDSAJWTIssuer) IssueLogoutToken(ctx context.Context, req *sso.LogoutTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("ecdsa: logout token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultLogoutTokenTTL
	}
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("ecdsa: generate jti: %w", err)
	}
	now := time.Now()
	header := ecdsaHeader{Alg: jwtAlgES256, Typ: logoutTokenTyp, Kid: kid}
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
		return "", fmt.Errorf("ecdsa: sign logout token: %w", err)
	}
	j.recordSigningUsage(kid)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// SignJWT signs an arbitrary claims object as a compact JWS using the
// SAME ES256 key (and kid) as access + ID + logout tokens, stamping the
// supplied `typ` in the JOSE header. It is the generic-JWT seam the
// CAEP/SSF transmitter reuses to mint Security Event Tokens (RFC 8417,
// `typ: secevent+jwt`) — the SET verifies against the key already in
// JWKS, so no new RP trust setup is needed. See the Ed25519 sibling for
// the full rationale; typ MUST be non-empty.
func (j *ECDSAJWTIssuer) SignJWT(ctx context.Context, typ string, claims any) (string, error) {
	if typ == "" {
		return "", errors.New("ecdsa: sign jwt requires a typ header")
	}
	sgn, kid := j.currentKey()
	header := ecdsaHeader{Alg: jwtAlgES256, Typ: typ, Kid: kid}
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
		return "", fmt.Errorf("ecdsa: sign jwt (typ=%s): %w", typ, err)
	}
	j.recordSigningUsage(kid)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
