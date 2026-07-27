package defaultimpl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oidc"
)

func (j *RSAJWTIssuer) Issue(ctx context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error) {
	sgn, kid := j.currentKey()
	if subject == nil || subject.ID == "" {
		return nil, errors.New("rsa: subject required")
	}
	now := nowFrom(j.clock)
	effectiveTTL := effectiveAccessTTL(subject, j.tokenTTL)
	expiresAt := now.Add(effectiveTTL)

	header := rsaHeader{Alg: j.alg, Typ: jwtTypAT, Kid: kid}
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("rsa: generate jti: %w", err)
	}

	payload := buildAccessPayload(j.issuer, subject, scopes, jti, now, expiresAt)

	token, err := signCompactJWS(ctx, sgn, header, payload, "rsa: sign access token")
	if err != nil {
		return nil, err
	}
	j.recordSigningUsage(kid)

	return &sso.Token{
		AccessToken: token,
		TokenType:   sso.TokenTypeBearer,
		ExpiresIn:   int(effectiveTTL.Seconds()),
		Scope:       payload.Scope,
		CreatedAt:   now,
	}, nil
}

// IssueIDToken signs an OIDC ID Token with the same RSA key.
func (j *RSAJWTIssuer) IssueIDToken(ctx context.Context, req *oidc.IDTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("rsa: id token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = j.tokenTTL
	}
	now := nowFrom(j.clock)
	header := rsaHeader{Alg: j.alg, Typ: jwtTyp, Kid: kid}
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
	// j.alg is RS256 or PS256 — both hash with SHA-256.
	payload.AtHash = accessTokenHash(j.alg, req.AccessToken)
	// Native SSO 1.0 §3.1: ds_hash binds an accompanying device_secret.
	payload.DsHash = accessTokenHash(j.alg, req.DeviceSecret)
	token, err := signCompactJWS(ctx, sgn, header, payload, "rsa: sign id token")
	if err != nil {
		return "", err
	}
	j.recordSigningUsage(kid)
	return token, nil
}

// IssueLogoutToken mints an OIDC BCL 1.0 §2.4 logout token with the same
// RSA key.
func (j *RSAJWTIssuer) IssueLogoutToken(ctx context.Context, req *sso.LogoutTokenRequest) (string, error) {
	sgn, kid := j.currentKey()
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("rsa: logout token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultLogoutTokenTTL
	}
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("rsa: generate jti: %w", err)
	}
	now := nowFrom(j.clock)
	header := rsaHeader{Alg: j.alg, Typ: logoutTokenTyp, Kid: kid}
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
	token, err := signCompactJWS(ctx, sgn, header, payload, "rsa: sign logout token")
	if err != nil {
		return "", err
	}
	j.recordSigningUsage(kid)
	return token, nil
}

// SignJWT signs an arbitrary claims object as a compact JWS using the
// SAME RSA key (and kid) as access + ID + logout tokens, stamping the
// supplied `typ` in the JOSE header. It is the generic-JWT seam the
// CAEP/SSF transmitter reuses to mint Security Event Tokens (RFC 8417,
// `typ: secevent+jwt`) — the SET verifies against the key already in
// JWKS, so no new RP trust setup is needed. See the Ed25519 sibling for
// the full rationale; typ MUST be non-empty.
func (j *RSAJWTIssuer) SignJWT(ctx context.Context, typ string, claims any) (string, error) {
	if typ == "" {
		return "", errors.New("rsa: sign jwt requires a typ header")
	}
	sgn, kid := j.currentKey()
	header := rsaHeader{Alg: j.alg, Typ: typ, Kid: kid}
	token, err := signCompactJWS(ctx, sgn, header, claims, "rsa: sign jwt (typ="+typ+")")
	if err != nil {
		return "", err
	}
	j.recordSigningUsage(kid)
	return token, nil
}
