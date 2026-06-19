package defaultimpl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/oidc"
)

func (j *RSAJWTIssuer) Issue(ctx context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error) {
	sgn, kid := j.currentKey()
	if subject == nil || subject.ID == "" {
		return nil, errors.New("rsa: subject required")
	}
	now := time.Now()
	effectiveTTL := j.tokenTTL
	if subject.TTL > 0 {
		effectiveTTL = subject.TTL
	}
	expiresAt := now.Add(effectiveTTL)

	header := rsaHeader{Alg: j.alg, Typ: jwtTypAT, Kid: kid}
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("rsa: generate jti: %w", err)
	}

	payload := ed25519Payload{
		Iss:      j.issuer,
		Sub:      subject.ID,
		Exp:      expiresAt.Unix(),
		Nbf:      now.Unix(),
		Iat:      now.Unix(),
		Scope:    strings.Join(scopes, " "),
		Extra:    subject.Claims,
		ClientID: subject.ClientID,
		JTI:      jti,
		ACR:      subject.ACR,
		SID:      subject.SID,
	}
	if subject.ConfirmationJKT != "" || subject.ConfirmationX5TS256 != "" {
		payload.CNF = &confirmationClaim{
			JKT:     subject.ConfirmationJKT,
			X5TS256: subject.ConfirmationX5TS256,
		}
	}
	if !subject.AuthTime.IsZero() {
		payload.AuthTime = subject.AuthTime.Unix()
	}
	if len(subject.AMR) > 0 {
		payload.AMR = append([]string(nil), subject.AMR...)
	}
	if len(subject.AuthorizationDetails) > 0 {
		payload.AuthorizationDetails = append(json.RawMessage(nil), subject.AuthorizationDetails...)
	}
	if chain := actorChainToWire(subject.Actor); chain != nil {
		payload.Act = chain
	}
	if len(subject.RequestedClaims) > 0 {
		payload.RequestedClaims = append(json.RawMessage(nil), subject.RequestedClaims...)
	}
	if len(subject.Resources) > 0 {
		payload.Aud = audClaim(append([]string(nil), subject.Resources...))
	}

	signingInput, err := rsaSigningInput(header, payload)
	if err != nil {
		return nil, err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return nil, fmt.Errorf("rsa: sign access token: %w", err)
	}
	token := string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(sig)

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
	now := time.Now()
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
	signingInput, err := rsaIDSigningInput(header, payload)
	if err != nil {
		return "", err
	}
	sig, err := sgn.Sign(ctx, signingInput)
	if err != nil {
		return "", fmt.Errorf("rsa: sign id token: %w", err)
	}
	return string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// rsaSigningInput JOSE-encodes the access-token header + payload.
func rsaSigningInput(header rsaHeader, payload ed25519Payload) ([]byte, error) {
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

// rsaIDSigningInput is the ID-token mirror of rsaSigningInput.
func rsaIDSigningInput(header rsaHeader, payload ed25519IDPayload) ([]byte, error) {
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
	now := time.Now()
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
		return "", fmt.Errorf("rsa: sign logout token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
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
		return "", fmt.Errorf("rsa: sign jwt (typ=%s): %w", typ, err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
