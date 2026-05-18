package defaultimpl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso"
)

// Ed25519 JWT constants.
const (
	jwtAlgEdDSA   = "EdDSA"
	jwtTyp        = "JWT"
	jwkKtyOKP     = "OKP"
	jwkCrvEd25519 = "Ed25519"
	jwkUseSig     = "sig"
)

// Ed25519JWTIssuer signs 3-segment JWTs (header.payload.signature) with an
// Ed25519 private key. The public key is published via the JWKS endpoint so
// downstream gateways (e.g. OpenResty + lua-resty-jwt) can verify tokens
// locally without round-tripping back to the SSO server.
//
// Revocation is in-memory: tokens are added to a deny set on Revoke and
// Validate consults it. Persistent / distributed revocation requires
// replacing the deny set with a Redis/DB-backed implementation.
type Ed25519JWTIssuer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	issuer     string
	tokenTTL   time.Duration

	revokedMu sync.RWMutex
	revoked   map[string]struct{}
}

type Ed25519Option func(*Ed25519JWTIssuer)

func WithEd25519Issuer(name string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.issuer = name }
}

func WithEd25519TokenTTL(ttl time.Duration) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.tokenTTL = ttl }
}

// WithEd25519Key uses the supplied keypair instead of generating one.
// Useful for tests and for long-lived deployments where the key must persist
// across process restarts.
func WithEd25519Key(priv ed25519.PrivateKey) Ed25519Option {
	return func(j *Ed25519JWTIssuer) {
		j.privateKey = priv
		j.publicKey = priv.Public().(ed25519.PublicKey)
	}
}

// WithEd25519KeyID overrides the auto-derived kid.
func WithEd25519KeyID(kid string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.keyID = kid }
}

func NewEd25519JWTIssuer(opts ...Ed25519Option) *Ed25519JWTIssuer {
	j := &Ed25519JWTIssuer{
		issuer:   sso.DefaultIssuer,
		tokenTTL: defaultTokenTTL,
		revoked:  make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(j)
	}
	if j.privateKey == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(fmt.Sprintf("ed25519: generate key: %v", err))
		}
		j.privateKey = priv
		j.publicKey = pub
	}
	if j.keyID == "" {
		j.keyID = fingerprintKid(j.publicKey)
	}
	return j
}

// PublicKey returns the verification key so callers can pre-populate
// caches or pass it to non-JWKS verifiers.
func (j *Ed25519JWTIssuer) PublicKey() ed25519.PublicKey { return j.publicKey }

// KeyID returns the kid string embedded in every issued token's header.
func (j *Ed25519JWTIssuer) KeyID() string { return j.keyID }

type ed25519Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type ed25519Payload struct {
	Iss   string            `json:"iss,omitempty"`
	Sub   string            `json:"sub,omitempty"`
	Aud   []string          `json:"aud,omitempty"`
	Exp   int64             `json:"exp,omitempty"`
	Nbf   int64             `json:"nbf,omitempty"`
	Iat   int64             `json:"iat,omitempty"`
	Scope string            `json:"scope,omitempty"`
	Extra map[string]string `json:"ext,omitempty"`
}

// ed25519IDPayload is the ID-Token-specific claim set, distinct from
// access tokens because OIDC names some fields differently (aud is a
// scalar string when single-valued in many real deployments; auth_time
// is a first-class claim; nonce/amr/acr/azp are OIDC-specific).
type ed25519IDPayload struct {
	Iss      string            `json:"iss,omitempty"`
	Sub      string            `json:"sub,omitempty"`
	Aud      string            `json:"aud,omitempty"`
	Exp      int64             `json:"exp,omitempty"`
	Iat      int64             `json:"iat,omitempty"`
	Nonce    string            `json:"nonce,omitempty"`
	AuthTime int64             `json:"auth_time,omitempty"`
	AMR      []string          `json:"amr,omitempty"`
	ACR      string            `json:"acr,omitempty"`
	AZP      string            `json:"azp,omitempty"`
	Extra    map[string]string `json:"ext,omitempty"`
}

func (j *Ed25519JWTIssuer) Issue(_ context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error) {
	if subject == nil || subject.ID == "" {
		return nil, errors.New("ed25519: subject required")
	}
	now := time.Now()
	expiresAt := now.Add(j.tokenTTL)

	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTyp, Kid: j.keyID}
	payload := ed25519Payload{
		Iss:   j.issuer,
		Sub:   subject.ID,
		Exp:   expiresAt.Unix(),
		Nbf:   now.Unix(),
		Iat:   now.Unix(),
		Scope: strings.Join(scopes, " "),
		Extra: subject.Claims,
	}

	signingInput, err := jwtSigningInput(header, payload)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(j.privateKey, signingInput)
	token := string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(sig)

	return &sso.Token{
		AccessToken: token,
		TokenType:   sso.TokenTypeBearer,
		ExpiresIn:   int(j.tokenTTL.Seconds()),
		Scope:       payload.Scope,
		CreatedAt:   now,
	}, nil
}

func (j *Ed25519JWTIssuer) Validate(_ context.Context, token string) (*sso.TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("ed25519: malformed token")
	}

	j.revokedMu.RLock()
	_, revoked := j.revoked[token]
	j.revokedMu.RUnlock()
	if revoked {
		return nil, errors.New("ed25519: token revoked")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("ed25519: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(j.publicKey, []byte(signingInput), sig) {
		return nil, errors.New("ed25519: signature invalid")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ed25519: payload decode: %w", err)
	}
	var p ed25519Payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, fmt.Errorf("ed25519: payload parse: %w", err)
	}

	now := time.Now().Unix()
	if p.Exp != 0 && now >= p.Exp {
		return nil, errors.New("ed25519: token expired")
	}
	if p.Nbf != 0 && now < p.Nbf {
		return nil, errors.New("ed25519: token not yet valid")
	}

	claims := &sso.TokenClaims{
		Subject:   p.Sub,
		Issuer:    p.Iss,
		Audience:  p.Aud,
		ExpiresAt: time.Unix(p.Exp, 0),
		NotBefore: time.Unix(p.Nbf, 0),
		IssuedAt:  time.Unix(p.Iat, 0),
		Extra:     p.Extra,
	}
	if p.Scope != "" {
		claims.Scopes = strings.Split(p.Scope, " ")
	}
	return claims, nil
}

// Revoke adds the token to an in-memory deny list. Returns an error when the
// token wasn't signed by this issuer, so that revokeAcrossIssuers correctly
// attributes ownership.
func (j *Ed25519JWTIssuer) Revoke(ctx context.Context, token string) error {
	if _, err := j.Validate(ctx, token); err != nil {
		return err
	}
	j.revokedMu.Lock()
	defer j.revokedMu.Unlock()
	j.revoked[token] = struct{}{}
	return nil
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
func (j *Ed25519JWTIssuer) IssueIDToken(_ context.Context, req *sso.IDTokenRequest) (string, error) {
	if req == nil || req.Subject == "" || req.Audience == "" {
		return "", errors.New("ed25519: id token requires subject + audience")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = j.tokenTTL
	}
	now := time.Now()
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTyp, Kid: j.keyID}
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
		Extra: req.Claims,
	}
	if !req.AuthTime.IsZero() {
		payload.AuthTime = req.AuthTime.Unix()
	}
	signingInput, err := idTokenSigningInput(header, payload)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(j.privateKey, signingInput)
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

// JWKS returns the issuer's public key as a single JWK suitable for inclusion
// in the /.well-known/jwks.json document. The sso package's JWKS handler
// calls this when an issuer implements sso.JWKSProvider.
func (j *Ed25519JWTIssuer) JWKS(_ context.Context) ([]sso.JWK, error) {
	return []sso.JWK{{
		Kty: jwkKtyOKP,
		Crv: jwkCrvEd25519,
		Kid: j.keyID,
		X:   base64.RawURLEncoding.EncodeToString(j.publicKey),
		Use: jwkUseSig,
		Alg: jwtAlgEdDSA,
	}}, nil
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

// fingerprintKid derives a deterministic kid from the public key — first 16
// hex chars of sha256(pubkey). Same key always yields the same kid.
func fingerprintKid(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// Compile-time check: the same issuer can mint OIDC ID Tokens, so
// operators don't need a second key + JWKS entry.
var _ sso.IDTokenIssuer = (*Ed25519JWTIssuer)(nil)
