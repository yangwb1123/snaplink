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
	jwtTyp        = "JWT" // OIDC ID tokens
	jwtTypAT      = "at+jwt" // RFC 9068 §2.1 — JWT Profile for OAuth 2.0 Access Tokens
	jwkKtyOKP     = "OKP"
	jwkCrvEd25519 = "Ed25519"
	jwkUseSig     = "sig"
)

// supportedJWTAlgs is the Validate-time allowlist. Per RFC 9068 §4
// the recipient MUST reject tokens whose `alg` is outside the
// allowlist (in particular: never `none`, never asymmetric algs
// confused with symmetric ones). Today we only sign EdDSA; extend
// this list only when a new signer is wired AND validated against
// the JWT algorithm-confusion threat model.
var supportedJWTAlgs = map[string]struct{}{
	jwtAlgEdDSA: {},
}

// supportedJWTTypes is the Validate-time `typ` allowlist for
// access tokens. `at+jwt` is the RFC 9068 §2.1 canonical value;
// `JWT` stays accepted for backward compatibility with tokens
// minted before the profile was wired (in-flight tokens at
// upgrade time keep verifying until their natural expiry).
// `application/at+jwt` is the long-form variant some libraries
// emit per RFC 9068 §2.1 footnote.
var supportedJWTTypes = map[string]struct{}{
	jwtTypAT:             {},
	"application/at+jwt": {},
	jwtTyp:               {},
}

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

	// verifyKeys maps kid → public key for additional verification-
	// only keys (previously-active signers being phased out). The
	// primary publicKey is registered here too at construction time
	// so Validate has one lookup path. Operators add additional
	// retired-but-still-trusted keys via [WithEd25519VerifyKey] so
	// in-flight tokens signed by the old key stay valid through
	// their TTL window after a rotation.
	verifyKeys map[string]ed25519.PublicKey

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

// WithEd25519VerifyKey adds a public key the issuer will accept on
// Validate but will NOT use to sign new tokens — the retired-signer
// half of a rotation. Operators add the OUTGOING key here for the
// duration of the access-token TTL after a key swap, so tokens
// minted before the swap stay verifiable until they expire
// naturally. Once the TTL window has passed, remove the option on
// the next deployment and the retired key disappears from JWKS.
//
// kid MUST be distinct from the primary signing key's kid and from
// every other verify-only key (key lookup is by kid in Validate).
// Idempotent: registering the same kid twice updates the public
// key without erroring — useful for testing rotations.
func WithEd25519VerifyKey(kid string, pub ed25519.PublicKey) Ed25519Option {
	return func(j *Ed25519JWTIssuer) {
		if j.verifyKeys == nil {
			j.verifyKeys = make(map[string]ed25519.PublicKey, 2)
		}
		j.verifyKeys[kid] = pub
	}
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
	if j.verifyKeys == nil {
		j.verifyKeys = make(map[string]ed25519.PublicKey, 1)
	}
	// Always register the primary signing key in the verify map so
	// Validate has one lookup path (no special-case for "primary").
	j.verifyKeys[j.keyID] = j.publicKey
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
	Iss      string            `json:"iss,omitempty"`
	Sub      string            `json:"sub,omitempty"`
	Aud      audClaim          `json:"aud,omitempty"`
	Exp      int64             `json:"exp,omitempty"`
	Nbf      int64             `json:"nbf,omitempty"`
	Iat      int64             `json:"iat,omitempty"`
	Scope    string            `json:"scope,omitempty"`
	Extra    map[string]string `json:"ext,omitempty"`

	// RFC 9068 §2.2 access-token claims.
	ClientID string   `json:"client_id,omitempty"`
	JTI      string   `json:"jti,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"`
	ACR      string   `json:"acr,omitempty"`
	AMR      []string `json:"amr,omitempty"`

	// RFC 9396 — Rich Authorization Requests. Pass-through of
	// the original `authorization_details` array as raw JSON so
	// extension fields survive without an explicit schema here.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
}

// audClaim handles RFC 7519 §4.1.3's polymorphic `aud` claim. Per
// the spec it's "an array of case-sensitive strings"; "in the
// special case when the JWT has one audience, the aud value MAY be
// a single case-sensitive string." OIDC ID tokens favor the
// single-string form; access tokens here favor the array form.
// Tolerating both lets one Validate path handle every shape.
type audClaim []string

func (a *audClaim) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*a = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

func (a audClaim) MarshalJSON() ([]byte, error) {
	// Single-audience tokens stay compact-string per OIDC convention;
	// multi-audience marshals as an array.
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
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

	// RFC 9068 §2.1: header `typ` MUST be `at+jwt` to distinguish
	// access tokens from other JWT shapes (ID tokens, generic JWT)
	// so strict resource servers can reject misrouted tokens.
	header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTypAT, Kid: j.keyID}

	// RFC 9068 §2.2 REQUIRES jti — a unique identifier per token,
	// suitable for replay tracking + revocation lookup. 16 bytes
	// = 128 bits = collision-free at any practical issue rate.
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("ed25519: generate jti: %w", err)
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
	// RFC 8707 resource indicators flow through Subject.Resources
	// into the standard `aud` JWT claim. Resource servers verify
	// their own URI is in the array before accepting the token.
	if len(subject.Resources) > 0 {
		payload.Aud = audClaim(append([]string(nil), subject.Resources...))
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

// generateJTI mints a 16-byte (128-bit) base64url-encoded unique
// identifier for the `jti` claim per RFC 9068 §2.2.
func generateJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
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

	// RFC 9068 §4: parse the header explicitly so the algorithm
	// and typ allowlists are enforced BEFORE signature verification
	// even runs. Defends against alg-confusion attacks (e.g.
	// alg=none, alg=HS256-spoofed-with-RS256-public-key) and
	// against a token meant for a different shape (ID token,
	// generic JWT) being accepted as an access token.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("ed25519: header decode: %w", err)
	}
	var h ed25519Header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("ed25519: header parse: %w", err)
	}
	if _, ok := supportedJWTAlgs[h.Alg]; !ok {
		return nil, fmt.Errorf("ed25519: alg %q not in allowlist", h.Alg)
	}
	// Empty typ is tolerated for legacy tokens minted before this
	// gate landed (back-compat); a non-empty typ MUST be in the
	// allowlist.
	if h.Typ != "" {
		if _, ok := supportedJWTTypes[h.Typ]; !ok {
			return nil, fmt.Errorf("ed25519: typ %q not in allowlist", h.Typ)
		}
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("ed25519: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]

	// Pick the verification key by the JWT header's kid. Tokens
	// without a kid (legacy) fall back to the primary key —
	// rotation needs every minted token to carry a kid for the
	// lookup to be O(1), which `Issue` does unconditionally.
	pub := j.lookupVerifyKey(parts[0])
	if pub == nil {
		return nil, errors.New("ed25519: unknown kid")
	}
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
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
		Audience:  []string(p.Aud),
		ExpiresAt: time.Unix(p.Exp, 0),
		NotBefore: time.Unix(p.Nbf, 0),
		IssuedAt:  time.Unix(p.Iat, 0),
		Extra:     p.Extra,
		ClientID:  p.ClientID,
		JTI:       p.JTI,
		ACR:       p.ACR,
		AMR:       append([]string(nil), p.AMR...),
	}
	if p.AuthTime > 0 {
		claims.AuthTime = time.Unix(p.AuthTime, 0)
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

// lookupVerifyKey selects the verification key matching the JWT
// header's kid. Returns the primary publicKey when the header is
// missing kid (legacy tokens without a kid still verify under the
// primary), or nil when the kid is supplied but unrecognised so
// Validate can fail closed on an unknown signer.
func (j *Ed25519JWTIssuer) lookupVerifyKey(headerB64 string) ed25519.PublicKey {
	raw, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil
	}
	var h ed25519Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil
	}
	if h.Kid == "" {
		return j.publicKey
	}
	if pub, ok := j.verifyKeys[h.Kid]; ok {
		return pub
	}
	return nil
}

// JWKS returns the issuer's public keys as JWKs for inclusion in
// /.well-known/jwks.json. During a key rotation this emits BOTH
// the primary signing key AND every WithEd25519VerifyKey retired
// key, so RPs that pulled a token before the rotation can still
// verify it after the swap.
//
// Output order: primary first, then verify-only keys in
// fingerprint-sorted order. Stable across one process lifetime so
// the JWKS ETag stays valid until something actually changes.
func (j *Ed25519JWTIssuer) JWKS(_ context.Context) ([]sso.JWK, error) {
	out := []sso.JWK{{
		Kty: jwkKtyOKP,
		Crv: jwkCrvEd25519,
		Kid: j.keyID,
		X:   base64.RawURLEncoding.EncodeToString(j.publicKey),
		Use: jwkUseSig,
		Alg: jwtAlgEdDSA,
	}}
	// Collect kids of verify-only keys (skip the primary, already
	// emitted above).
	verifyKids := make([]string, 0, len(j.verifyKeys))
	for kid := range j.verifyKeys {
		if kid == j.keyID {
			continue
		}
		verifyKids = append(verifyKids, kid)
	}
	// Sort for deterministic output — the JWKS ETag depends on it.
	sortStrings(verifyKids)
	for _, kid := range verifyKids {
		out = append(out, sso.JWK{
			Kty: jwkKtyOKP,
			Crv: jwkCrvEd25519,
			Kid: kid,
			X:   base64.RawURLEncoding.EncodeToString(j.verifyKeys[kid]),
			Use: jwkUseSig,
			Alg: jwtAlgEdDSA,
		})
	}
	return out, nil
}

// sortStrings is a tiny non-allocating bubble sort to avoid
// importing "sort" just for one ordering site. n is bounded by the
// number of retired keys an operator carries — typically 1, almost
// never more than a handful.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
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
