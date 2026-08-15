package caep

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// SET wire constants per RFC 8417 (Security Event Token) and the
// OpenID Shared Signals Framework (SSF) / CAEP + RISC event profiles.
const (
	// SecurityEventTokenTyp is the RFC 8417 §2.3 REQUIRED media type for
	// the JOSE `typ` header. It MUST be stamped so a receiver's JWT
	// library never confuses a SET for an access token or ID token — the
	// strict access-token validators in this codebase reject anything
	// outside their own `at+jwt` allowlist, and an RP's SET pipeline
	// likewise keys off this value.
	SecurityEventTokenTyp = "secevent+jwt"

	// DefaultSETTTL bounds a SET's lifetime. Short on purpose — a SET is
	// processed on receipt (it carries a one-shot security signal); a
	// stale SET delivered late has no use and only widens the replay
	// window an attacker could exploit if it leaked. Mirrors the
	// short-lived logout-token convention.
	DefaultSETTTL = 2 * time.Minute
)

// SSF / RISC / CAEP event URIs. These name the keys inside the SET's
// `events` claim (RFC 8417 §2.2). Receivers branch on these URIs to
// decide what local action to take (kill sessions, disable the account,
// re-evaluate claims). v1 implements the small subset the existing
// internal audit events map cleanly onto; see event_mapper.go.
const (
	// EventURIRISCAccountDisabled — OpenID RISC: the subject's account
	// was disabled at the IdP. Receivers SHOULD terminate the subject's
	// sessions and refuse further access.
	EventURIRISCAccountDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"

	// EventURIRISCAccountEnabled — OpenID RISC: the subject's account was
	// re-enabled at the IdP. Emitted on a lifecycle transition back into
	// ACTIVE so an RP that disabled the subject on account-disabled can
	// resume honoring it (reinstated suspension, restored archive). The
	// stock receiver no-ops events it does not act on, so this positive
	// signal is safe for RPs that do not handle it.
	EventURIRISCAccountEnabled = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"

	// EventURICAEPSessionRevoked — OpenID CAEP: a session for the subject
	// was revoked. The real-time cross-RP revocation primitive: an RP that
	// receives this for a subject it has an active session for SHOULD
	// terminate that session immediately rather than wait for token TTL.
	EventURICAEPSessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

	// EventURICAEPTokenClaimsChange — OpenID CAEP: claims bound to the
	// subject's tokens changed (e.g. a refresh-token family was killed
	// after reuse detection, so previously-minted access tokens should no
	// longer be trusted at face value).
	EventURICAEPTokenClaimsChange = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"

	// EventURICAEPTokenRevoked — OpenID CAEP (RFC 9491 token-revocation
	// profile): a specific token was revoked at the IdP.
	EventURICAEPTokenRevoked = "https://schemas.openid.net/secevent/caep/event-type/token-revoked"
)

// JWTSigner is the narrow generic-JWT signing seam the transmitter
// consumes. It is satisfied structurally by the Ed25519 / ECDSA / RSA
// issuers in defaultimpl (their SignJWT method) — the SAME signer that
// mints access + ID + logout tokens and whose public key is already
// published in JWKS. Reusing it means a relying party validates a SET
// with no new trust setup: the SET's kid resolves to a key the RP
// already trusts.
//
// Defined here (not in root sso) so the caep package depends only on
// core + audit, keeping the import graph acyclic (root sso imports caep
// for WithCAEPTransmitter; caep must therefore not import root sso).
type JWTSigner interface {
	// SignJWT signs claims as a compact JWS stamping `typ` in the header,
	// using the issuer's active signing key + kid. typ MUST be non-empty.
	SignJWT(ctx context.Context, typ string, claims any) (string, error)
}

// setClaims is the RFC 8417 Security Event Token payload. Field order
// follows the spec's prose: iss, jti, iat, aud, plus the subject
// identifier and the events map.
//
// SubID is the RFC 9493 "Subject Identifiers for SETs" object. v1 emits
// the simple `{"format":"opaque","id":<subject>}` shape — enough for an
// RP to match the SET to a local account by the same subject string it
// received in the original id_token `sub`. Encrypted SETs and richer
// subject-identifier formats (email, iss_sub, phone) are v2.
type setClaims struct {
	Iss    string                     `json:"iss"`
	Jti    string                     `json:"jti"`
	Iat    int64                      `json:"iat"`
	Exp    int64                      `json:"exp,omitempty"`
	Aud    []string                   `json:"aud"`
	SubID  *subjectIdentifier         `json:"sub_id,omitempty"`
	Events map[string]json.RawMessage `json:"events"`
}

// subjectIdentifier is the RFC 9493 §3 Subject Identifier carried in the
// `sub_id` claim. Opaque format keeps v1 minimal — the id is exactly the
// subject string the RP already knows from the id_token.
type subjectIdentifier struct {
	Format string `json:"format"`
	ID     string `json:"id"`
}

const subjectIdentifierFormatOpaque = "opaque"

// buildSETRequest carries everything needed to mint one SET for one
// receiver. Issuer is the SET `iss` (the AS issuer URL — the same value
// the RP sees in its tokens, so it can pin the expected SET issuer).
// Audience is the single receiver this SET is addressed to (decision 2:
// one SET per affected receiver, never a broadcast). Subject is the
// affected end-user. Events is the already-built `events` map (one or
// more SSF/CAEP/RISC URIs → their per-event payload object).
type buildSETRequest struct {
	Issuer   string
	Audience string
	Subject  string
	Events   map[string]json.RawMessage
}

// mintSET builds the RFC 8417 SET payload and signs it via the generic
// JWT path (typ=secevent+jwt). A fresh 128-bit jti is generated per call
// so a receiver can defend against replay (RFC 8417 §2.2 RECOMMENDS jti
// uniqueness; our two-emission test asserts it). The SET is signed by the
// same key already in JWKS, so the RP verifies with no new trust setup.
func mintSET(ctx context.Context, signer JWTSigner, req buildSETRequest, ttl time.Duration) (string, error) {
	if signer == nil {
		return "", errors.New("caep: nil signer")
	}
	if req.Audience == "" {
		return "", errors.New("caep: SET requires a receiver audience")
	}
	if len(req.Events) == 0 {
		return "", errors.New("caep: SET requires at least one event")
	}
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = DefaultSETTTL
	}
	now := time.Now()
	claims := setClaims{
		Iss:    req.Issuer,
		Jti:    jti,
		Iat:    now.Unix(),
		Exp:    now.Add(ttl).Unix(),
		Aud:    []string{req.Audience},
		Events: req.Events,
	}
	if req.Subject != "" {
		claims.SubID = &subjectIdentifier{Format: subjectIdentifierFormatOpaque, ID: req.Subject}
	}
	return signer.SignJWT(ctx, SecurityEventTokenTyp, claims)
}

// newJTI mints a 128-bit base64url-encoded unique token identifier for
// the SET `jti` claim. Sized identically to the access-token jti so
// collisions are not a practical concern at any emission rate.
func newJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
