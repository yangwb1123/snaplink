package defaultimpl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/core"
)

type ed25519Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type ed25519Payload struct {
	Iss   string   `json:"iss,omitempty"`
	Sub   string   `json:"sub,omitempty"`
	Aud   audClaim `json:"aud,omitempty"`
	Exp   int64    `json:"exp,omitempty"`
	Nbf   int64    `json:"nbf,omitempty"`
	Iat   int64    `json:"iat,omitempty"`
	Scope string   `json:"scope,omitempty"`
	// GrantedResources is an ID-token-only private binding used to prevent
	// prompt=none renewal from expanding the original RFC 8707 grant.
	GrantedResources []string          `json:"_resources,omitempty"`
	Extra            map[string]string `json:"ext,omitempty"`

	// RFC 9068 §2.2 access-token claims.
	ClientID string             `json:"client_id,omitempty"`
	JTI      string             `json:"jti,omitempty"`
	AuthTime int64              `json:"auth_time,omitempty"`
	ACR      string             `json:"acr,omitempty"`
	AMR      []string           `json:"amr,omitempty"`
	SID      string             `json:"sid,omitempty"`
	CNF      *confirmationClaim `json:"cnf,omitempty"`

	// ServingRegion is the mint-region evidence claim (SnapLink
	// extension). Stamped from the region middleware stash at mint time;
	// omitempty omits it when no region was resolved, so the JSON is
	// byte-identical to pre-region builds.
	ServingRegion string `json:"serving_region,omitempty"`

	// TenantID is the mint-time client-binding tenant claim (SnapLink
	// extension; RFC 9068 has no tenant claim), projected from
	// Subject.TenantID by buildAccessPayload. Unconditional-literal
	// discipline (ServingRegion precedent): omitempty performs the
	// omission, so the wire needs no guard. Whenever this literal is
	// emitted, buildAccessPayload strips the same-named `ext` key via
	// claimsWithoutEmittedKeys — one claim name, one value per token.
	TenantID string `json:"tenant_id,omitempty"`

	// Roles is the tenant-membership role-code claim (SnapLink extension),
	// projected from Subject.Roles by buildAccessPayload with the AMR
	// guard+copy discipline (emitted only when non-empty). Same strip
	// coupling as TenantID: the `ext` copy of `roles` is removed when this
	// top-level claim is emitted.
	Roles []string `json:"roles,omitempty"`

	// RFC 9396 — Rich Authorization Requests. Pass-through of
	// the original `authorization_details` array as raw JSON so
	// extension fields survive without an explicit schema here.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`

	// RFC 8693 §4.1 `act` claim for delegation chains. Populated
	// by the token-exchange grant when an actor_token is
	// presented; nil for direct (non-delegated) tokens.
	Act *actClaim `json:"act,omitempty"`

	// RequestedClaims carries the OIDC Core §5.5 `claims` parameter
	// so /userinfo can project RP-requested claims from the token.
	RequestedClaims json.RawMessage `json:"_claims_,omitempty"`
}

// confirmationClaim is RFC 7800 §3.1's `cnf` JSON object. RFC 9449
// §6 uses the `jkt` member to carry a DPoP key's JWK thumbprint;
// RFC 8705 §3.1 uses `x5t#S256` to carry the mTLS client cert
// thumbprint. A single token uses one mechanism — both fields
// populated simultaneously would be a caller bug.
type confirmationClaim struct {
	JKT     string `json:"jkt,omitempty"`
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// actClaim is the wire shape of `act`. Per RFC 8693 §4.1 the
// claim is a JSON object with at least `sub` and an optional
// nested `act` for multi-hop delegation chains. Mirrors
// sso.ActorClaim's structure on the public API side.
type actClaim struct {
	Sub string    `json:"sub,omitempty"`
	Act *actClaim `json:"act,omitempty"`
}

// actorChainToWire walks an sso.ActorClaim chain (outermost-first)
// into the wire-shape actClaim chain. nil-safe — returns nil so
// "no delegation" stays distinguishable from "empty chain" in the
// emitted JWT.
func actorChainToWire(a *sso.ActorClaim) *actClaim {
	if a == nil || a.Subject == "" {
		return nil
	}
	return &actClaim{Sub: a.Subject, Act: actorChainToWire(a.Actor)}
}

// wireChainToActor is the inverse: rebuild the sso.ActorClaim
// chain from a validated JWT's act tree. nil-safe.
func wireChainToActor(a *actClaim) *sso.ActorClaim {
	if a == nil || a.Sub == "" {
		return nil
	}
	return &sso.ActorClaim{Subject: a.Sub, Actor: wireChainToActor(a.Act)}
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
	Iss                  string            `json:"iss,omitempty"`
	Sub                  string            `json:"sub,omitempty"`
	Aud                  string            `json:"aud,omitempty"`
	Exp                  int64             `json:"exp,omitempty"`
	Iat                  int64             `json:"iat,omitempty"`
	Nonce                string            `json:"nonce,omitempty"`
	AtHash               string            `json:"at_hash,omitempty"`
	DsHash               string            `json:"ds_hash,omitempty"`
	AuthTime             int64             `json:"auth_time,omitempty"`
	AMR                  []string          `json:"amr,omitempty"`
	ACR                  string            `json:"acr,omitempty"`
	AZP                  string            `json:"azp,omitempty"`
	SID                  string            `json:"sid,omitempty"`
	Extra                map[string]string `json:"ext,omitempty"`
	Scope                string            `json:"scope,omitempty"`
	GrantedResources     []string          `json:"_resources,omitempty"`
	AuthorizationDetails json.RawMessage   `json:"authorization_details,omitempty"`

	// ServingRegion mirrors the access-token claim (SnapLink extension):
	// the regional deployment that minted this ID token. First-class
	// field (never an `ext` map entry) so OIDC §5.5 ProjectIDTokenClaims
	// — which filters only the Extra map — can never drop it.
	ServingRegion string `json:"serving_region,omitempty"`
}

// Ed25519 issuer construction options and key-loading helpers, kept in this
// file (not ed25519_jwt_issuer.go) to hold that file under the 500-line
// maintainability budget. Same package; no behavior change.
// Ed25519Signer abstracts the raw EdDSA signing operation so the
// process-held private key can be swapped for a KMS/HSM-backed signer
// without touching JWT assembly. Sign receives the JWS signing input
// (the "header.payload" bytes) and returns the 64-byte Ed25519
// signature. It MAY return an error (e.g. a KMS round-trip failure);
// every call site propagates it, so token issuance fails closed rather
// than emitting an unsigned token.
type Ed25519Signer interface {
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

// softwareEd25519Signer is the default in-process signer.
type softwareEd25519Signer struct{ priv ed25519.PrivateKey }

func (s softwareEd25519Signer) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

type Ed25519Option func(*Ed25519JWTIssuer)

func WithEd25519Issuer(name string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.issuer = name }
}

func WithEd25519TokenTTL(ttl time.Duration) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.tokenTTL = ttl }
}

// WithEd25519MaxClockSkew widens the inbound exp/nbf validation
// window per RFC 7519 §4.1.4-5. Useful when AS and resource server
// clocks drift (NTP-managed clocks routinely drift 100ms-1s; a
// well-managed pair drifts under 5s). Default 0 = exact comparison.
// Recommended production value: 30s-2min. Going much higher widens
// the window an attacker has to replay an expired token.
func WithEd25519MaxClockSkew(skew time.Duration) Ed25519Option {
	return func(j *Ed25519JWTIssuer) {
		if skew > 0 {
			j.maxClockSkew = skew
		}
	}
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

// WithEd25519KeyFile persists the Ed25519 signing key to a PEM file
// (PKCS#8) so a process restart reuses the same key (kid stable across
// restarts — the deployed `rotation.enabled=false` profile otherwise
// regenerates the key on every boot and silently invalidates every
// issued token). First run: generate + write (0600, atomic rename).
// Subsequent runs: load. External signer wins when both are set.
func WithEd25519KeyFile(path string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) {
		if j.signer != nil || path == "" {
			return
		}
		priv, err := loadOrGenerateEd25519Key(path)
		if err != nil {
			panic(fmt.Sprintf("ed25519: key file %s: %v", path, err))
		}
		j.privateKey = priv
		j.publicKey = priv.Public().(ed25519.PublicKey)
	}
}

func loadOrGenerateEd25519Key(path string) (ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("decode PEM")
		}
		der, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8: %w", err)
		}
		priv, ok := der.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an Ed25519 key")
		}
		return priv, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pemBytes, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return priv, nil
}

// WithEd25519KeyID overrides the auto-derived kid.
func WithEd25519KeyID(kid string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.keyID = kid }
}

// WithEd25519Clock overrides the wall clock Issue/IssueIDToken/
// IssueLogoutToken read for iat/nbf/exp. Test-only knob: nil (the
// default every issuer starts with) means every call reads the real
// time.Now(), byte-identical to the code before Clock existed. Wiring a
// fixed or steppable Clock lets a test assert exact claim values without
// sleeping or tolerating a timing window.
func WithEd25519Clock(c Clock) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.clock = c }
}

// WithEd25519Metrics wires per-(alg,kid) signing-usage observability
// (sso_signing_key_usage_total). Optional — a nil or omitted Metrics keeps
// every Sign call a no-op observation, byte-identical to a build without it.
func WithEd25519Metrics(m *metrics.Metrics) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.metrics = m }
}

// recordSigningUsage bumps the signing-usage counter for a successful
// in-process sign. Nil-safe; called from every Issue*/SignJWT method right
// after their sgn.Sign succeeds, never from JWKS/lookup paths that don't
// actually sign.
func (j *Ed25519JWTIssuer) recordSigningUsage(kid string) {
	j.metrics.ObserveSigningUsage(metricsAlgEdDSA, kid)
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

// WithEd25519ExternalSigner injects a signer whose private key lives
// outside this process (AWS KMS, GCP KMS, an HSM via PKCS#11). pub is
// the corresponding Ed25519 public key — published in JWKS and used by
// Validate — and kid names it in issued tokens' headers. The issuer
// never generates or holds a private key in this mode.
//
// pub MUST be the public half of the key the signer signs with;
// otherwise every issued token fails verification. kid SHOULD be stable
// across replicas sharing the same external key so JWKS lookups agree.
func WithEd25519ExternalSigner(signer Ed25519Signer, pub ed25519.PublicKey, kid string) Ed25519Option {
	return func(j *Ed25519JWTIssuer) {
		j.signer = signer
		j.publicKey = pub
		if kid != "" {
			j.keyID = kid
		}
	}
}

// WithEd25519KeyOrigin sets the key origin attestation for this issuer's
// signing key. Defaults to OriginUnattested (software). Callers that wire
// a KMS/HSM-backed external signer SHOULD set this to the appropriate
// value so the JWKS endpoint publishes the origin for compliance audits.
func WithEd25519KeyOrigin(origin core.KeyOrigin) Ed25519Option {
	return func(j *Ed25519JWTIssuer) { j.keyOrigin = origin }
}
