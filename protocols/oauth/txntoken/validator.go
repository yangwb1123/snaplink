package txntoken

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/securityverify"
)

// Validator is the RECEIVING side: it validates a Txn-Token LOCALLY
// (signature + typ + exp/nbf + aud) so a downstream microservice — or the
// TTS itself, re-validating a Txn-Token presented as a nested
// subject_token — never has to round-trip back to the authorization
// server. It depends on nothing beyond a key source and this package,
// so a downstream service that doesn't run the rest of this SDK can
// construct one directly (see [StaticJWKS]).
type Validator struct {
	keys        core.JWKSProvider
	trustDomain string
	algs        map[string]struct{}
	clockSkew   time.Duration
}

// ValidatorOption configures a new Validator.
type ValidatorOption func(*Validator)

// WithValidatorAlgs restricts the asymmetric JWS algorithms Validate
// accepts. Unset (the default) uses securityverify.AsymmetricJWSAlgs() —
// the same allowlist DPoP/JAR/private_key_jwt already use. A symmetric or
// empty allowlist is rejected by securityverify.VerifyCompactJWS itself.
func WithValidatorAlgs(algs map[string]struct{}) ValidatorOption {
	return func(v *Validator) { v.algs = algs }
}

// WithValidatorClockSkew widens the exp/nbf acceptance window, matching
// the leeway RFC 7519 §4.1.4-5 permits. 0 (the default) is exact
// comparison.
func WithValidatorClockSkew(skew time.Duration) ValidatorOption {
	return func(v *Validator) {
		if skew > 0 {
			v.clockSkew = skew
		}
	}
}

// NewValidator constructs a Validator trusting keys for the given Trust
// Domain. keys is typically the SAME issuer minting Txn-Tokens (its JWKS()
// method already satisfies core.JWKSProvider) for same-process
// self-validation (the nested-mint case), or a [StaticJWKS] loaded once
// from the TTS's published JWKS document for a genuinely separate
// downstream service. Panics on a nil keys or empty trustDomain — a
// Validator that silently accepts everything (no aud check) or nothing
// (no keys) would be a dangerous, hard-to-notice misconfiguration for a
// security-critical verification primitive.
func NewValidator(keys core.JWKSProvider, trustDomain string, opts ...ValidatorOption) *Validator {
	if keys == nil {
		panic("txntoken: NewValidator requires a non-nil key source")
	}
	if trustDomain == "" {
		panic("txntoken: NewValidator requires a non-empty trust domain")
	}
	v := &Validator{keys: keys, trustDomain: trustDomain}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// StaticJWKS adapts a fixed key set to core.JWKSProvider, letting a
// downstream service that already fetched the TTS's JWKS once (e.g. via
// HTTP at startup, mirroring how security.NewStaticJWKS backs the SPIFFE
// trust bundle) construct a Validator with no dependency on any
// TokenIssuer or live JWKS endpoint.
type StaticJWKS []core.JWK

// JWKS implements core.JWKSProvider.
func (s StaticJWKS) JWKS(context.Context) ([]core.JWK, error) { return []core.JWK(s), nil }

// Validate verifies a compact Txn-Token: typ (BEFORE any signature work,
// same discipline as the alg-confusion gate in securityverify — a
// mis-typed token is refused before its signature is even inspected),
// signature (via securityverify.VerifyCompactJWS against this Validator's
// key source and alg allowlist), expiry/not-before, and audience (MUST
// equal this Validator's Trust Domain). Every failure is reported as a
// single class of error; callers that must stay oracle-safe (the nested
// TTS-side re-validation path) collapse ALL of them to the same
// invalid_grant every other subject_token failure returns.
func (v *Validator) Validate(ctx context.Context, compact string) (*Claims, error) {
	if v == nil || v.keys == nil {
		return nil, ErrNotConfigured
	}
	typ, err := peekTyp(compact)
	if err != nil {
		return nil, err
	}
	if typ != Typ {
		return nil, fmt.Errorf("txntoken: typ %q is not a Txn-Token", typ)
	}

	keys, err := v.keys.JWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("txntoken: fetch verification keys: %w", err)
	}
	algs := v.algs
	if algs == nil {
		algs = securityverify.AsymmetricJWSAlgs()
	}
	payload, err := securityverify.VerifyCompactJWS(compact, keys, algs)
	if err != nil {
		return nil, err
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("txntoken: decode claims: %w", err)
	}
	return &claims, v.checkClaims(&claims)
}

// checkClaims applies the exp/nbf/aud gates once the signature is
// already verified.
func (v *Validator) checkClaims(claims *Claims) error {
	now := time.Now()
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(v.clockSkew)) {
		return errors.New("txntoken: expired")
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-v.clockSkew)) {
		return errors.New("txntoken: not yet valid")
	}
	if claims.Aud != v.trustDomain {
		return fmt.Errorf("txntoken: aud %q is not trust domain %q", claims.Aud, v.trustDomain)
	}
	return nil
}

// peekTyp base64url-decodes JUST the JOSE header segment of a compact JWS
// and extracts `typ`, without touching the signature. Used to reject a
// shape-mismatched token (e.g. an ordinary access token) before any
// signature-verification work — the same "check BEFORE crypto" discipline
// securityverify.VerifyCompactJWS applies to `alg`.
func peekTyp(compact string) (string, error) {
	dot := -1
	for i := 0; i < len(compact); i++ {
		if compact[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 {
		return "", errors.New("txntoken: not a compact JWS")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(compact[:dot])
	if err != nil {
		return "", fmt.Errorf("txntoken: header decode: %w", err)
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return "", fmt.Errorf("txntoken: header parse: %w", err)
	}
	return h.Typ, nil
}
