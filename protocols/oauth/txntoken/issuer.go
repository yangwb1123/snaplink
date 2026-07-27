package txntoken

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// Issuer is the Transaction Token Service (TTS) minting side — it mints a
// Txn-Token from a validated inbound access token (first hop) or from a
// previously-issued, re-validated Txn-Token (a nested hop). One Issuer
// serves exactly one Trust Domain, matching RFC 9321's model of a Txn-Token
// being valid within a single trust boundary; a deployment spanning
// multiple trust domains wires one Issuer (+ Validator) pair per domain.
type Issuer struct {
	signer      Signer
	issuerName  string
	trustDomain string
	ttl         time.Duration
}

// IssuerOption configures a new Issuer.
type IssuerOption func(*Issuer)

// WithIssuerName sets the `iss` claim stamped on every minted Txn-Token.
// Empty (the default) omits nothing — Mint always stamps SOME value, so an
// unset name yields an empty `iss` string, which is legal JSON but rarely
// what an operator wants; callers SHOULD set this to the same issuer URL
// their access tokens use.
func WithIssuerName(name string) IssuerOption {
	return func(i *Issuer) { i.issuerName = name }
}

// WithTTL overrides DefaultTTL for every Txn-Token this Issuer mints.
// d <= 0 is ignored (keeps the current default).
func WithTTL(d time.Duration) IssuerOption {
	return func(i *Issuer) {
		if d > 0 {
			i.ttl = d
		}
	}
}

// NewIssuer constructs an Issuer bound to one Trust Domain. signer is
// typically the SAME defaultimpl issuer minting this server's access
// tokens (its SignJWT method structurally satisfies Signer) — reusing it
// means a receiving workload verifies a Txn-Token against the SAME JWKS it
// already trusts for access tokens. Panics on a nil signer or empty
// trustDomain: both are required for this type to do anything meaningful,
// and a silently-inert Issuer would be a confusing partial success.
func NewIssuer(signer Signer, trustDomain string, opts ...IssuerOption) *Issuer {
	if signer == nil {
		panic("txntoken: NewIssuer requires a non-nil Signer")
	}
	if trustDomain == "" {
		panic("txntoken: NewIssuer requires a non-empty trust domain")
	}
	iss := &Issuer{signer: signer, trustDomain: trustDomain, ttl: DefaultTTL}
	for _, opt := range opts {
		opt(iss)
	}
	return iss
}

// TrustDomain returns the Trust Domain this Issuer mints Txn-Tokens for —
// exposed so the grant-dispatch layer can validate an inbound `audience`
// request parameter against it before ever calling Mint.
func (iss *Issuer) TrustDomain() string { return iss.trustDomain }

// MintRequest carries everything Mint needs for one hop of Txn-Token
// issuance — either the FIRST hop (from an ordinary access token) or a
// NESTED hop (from an existing Txn-Token presented as subject_token).
type MintRequest struct {
	// Subject is the transaction's principal — the inbound access
	// token's `sub` on a first hop, or the existing Txn-Token's `sub`
	// UNCHANGED on a nested hop (RFC 9321: the principal never changes
	// across the chain, only the requesting workload does).
	Subject string

	// RequestingWorkload identifies the caller of THIS Issuer for this
	// hop (the authenticated OAuth client_id at the /token request) and
	// becomes the new outermost `act` link. Empty leaves Act as
	// PriorChain unchanged (no new link) — the rare case of re-minting
	// with no distinct workload identity to record.
	RequestingWorkload string

	// PriorChain is the `act` chain to prepend the new link onto — nil
	// on a first hop; the previously-validated Txn-Token's Act on a
	// nested hop.
	PriorChain *core.ActorClaim

	// TrustDomain MUST equal this Issuer's configured TrustDomain(); Mint
	// fails closed otherwise (a request naming a foreign trust domain is
	// never honored).
	TrustDomain string

	// Purpose is copied verbatim into `purp`. Empty omits the claim.
	Purpose string

	// RequestContext is copied verbatim into `rctx`. Nil/empty omits the
	// claim.
	RequestContext json.RawMessage

	// AuthorizationDetails is copied verbatim into `azd`. On a first hop
	// this is the inbound access token's RFC 9396 authorization_details;
	// on a nested hop the caller MUST pass through the prior Txn-Token's
	// own Azd unchanged (RFC 9321's immutability requirement) rather than
	// deriving a new value.
	AuthorizationDetails json.RawMessage

	// TTL overrides this Issuer's configured ttl for this ONE mint. <= 0
	// uses the Issuer default.
	TTL time.Duration
}

// Mint issues one Txn-Token. Returns the compact JWS plus the Claims that
// were signed (so the caller can read back Exp / Txn / Act without
// re-parsing the token it just minted).
func (iss *Issuer) Mint(ctx context.Context, req MintRequest) (string, *Claims, error) {
	if err := iss.validateMintRequest(req); err != nil {
		return "", nil, err
	}
	txn, err := newTxnID()
	if err != nil {
		return "", nil, fmt.Errorf("txntoken: generate txn id: %w", err)
	}
	claims := iss.buildClaims(req, txn)

	signed, err := iss.signer.SignJWT(ctx, Typ, claims)
	if err != nil {
		return "", nil, fmt.Errorf("txntoken: sign: %w", err)
	}
	return signed, claims, nil
}

// validateMintRequest runs Mint's pre-flight gates, BEFORE any txn id is
// generated or claims are built.
func (iss *Issuer) validateMintRequest(req MintRequest) error {
	if iss == nil || iss.signer == nil {
		return ErrNotConfigured
	}
	if req.Subject == "" {
		return fmt.Errorf("txntoken: mint requires a subject")
	}
	if req.TrustDomain == "" || req.TrustDomain != iss.trustDomain {
		return fmt.Errorf("txntoken: mint requires trust domain %q, got %q", iss.trustDomain, req.TrustDomain)
	}
	if chainDepth(req.PriorChain) >= MaxChainDepth {
		return ErrChainTooDeep
	}
	return nil
}

// buildClaims assembles the Claims payload for one mint, given an
// already-generated txn id. Extracted from Mint to keep it within the
// function-length budget.
func (iss *Issuer) buildClaims(req MintRequest, txn string) *Claims {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = iss.ttl
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	now := time.Now()
	claims := &Claims{
		Iss:  iss.issuerName,
		Sub:  req.Subject,
		Aud:  req.TrustDomain,
		Exp:  now.Add(ttl).Unix(),
		Iat:  now.Unix(),
		Txn:  txn,
		Purp: req.Purpose,
		Rctx: core.CloneRawJSON(req.RequestContext),
		Azd:  core.CloneRawJSON(req.AuthorizationDetails),
		Act:  req.PriorChain,
	}
	// Prepend the new link OUTSIDE the prior chain — mirrors RFC 8693
	// §4.1.1's act-chain prepend (tokengrant.tokExResolveActor): the
	// requesting workload for THIS hop becomes the outermost (most
	// recent) entry, nesting whatever chain it was linked onto.
	if req.RequestingWorkload != "" {
		claims.Act = &core.ActorClaim{Subject: req.RequestingWorkload, Actor: req.PriorChain}
	}
	return claims
}

// newTxnID mints a 128-bit base64url-encoded unique transaction
// identifier for the `txn` claim — sized identically to the access-token
// jti / SET jti so collisions are not a practical concern at any
// realistic mint rate.
func newTxnID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
