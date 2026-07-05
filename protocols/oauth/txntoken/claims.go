// Package txntoken implements RFC 9321 OAuth 2.0 Transaction Tokens
// (Txn-Tokens): a short-lived, workload-identity-bound token minted by a
// Transaction Token Service (TTS) from an inbound OAuth access token — or,
// for a further hop, from a previously-issued Txn-Token — that propagates
// the ORIGINAL caller's authorization context across a chain of internal
// microservice calls within one trust domain. Unlike an access token, a
// Txn-Token is meant to be verified LOCALLY (signature + exp + aud) by
// every hop, with no round trip back to the AS.
//
// Wire shape mirrors the draft: `typ: txn-token+jwt`, `aud` names the
// Trust Domain, `sub` is the transaction's principal (unchanged across
// hops), `txn` is a per-transaction audit correlator, `purp` is the
// caller-supplied purpose of THIS specific request, `rctx` is an opaque
// caller-supplied request-context object, `azd` is the RFC 9396
// authorization_details carried IMMUTABLY from the first hop, and `act`
// is the RFC 8693 §4.1-shaped chain of requesting workloads — reusing
// core.ActorClaim and the SAME prepend-and-nest convention the RFC 8693
// token-exchange grant already uses (internal/handler/tokengrant), so a
// multi-hop internal call chain reads outside-in exactly like an `act`
// chain does today.
//
// Fully opt-in: nothing in this package is reachable unless the host
// wires an [Issuer] (interfaces/sso's WithTransactionTokens) — an
// unconfigured server is byte-identical to one built without this
// package.
package txntoken

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/snaplink/sso/shared/core"
)

const (
	// Typ is the RFC 9321 REQUIRED JOSE `typ` header value. It MUST be
	// stamped so a strict verifier never confuses a Txn-Token for an RFC
	// 9068 access token (`at+jwt`) or any other JWT shape signed by the
	// same key — mirrors the discipline access/ID/logout/SET tokens
	// already apply to their own `typ` values.
	Typ = "txn-token+jwt"

	// TokenType is the RFC 9321 token-type URN. A caller sets it as the
	// /token request's `requested_token_type` to ask for a Txn-Token
	// instead of an ordinary RFC 8693 exchanged access token; the AS
	// echoes it back as `issued_token_type` on success.
	TokenType = "urn:ietf:params:oauth:token-type:txn-token"

	// TokenTypeNameNA is the RFC 8693 §2.2.1 `token_type` response value
	// for an issued token that is not a bearer credential meant for the
	// `Authorization: Bearer` header — a Txn-Token is propagated over its
	// own dedicated internal channel/header, never as a bearer token.
	TokenTypeNameNA = "N_A"

	// MaxChainDepth caps the workload delegation (`act`) chain length a
	// nested mint (Txn-Token-from-Txn-Token) may prepend onto — the exact
	// rationale and value as tokengrant.MaxActChainDepth (RFC 8693 §4.1):
	// unbounded nesting risks unbounded processing cost on every further
	// hop.
	MaxChainDepth = 10

	// DefaultTTL bounds a Txn-Token's lifetime when the Issuer wasn't
	// given an explicit one. Deliberately much shorter than a normal
	// access token — a Txn-Token exists only to cross one internal call
	// chain, not to be held or retried later.
	DefaultTTL = 30 * time.Second
)

// ErrChainTooDeep is returned by Issuer.Mint when the prior `act` chain
// (from a nested Txn-Token-from-Txn-Token mint) has already reached
// MaxChainDepth. Callers collapse it to the SAME oracle-safe
// invalid_grant every other token-exchange chain failure returns.
var ErrChainTooDeep = errors.New("txntoken: act chain exceeds max depth")

// ErrNotConfigured is returned by Mint/Validate when called on a nil or
// zero-value Issuer/Validator — defensive backstop; the wiring layer
// (interfaces/sso) never dispatches into this package unless both are
// non-nil, so this indicates a caller bypassing the normal wiring path.
var ErrNotConfigured = errors.New("txntoken: not configured")

// Claims is the RFC 9321 Txn-Token JWT payload.
type Claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	// Aud MUST identify the Trust Domain the Txn-Token is valid in — a
	// single string (not an array), unlike an RFC 9068 access token's aud.
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf,omitempty"`

	// Txn is a unique per-transaction identifier. Logged by the TTS and
	// (by convention) every workload it passes through, so operators can
	// correlate a request's full call chain across services for audit /
	// troubleshooting — independent of any per-hop token's own jti.
	Txn string `json:"txn"`

	// Purp is the caller-supplied purpose of THIS specific request —
	// narrower than an OAuth scope (e.g. "refund.issue" rather than
	// "payments:write"). Set fresh per hop; unlike Azd it is NOT required
	// to stay constant across the chain.
	Purp string `json:"purp,omitempty"`

	// Rctx is the RFC 9321 request_context: an opaque, caller-supplied
	// JSON object describing the environmental context of this specific
	// request (e.g. a trace id). Set fresh per hop.
	Rctx json.RawMessage `json:"rctx,omitempty"`

	// Azd is the RFC 9321 azd claim — carries the RFC 9396
	// authorization_details bound at the FIRST hop. Per RFC 9321 it MUST
	// remain constant through the call chain, so every nested mint
	// propagates the immediately-prior Txn-Token's Azd byte-for-byte
	// rather than accepting a caller override.
	Azd json.RawMessage `json:"azd,omitempty"`

	// Act is the requesting-workload delegation chain, in the SAME
	// shape + prepend-and-nest convention as the RFC 8693 §4.1 `act`
	// claim (core.ActorClaim): the outermost entry is the workload that
	// requested THIS Txn-Token; nested entries are the earlier hops,
	// read outside-in in time-order. Nil on a first hop whose caller
	// supplied no requesting-workload identity.
	Act *core.ActorClaim `json:"act,omitempty"`
}

// chainDepth counts the links in an *core.ActorClaim chain. Mirrors
// tokengrant's actChainDepth exactly (same semantics: nil = 0).
func chainDepth(actor *core.ActorClaim) int {
	depth := 0
	for actor != nil {
		depth++
		actor = actor.Actor
	}
	return depth
}

// Signer is the narrow generic-JWT signing seam this package consumes —
// the SAME shape as caep.JWTSigner, satisfied structurally by the Ed25519
// / ECDSA / RSA issuers in infrastructure/defaultimpl (their SignJWT
// method). Reusing the issuer already minting access/ID/logout tokens
// means a receiving workload verifies a Txn-Token with no new trust
// setup: its `kid` resolves to a key already published in this server's
// JWKS.
//
// Defined here (not depending on defaultimpl or infrastructure) so this
// package stays a leaf under protocols/oauth with no infrastructure
// import — interfaces/sso wires a concrete issuer in.
type Signer interface {
	// SignJWT signs claims as a compact JWS stamping `typ` in the header,
	// using the issuer's active signing key + kid. typ MUST be non-empty.
	SignJWT(ctx context.Context, typ string, claims any) (string, error)
}
