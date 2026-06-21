package sso

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/snaplink/sso/interfaces/sso/servercache"
	"github.com/snaplink/sso/shared/security"
)

// cacheState holds discovery/JWKS body caches, the JWKS single-flight, pairwise subject config, and the Server-level signing-alg allowlist.
type cacheState struct {
	// Discovery doc derivations from the client store (scopes union,
	// RequirePAR-any, RequireSignedRequestObject-all,
	// frontchannel_logout_supported, authorization_details types union).
	// Cached for `discoveryCacheTTL` so a high-QPS RP polling
	// `/.well-known/openid-configuration` doesn't pay 5× ClientStore.List
	// per request. Refresh is single-flight gated by discoveryCacheMu.
	discoveryCacheTTL time.Duration
	discoveryCache    atomic.Pointer[clientDiscoverySnapshot]
	discoveryCacheMu  sync.Mutex

	// Body cache: the marshaled discovery doc + ETag, keyed by base
	// URL (so multi-host SSO doesn't conflate). Reads are sync.Map-
	// served lock-free; misses fall through to the snapshot path.
	discoveryDocCacheTTL time.Duration
	discoveryDocCache    sync.Map

	// Authorization policy bundle body cache: the marshaled role-
	// DEFINITION bundle + ETag, keyed by "<clientID>\x00<baseURL>" so a
	// multi-host deployment doesn't conflate per-host renders. Reads are
	// sync.Map-served lock-free; misses re-render from the permissions
	// provider. Invalidated on any role/menu mutation (locally +, when a
	// bus is wired, across the cluster) so a sidecar's next pull sees the
	// change before the TTL elapses.
	authzPolicyBundleCacheTTL time.Duration
	authzPolicyBundleCache    sync.Map

	// Collapses concurrent /jwks.json document computations. The doc is
	// global (not per-host) and recomputing it on every poll — iterating
	// every issuer, marshaling, hashing — is wasted work under the
	// unknown-kid stampede many RPs emit right after a key rotation.
	// Deliberately TTL-free single-flight, not a time cache: only
	// genuinely concurrent calls share a result, so the next poll after
	// the in-flight one finishes recomputes — preserving the "JWKS
	// reflects the new key immediately" contract (no staleness window).
	jwksFlight servercache.JWKSSingleFlight

	// OIDC Core §8 pairwise subject identifiers. Nil pairwiseStore
	// disables the feature entirely — every client receives a public
	// (local) sub regardless of subject_type. Salt mixes into the
	// hash; empty falls back to security.DefaultPairwiseSalt.
	pairwiseStore security.PairwiseSubjectStore
	pairwiseSalt  string

	// supportedSigningAlgs is the Server-level Validate-time alg
	// allowlist (defense-in-depth on top of each issuer's own
	// allowlist). When non-empty, validateAnyToken parses every
	// inbound compact JWS header and rejects — BEFORE handing the
	// token to any issuer — tokens whose `alg` isn't listed. This is
	// the critical anti-alg-confusion property (AGENTS.md §2): the
	// verification algorithm is fixed by the Server's wired signers,
	// never chosen by the RP via the token header. Empty = no extra
	// Server-level gate; each issuer still enforces its own allowlist.
	//
	// It does NOT relax per-issuer enforcement: even an allowlisted
	// alg must still match the key type of the kid the issuer
	// resolves, so an ES256-labelled token only verifies against an
	// ES256 key and an EdDSA-labelled token only against an EdDSA key.
	supportedSigningAlgs []string
}
