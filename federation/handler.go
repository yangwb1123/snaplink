package federation

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/core"
)

// Deps is what HandleEntityConfiguration needs from the host server.
// *sso.Server satisfies it via accessor methods (accessors.go). Defined as
// an interface (the hexagonal seam) so the handler body lives in this
// package — which never imports root sso — while the root delegates a
// one-liner to it.
type Deps interface {
	// ResolveIssuer returns the issuer URL for this request (honoring the
	// configured issuer override + the X-Forwarded edge-trust contract).
	// For a self-signed Entity Configuration this is BOTH iss and sub.
	ResolveIssuer(ctx core.HandlerContext) string
	// TokenIssuers returns the registered strategy -> TokenIssuer map. The
	// handler walks it for every issuer satisfying core.JWKSProvider to
	// assemble the inline jwks (the SAME aggregation the /jwks.json handler
	// performs) — so the Entity Statement's keys are exactly the OP's
	// published signing keys.
	TokenIssuers() map[string]core.TokenIssuer
	// BuildOPMetadata projects the openid_provider metadata for base URL,
	// DERIVED from the discovery document so the federation view cannot
	// drift from the discovery view.
	BuildOPMetadata(ctx core.HandlerContext, base string) OPFederationMetadata
	// FederationSigner is the OP signing issuer reused via its SignJWT seam
	// (typ entity-statement+jwt). The statement's kid is one of the keys in
	// its own jwks, so a verifier validates it against a trusted key.
	FederationSigner() JWTSigner
	// FederationConfig carries authority_hints, federation_entity fields,
	// and the TTLs.
	FederationConfig() *Config
	// RequestBaseURL derives the absolute scheme://host base for this
	// request (the SAME derivation the discovery doc uses). Exposed via Deps
	// — rather than computed here — so this package depends only on core +
	// security and never reaches into the middleware base-URL extractor.
	RequestBaseURL(ctx core.HandlerContext) string
	// FederationCache is the per-issuer signed-statement cache.
	FederationCache() *EntityConfigCache
	// FederationNow is the clock the handler stamps iat/exp from. Injected
	// (not a direct time.Now call) so a test can drive a fixed time through
	// BOTH the handler and its assertions, keeping exp deterministic — no
	// real-clock-vs-fixed-time date bomb.
	FederationNow() time.Time
	// LogError logs a non-fatal error (signing/marshal failure). Mirrors the
	// server logger used by the discovery signed_metadata path.
	LogError(msg string, args ...any)
}

// HandleEntityConfiguration serves GET /.well-known/openid-federation — the
// OP's self-signed Entity Configuration (OpenID Federation 1.0 §9). It:
//
//  1. resolves the issuer (iss == sub, the self-signed entity identifier);
//  2. assembles the inline jwks from every JWKSProvider TokenIssuer (the
//     OP's published signing keys, so the statement is verifiable against a
//     key a consumer already trusts);
//  3. derives openid_provider metadata from the discovery doc and adds the
//     federation_entity metadata from config;
//  4. builds the Entity Statement claims and signs them via the OP's
//     SignJWT seam with typ entity-statement+jwt;
//  5. ETag + Cache-Control caches + writes the signed JWS (public metadata,
//     so public max-age, NOT no-store).
//
// A signing/marshal failure logs + returns 500 (mirroring the discovery
// signed_metadata 500 path). NO new wire error code is introduced.
//
// This slice performs NO trust-chain resolution: authority_hints are
// emitted but never followed. Validating the chain up to a trust anchor is
// the trust boundary and a separate slice.
func HandleEntityConfiguration(deps Deps, ctx core.HandlerContext) {
	cfg := deps.FederationConfig()
	now := deps.FederationNow()
	base := deps.RequestBaseURL(ctx)
	iss := deps.ResolveIssuer(ctx)

	// Body cache keyed by issuer: skip the jwks walk + metadata build +
	// SIGN when a recent rendering is still fresh. Signing can be a KMS
	// round-trip (5-50ms), so caching matters under federation-resolver
	// polling. Honors If-None-Match → 304 via WriteEntityStatement.
	cache := deps.FederationCache()
	if cache != nil {
		if entry := cache.lookup(iss, now); entry != nil {
			WriteEntityStatement(ctx.ResponseWriter(), ctx.Request(), entry.compact, entry.etag, cfg.cacheTTL())
			return
		}
	}

	// Inline jwks: aggregate every JWKSProvider issuer's keys — the SAME
	// walk /jwks.json performs. These are the OP's published signing keys;
	// the Entity Statement is signed by one of them (kid match), so a
	// consumer validates it with no new trust setup (the key-reuse crux).
	keys := make([]core.JWK, 0)
	for _, ti := range deps.TokenIssuers() {
		jp, ok := ti.(core.JWKSProvider)
		if !ok {
			continue
		}
		ks, err := jp.JWKS(ctx.Request().Context())
		if err != nil {
			deps.LogError("federation: jwks provider failed", "error", err)
			continue
		}
		keys = append(keys, ks...)
	}

	// openid_provider metadata is DERIVED from the discovery doc (via the
	// OP projection) so the two views never diverge. federation_entity is
	// the federation-level contact/org metadata from config.
	opMeta := deps.BuildOPMetadata(ctx, base)
	meta := &EntityMetadata{OP: &opMeta}
	if fe := federationEntityMeta(cfg); fe != nil {
		meta.FederationEntity = fe
	}

	ttl := cfg.entityStatementTTL()
	claims := EntityStatementClaims{
		// Self-signed Entity Configuration: iss == sub == entity identifier.
		Iss:            iss,
		Sub:            iss,
		Iat:            now.Unix(),
		Exp:            now.Add(ttl).Unix(),
		JWKS:           EntityJWKS{Keys: keys},
		Metadata:       meta,
		AuthorityHints: authorityHints(cfg),
	}

	compact, err := deps.FederationSigner().SignJWT(ctx.Request().Context(), EntityStatementTyp, claims)
	if err != nil {
		// Mirror the discovery signed_metadata failure: log + 500. The
		// signed Entity Configuration is the whole response (unlike
		// signed_metadata, which is one field of an otherwise-serveable
		// doc), so there is nothing to fall back to.
		deps.LogError("federation: entity configuration signing failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}

	body := []byte(compact)
	etag := buildETag(body)
	if cache != nil {
		cache.store(iss, &entityConfigEntry{compact: body, etag: etag, expiresAt: now.Add(cfg.cacheTTL())})
	}
	WriteEntityStatement(ctx.ResponseWriter(), ctx.Request(), body, etag, cfg.cacheTTL())
}

// federationEntityMeta builds the federation_entity metadata entry from
// config, or nil when the operator configured neither field (so the entry
// is omitted from the statement rather than emitted empty).
func federationEntityMeta(cfg *Config) *FederationEntityMeta {
	if cfg == nil {
		return nil
	}
	if cfg.OrganizationName == "" && len(cfg.Contacts) == 0 {
		return nil
	}
	return &FederationEntityMeta{
		OrganizationName: cfg.OrganizationName,
		Contacts:         append([]string(nil), cfg.Contacts...),
	}
}

// authorityHints returns a defensive copy of the configured authority_hints
// (nil when none, so the claim is omitted).
func authorityHints(cfg *Config) []string {
	if cfg == nil || len(cfg.AuthorityHints) == 0 {
		return nil
	}
	return append([]string(nil), cfg.AuthorityHints...)
}
