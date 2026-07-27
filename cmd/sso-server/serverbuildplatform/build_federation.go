package serverbuildplatform

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/federation"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/security"
)

func BuildFederationConfig(cfg config.FederationConfig) (*federation.Config, error) {
	anchors, err := loadFederationAnchors(cfg.TrustAnchors)
	if err != nil {
		return nil, err
	}
	// §7 trust-mark issuers (slice 4b): load each authorized issuer's JWKS into
	// Keys — the root of trust the marks it signs are verified against (NEVER a
	// mark's self-asserted keys; an authorized issuer's keys are operator-pinned
	// here). A configured-but-unloadable issuer is a BOOT ERROR (the gate must
	// not silently run without an authorized issuer's keys, which would reject
	// every otherwise-valid mark and surface as a mysterious admission failure).
	tmIssuers, err := loadFederationTrustMarkIssuers(cfg.TrustMarkIssuers)
	if err != nil {
		return nil, err
	}
	if err := validateFederationTrustMarkConfig(cfg, tmIssuers, anchors); err != nil {
		return nil, err
	}
	// §8 SUPERIOR role: load each configured subordinate's JWKS into Keys — the
	// keys this server VOUCHES FOR in the Subordinate Statement it issues about
	// the subordinate at /fetch. A configured-but-unloadable subordinate is a
	// BOOT ERROR: a statement vouching for an empty key set is useless and would
	// fail every downstream chain validation, so fail loud at boot rather than
	// silently issue an unusable statement. With no subordinates the §8 route is
	// unmounted + the entity config advertises no fetch endpoint (byte-identical
	// to a leaf OP).
	subordinates, err := loadFederationSubordinates(cfg.Subordinates)
	if err != nil {
		return nil, err
	}
	return assembleFederationConfig(cfg, anchors, tmIssuers, subordinates), nil
}

// loadFederationJWKS reads + parses a static JWKS file and resolves its keys.
// Shared by the anchor / trust-mark-issuer / subordinate loaders so all three
// fail loud identically on a missing, unreadable, or unparseable key file.
func loadFederationJWKS(field, file string) ([]sso.JWK, error) {
	doc, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", field, err)
	}
	source, err := security.ParseStaticJWKS(doc)
	if err != nil {
		return nil, fmt.Errorf("parse %s JWKS: %w", field, err)
	}
	keys, err := source.GetJWKS(context.Background())
	if err != nil {
		return nil, fmt.Errorf("%s JWKS: %w", field, err)
	}
	return keys, nil
}

func loadFederationAnchors(in []config.TrustAnchorConfig) ([]federation.TrustAnchor, error) {
	anchors := make([]federation.TrustAnchor, 0, len(in))
	for i, ta := range in {
		if ta.EntityID == "" {
			return nil, fmt.Errorf("federation.trust_anchors[%d].entity_id required", i)
		}
		if ta.JWKSFile == "" {
			return nil, fmt.Errorf("federation.trust_anchors[%d].jwks_file required (the anchor's root-of-trust keys)", i)
		}
		keys, err := loadFederationJWKS(fmt.Sprintf("federation.trust_anchors[%d].jwks_file", i), ta.JWKSFile)
		if err != nil {
			return nil, err
		}
		anchors = append(anchors, federation.TrustAnchor{EntityID: ta.EntityID, JWKSFile: ta.JWKSFile, Keys: keys})
	}
	return anchors, nil
}

func loadFederationTrustMarkIssuers(in []config.TrustMarkIssuerConfig) ([]federation.TrustMarkIssuer, error) {
	tmIssuers := make([]federation.TrustMarkIssuer, 0, len(in))
	for i, ti := range in {
		if ti.EntityID == "" {
			return nil, fmt.Errorf("federation.trust_mark_issuers[%d].entity_id required", i)
		}
		if ti.JWKSFile == "" {
			return nil, fmt.Errorf("federation.trust_mark_issuers[%d].jwks_file required (the issuer's trust-mark signing keys)", i)
		}
		keys, err := loadFederationJWKS(fmt.Sprintf("federation.trust_mark_issuers[%d].jwks_file", i), ti.JWKSFile)
		if err != nil {
			return nil, err
		}
		tmIssuers = append(tmIssuers, federation.TrustMarkIssuer{
			EntityID:     ti.EntityID,
			JWKSFile:     ti.JWKSFile,
			Keys:         keys,
			AllowedTypes: append([]string(nil), ti.AllowedTypes...),
		})
	}
	return tmIssuers, nil
}

// validateFederationTrustMarkConfig enforces the cross-field invariants between
// required trust-mark types, configured issuers, the federation-resolved path,
// and anchors — split out so the assembly path stays flat.
func validateFederationTrustMarkConfig(cfg config.FederationConfig, tmIssuers []federation.TrustMarkIssuer, anchors []federation.TrustAnchor) error {
	// A required type needs SOME authorized-issuer source, else it locks out
	// EVERY auto-registering RP. Normally that source is operator-configured
	// trust_mark_issuers; the opt-in federation-resolved path provides an
	// ALTERNATE source (issuers discovered via their trust chain + authorized by
	// the anchor's trust_mark_issuers). So a required type with no configured
	// issuers is a misconfig ONLY when the federation-resolved path is ALSO off.
	if len(cfg.RequiredTrustMarkTypes) > 0 && len(tmIssuers) == 0 && !cfg.AllowFederationResolvedTrustMarkIssuers {
		return errors.New("federation.required_trust_mark_types set but no federation.trust_mark_issuers configured and allow_federation_resolved_trust_mark_issuers is false (a required trust mark with no authorized issuer source would admit no RP)")
	}
	// The federation-resolved issuer path needs a configured trust anchor: it is
	// the root of trust the issuer's chain must reach AND whose trust_mark_issuers
	// authorizes the issuer. Without any anchor the path is inert (the SDK gate
	// nil-checks the resolver), so a flag set with no anchors is a misconfig —
	// fail loud rather than silently never admitting a resolved issuer.
	if cfg.AllowFederationResolvedTrustMarkIssuers && len(anchors) == 0 {
		return errors.New("federation.allow_federation_resolved_trust_mark_issuers is true but no federation.trust_anchors configured (the anchor is the root of trust that authorizes a resolved issuer)")
	}
	return nil
}

func loadFederationSubordinates(in []config.SubordinateConfig) ([]federation.SubordinateEntity, error) {
	subordinates := make([]federation.SubordinateEntity, 0, len(in))
	for i, sub := range in {
		if sub.EntityID == "" {
			return nil, fmt.Errorf("federation.subordinates[%d].entity_id required", i)
		}
		if sub.JWKSFile == "" {
			return nil, fmt.Errorf("federation.subordinates[%d].jwks_file required (the keys this server vouches for the subordinate)", i)
		}
		keys, err := loadFederationJWKS(fmt.Sprintf("federation.subordinates[%d].jwks_file", i), sub.JWKSFile)
		if err != nil {
			return nil, err
		}
		subordinates = append(subordinates, federation.SubordinateEntity{
			EntityID:       sub.EntityID,
			JWKSFile:       sub.JWKSFile,
			Keys:           keys,
			MetadataPolicy: sub.MetadataPolicy,
			Constraints:    SubordinateConstraints(sub.Constraints),
		})
	}
	return subordinates, nil
}

// assembleFederationConfig maps the validated, loaded pieces onto the SDK
// federation.Config. Pure projection — no I/O or validation.
func assembleFederationConfig(cfg config.FederationConfig, anchors []federation.TrustAnchor, tmIssuers []federation.TrustMarkIssuer, subordinates []federation.SubordinateEntity) *federation.Config {
	return &federation.Config{
		AuthorityHints:     append([]string(nil), cfg.AuthorityHints...),
		TrustAnchors:       anchors,
		Subordinates:       subordinates,
		OrganizationName:   cfg.OrganizationName,
		Contacts:           append([]string(nil), cfg.Contacts...),
		EntityStatementTTL: cfg.EntityStatementTTL,
		CacheTTL:           cfg.CacheTTL,
		MaxTrustChainDepth: cfg.MaxTrustChainDepth,
		MaxClockSkew:       cfg.MaxClockSkew,
		// Slice-3 auto-registration abuse resistance (only consulted when
		// auto_register is enabled). Unset ⇒ the SDK applies its defaults (30s
		// negative-cache TTL, 16 concurrent resolutions, 1024-entry cap).
		ResolutionNegativeCacheTTL:     cfg.ResolutionNegativeCacheTTL,
		MaxConcurrentResolutions:       cfg.ResolutionMaxConcurrency,
		ResolutionNegativeCacheMaxSize: cfg.ResolutionNegativeCacheMaxSize,
		// Slice-4b §7 trust-mark requirement (only consulted when non-empty +
		// auto_register on). Empty RequiredTrustMarkTypes ⇒ the gate is OFF
		// (byte-identical to the slice-3 path).
		RequiredTrustMarkTypes: append([]string(nil), cfg.RequiredTrustMarkTypes...),
		TrustMarkIssuers:       tmIssuers,
		// Slice-4c opt-in federation-resolved issuer path (default false ⇒ the
		// slice-4b configured-issuer gate is byte-identical). Only consulted when
		// RequiredTrustMarkTypes is non-empty.
		AllowFederationResolvedTrustMarkIssuers: cfg.AllowFederationResolvedTrustMarkIssuers,
		// Slice-4c DoS bounds on the NESTED issuer-resolution fan-out (only
		// consulted on the federation-resolved path). Unset ⇒ the SDK applies its
		// defaults (4 distinct issuers/request, 8 concurrent nested resolutions,
		// 30s/1024 negative cache, 64 leaf-mark cap). Bound a malicious already-
		// chained RP's distinct-iss-mark amplification.
		MaxResolvedIssuersPerRequest:       cfg.ResolutionMaxResolvedIssuersPerRequest,
		MaxConcurrentIssuerResolutions:     cfg.ResolutionMaxConcurrentIssuerResolutions,
		ResolvedIssuerNegativeCacheTTL:     cfg.ResolvedIssuerNegativeCacheTTL,
		ResolvedIssuerNegativeCacheMaxSize: cfg.ResolvedIssuerNegativeCacheMaxSize,
		MaxLeafTrustMarks:                  cfg.MaxLeafTrustMarks,
	}
}
