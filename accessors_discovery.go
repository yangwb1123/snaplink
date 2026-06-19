// Code generated. Server field accessors for discovery, config, and federation.
package sso

import (
	"context"
	"sort"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/federation"
)

// Discovery and cache TTL accessors.
func (s *Server) JWKSCacheTTL() time.Duration                  { return s.jwksCacheTTL }
func (s *Server) JWKSCacheMaxAge() time.Duration               { return s.jwksCacheTTL }
func (s *Server) DiscoveryCacheTTL() time.Duration             { return s.discoveryCacheTTL }
func (s *Server) DiscoveryDocCacheTTL() time.Duration          { return s.discoveryDocCacheTTL }
func (s *Server) OpPolicyURI() string                          { return s.opPolicyURI }
func (s *Server) OpTosURI() string                             { return s.opTosURI }
func (s *Server) ServiceDocumentation() string                 { return s.serviceDocumentation }
func (s *Server) SupportedACRValues() []string                 { return s.supportedACRValues }
func (s *Server) OAuth21Strict() bool                          { return s.oauth21Strict }
func (s *Server) ScopeDescriptions() map[string]string         { return s.scopeDescriptions }
func (s *Server) JTIReplayFailClosed() bool                    { return s.jtiReplayFailClosed }
func (s *Server) AllowDynamicClientRegistration() bool         { return s.dcrPolicy != nil }

// ResolveIssuer returns the issuer URL for the current request.
func (s *Server) ResolveIssuer(ctx core.HandlerContext) string { return s.resolveIssuer(ctx) }

// RequestBaseURL derives the absolute scheme://host base for the request.
func (s *Server) RequestBaseURL(ctx core.HandlerContext) string {
	return requestBaseURL(ctx.Request())
}

// SigningAlgValues returns the distinct JWS `alg` values the wired
// signers actually publish, for the discovery doc's *_signing_alg_values_supported.
func (s *Server) SigningAlgValues(ctx context.Context) []string {
	if len(s.supportedSigningAlgs) > 0 {
		out := append([]string(nil), s.supportedSigningAlgs...)
		sort.Strings(out)
		return out
	}
	seen := map[string]struct{}{}
	for _, ti := range s.tokenIssuers {
		jp, ok := ti.(core.JWKSProvider)
		if !ok {
			continue
		}
		jwks, err := jp.JWKS(ctx)
		if err != nil {
			continue
		}
		for _, k := range jwks {
			if k.Alg != "" {
				seen[k.Alg] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return []string{"EdDSA"}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Federation accessors.
func (s *Server) FederationSigner() federation.JWTSigner {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.Signer()
}

func (s *Server) FederationConfig() *federation.Config {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.Config()
}

func (s *Server) FederationCache() *federation.EntityConfigCache {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.Cache()
}

func (s *Server) FederationFetchCache() *federation.SubordinateStatementCache {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.FetchCache()
}

func (s *Server) FederationNow() time.Time { return time.Now() }

// JWKS document cache methods.
func (s *Server) ComputeJWKSDocument(compute func() ([]byte, error)) ([]byte, error) {
	if s.jwksCacheTTL > 0 {
		s.jwksBodyMu.RLock()
		if time.Now().Before(s.jwksBodyExp) && len(s.jwksBodyCache) > 0 {
			body := s.jwksBodyCache
			s.jwksBodyMu.RUnlock()
			return body, nil
		}
		s.jwksBodyMu.RUnlock()
	}
	body, err := s.jwksFlight.Do(compute)
	if err != nil {
		return nil, err
	}
	if s.jwksCacheTTL > 0 {
		s.jwksBodyMu.Lock()
		s.jwksBodyCache = body
		s.jwksBodyExp = time.Now().Add(s.jwksCacheTTL)
		s.jwksBodyMu.Unlock()
	}
	return body, nil
}

func (s *Server) InvalidateJWKSBodyCache() {
	s.jwksBodyMu.Lock()
	s.jwksBodyExp = time.Time{}
	s.jwksBodyMu.Unlock()
}
