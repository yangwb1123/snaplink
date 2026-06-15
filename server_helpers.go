package sso

import (
	"fmt"

	"github.com/snaplink/sso/oidc"
)
func (s *Server) getAuthenticator(name string) (Authenticator, error) {
	a, ok := s.authenticators[name]
	if !ok {
		return nil, fmt.Errorf("authenticator %q not registered", name)
	}
	return a, nil
}

// issuerForClient returns the TokenIssuer that should mint tokens for the
// given client. Resolution order: per-tenant issuer (WithTenantTokenIssuer)
// → client.TokenStrategy → server default → (if exactly one issuer is
// registered) that one.
//
// A per-tenant mapping takes precedence over the client/server strategy so
// that crypto isolation is not silently defeatable by a client setting its
// own TokenStrategy. When a tenant mapping names an issuer that was never
// registered via WithTokenIssuer we fail closed (error) rather than fall
// back to a shared default key — a misconfiguration must not leak one
// tenant's clients onto another key.
func (s *Server) issuerForClient(c *Client) (string, TokenIssuer, error) {
	name := ""
	if c != nil && c.TenantID != "" {
		if tn, ok := s.tenantTokenStrategies[c.TenantID]; ok {
			name = tn
		}
	}
	if name == "" {
		if c != nil && c.TokenStrategy != "" {
			name = c.TokenStrategy
		} else if s.defaultTokenStrategy != "" {
			name = s.defaultTokenStrategy
		} else if len(s.tokenIssuers) == 1 {
			for n := range s.tokenIssuers {
				name = n
			}
		}
	}
	if name == "" {
		return "", nil, fmt.Errorf("no token strategy resolvable for client")
	}
	ti, ok := s.tokenIssuers[name]
	if !ok {
		return name, nil, fmt.Errorf("token strategy %q not registered", name)
	}
	return name, ti, nil
}

// idTokenIssuerForClient selects the oidc.IDTokenIssuer that should mint
// the ID token for the given client, mirroring issuerForClient so a
// tenant's id_tokens are signed by the SAME key as its access tokens —
// closing the crypto-isolation gap where id_token previously always used
// the one shared s.idTokenIssuer.
//
// A per-tenant mapping (WithTenantTokenIssuer) deliberately governs ALL of
// that tenant's token types at once: there is no separate id_token tenant
// map, because isolating access tokens but not id_tokens for the same
// tenant would silently re-open this very gap. The registered TokenIssuer
// object is reused — the default Ed25519/ECDSA/RSA issuers each satisfy
// oidc.IDTokenIssuer, so one signing key + one JWKS entry already covers
// access + id (+ JARM + userinfo).
//
// Returns (issuer, emit, err):
//   - No tenant mapping → (s.idTokenIssuer, s.idTokenIssuer != nil, nil):
//     unchanged shared behavior, pure backward-compat.
//   - Tenant mapping naming an UNREGISTERED issuer → (nil, false, error):
//     fail closed exactly like issuerForClient — a misconfiguration must
//     not leak the tenant onto a shared key. The caller logs + omits.
//   - Tenant mapping whose registered issuer does NOT implement
//     oidc.IDTokenIssuer (e.g. an opaque/session strategy) → (nil, false,
//     nil): emit=false, the caller OMITS id_token. Falling back to the
//     shared s.idTokenIssuer here would sign this tenant's id_token with
//     another key — the opposite of isolation — so we fail closed by
//     omission (the access-token branch is unaffected; only id_token is
//     withheld, exactly as if no issuer were wired).
func (s *Server) idTokenIssuerForClient(c *Client) (oidc.IDTokenIssuer, bool, error) {
	if c == nil || c.TenantID == "" {
		return s.idTokenIssuer, s.idTokenIssuer != nil, nil
	}
	name, ok := s.tenantTokenStrategies[c.TenantID]
	if !ok {
		// Tenant without a mapping behaves like a non-tenant client.
		return s.idTokenIssuer, s.idTokenIssuer != nil, nil
	}
	ti, ok := s.tokenIssuers[name]
	if !ok {
		return nil, false, fmt.Errorf("token strategy %q not registered", name)
	}
	idIssuer, ok := ti.(oidc.IDTokenIssuer)
	if !ok {
		// The tenant's signing strategy can't mint id_tokens (e.g. opaque
		// session tokens). Omit rather than sign with the shared key.
		s.logger.Error("tenant token strategy does not support id_token issuance; omitting id_token",
			"tenant", c.TenantID, "strategy", name, "client", c.ID)
		return nil, false, nil
	}
	return idIssuer, true, nil
}

// jarmSignerForClient selects the oidc.JARMSigner for the given client's
// authorization response, mirroring idTokenIssuerForClient so a tenant's
// JARM responses are signed by the SAME key as its access + id tokens.
// JARM is opt-in (WithJARM); when no signer is wired this returns (nil,
// false) and the caller never reaches a JARM response mode (gated in
// isValidResponseMode).
//
// Same discipline as idTokenIssuerForClient:
//   - No tenant mapping → the shared s.jarmSigner (unchanged behavior).
//   - Tenant issuer unregistered → (nil, false): fail closed. The JARM
//     render path already fails closed (invalid_request) when signing
//     can't proceed, so an omitted signer surfaces as that same error
//     rather than leaking the bare code.
//   - Tenant issuer registered but not a JARMSigner → (nil, false): omit
//     (fail closed) rather than sign with another tenant's / the shared
//     key.
func (s *Server) jarmSignerForClient(c *Client) (oidc.JARMSigner, bool) {
	if c == nil || c.TenantID == "" {
		return s.jarmSigner, s.jarmSigner != nil
	}
	name, ok := s.tenantTokenStrategies[c.TenantID]
	if !ok {
		return s.jarmSigner, s.jarmSigner != nil
	}
	ti, ok := s.tokenIssuers[name]
	if !ok {
		s.logger.Error("tenant token strategy not registered; failing JARM closed",
			"tenant", c.TenantID, "strategy", name, "client", c.ID)
		return nil, false
	}
	js, ok := ti.(oidc.JARMSigner)
	if !ok {
		s.logger.Error("tenant token strategy does not support JARM signing; failing closed",
			"tenant", c.TenantID, "strategy", name, "client", c.ID)
		return nil, false
	}
	return js, true
}

// ValidateToken is the public face of validateAnyToken — returns just the
// claims for callers (e.g. the admin middleware) that don't care which
// issuer accepted the token.
