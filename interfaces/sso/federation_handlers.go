package sso

import (
	"net/http"

	"github.com/snaplink/sso/domains/federation"
)

// handleFederationEntityConfig delegates to the Hex federation handler.
func (s *Server) handleFederationEntityConfig(ctx HandlerContext) {
	federation.HandleEntityConfiguration(s, ctx)
}

// handleFederationFetch delegates to the M-BM-§8 Federation Fetch handler.
func (s *Server) handleFederationFetch(ctx HandlerContext) {
	federation.HandleFederationFetch(s, ctx)
}

// handleFederationResolve delegates to the M-BM-§8.3 Federation Resolve handler.
func (s *Server) handleFederationResolve(ctx HandlerContext) {
	federation.HandleFederationResolve(s, ctx)
}

func (s *Server) FederationFetcher() federation.EntityStatementFetcher { return nil }

// handleFederationTrustMarkStatus delegates to the M-BM-§8.4 Trust Mark Status handler.
func (s *Server) handleFederationTrustMarkStatus(ctx HandlerContext) {
	federation.HandleTrustMarkStatus(s, ctx)
}

// handleFederationList delegates to the M-BM-§8.2 Federation Listing handler.
func (s *Server) handleFederationList(ctx HandlerContext) {
	federation.HandleFederationList(s, ctx)
}

// handleFederationHistoricalKeys serves the OP's historical signing keys
// (8.5). When a HistoricalKeyStore is wired, it returns a JSON JWKS
// containing all previously-published keys.
func (s *Server) handleFederationHistoricalKeys(ctx HandlerContext) {
	if s.federationHistoricalKeyStore == nil {
		tokenNoStoreHeaders(ctx)
		ctx.JSON(http.StatusOK, map[string]any{"keys": []any{}})
		return
	}
	keys, err := s.federationHistoricalKeyStore.HistoricalKeys(ctx.Request().Context())
	if err != nil {
		s.logger.Error("historical keys fetch failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	jwkKeys := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		if k.JWK != nil {
			entry := make(map[string]any)
			for kk, vv := range k.JWK {
				entry[kk] = vv
			}
			if !k.ActiveUntil.IsZero() {
				entry["active_until"] = k.ActiveUntil.Unix()
			}
			if !k.RetiredAt.IsZero() {
				entry["retired_at"] = k.RetiredAt.Unix()
			}
			jwkKeys = append(jwkKeys, entry)
		}
	}
	tokenNoStoreHeaders(ctx)
	ctx.JSON(http.StatusOK, map[string]any{"keys": jwkKeys})
}
