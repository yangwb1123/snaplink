package federation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// ---- Federation §8.3 Resolve endpoint ----

// ResolveDeps is what HandleFederationResolve needs from the host server.
type ResolveDeps interface {
	FederationResolver() *TrustChainResolver
	LogError(msg string, args ...any)
}

// noStoreHeaders sets Cache-Control: no-store + Pragma: no-cache.
func noStoreHeaders(ctx core.HandlerContext) {
	ctx.ResponseWriter().Header().Set("Cache-Control", "no-store")
	ctx.ResponseWriter().Header().Set("Pragma", "no-cache")
}

// HandleFederationResolve serves GET /.well-known/openid-federation-resolve
// (OpenID Federation 1.0 §8.3). All errors collapse to 404 (oracle-safe).
func HandleFederationResolve(deps ResolveDeps, ctx core.HandlerContext) {
	noStoreHeaders(ctx)
	sub := ctx.Query(ParamSub)
	if sub == "" {
		federationError(ctx, http.StatusBadRequest, ErrFederationInvalidRequest, "sub is required")
		return
	}
	resolver := deps.FederationResolver()
	if resolver == nil || !resolver.Enabled() {
		federationError(ctx, http.StatusNotFound, ErrFederationNotFound, "entity not found")
		return
	}
	chain, err := resolver.ResolveTrustChain(context.Background(), sub)
	if err != nil {
		federationError(ctx, http.StatusNotFound, ErrFederationNotFound, "entity not found")
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"chain": chain.Statements})
}

// ---- Federation §8.2 List endpoint ----

// ListEntry is one element in the Federation Listing response.
type ListEntry struct {
	EntityID        string `json:"entity_id"`
	JWKSThrumbprint string `json:"jwks_thumbprint,omitempty"`
}

// ListResponse is the JSON response for the Federation Listing endpoint.
type ListResponse struct {
	Subordinates []ListEntry `json:"subordinates"`
}

// ListDeps is what HandleFederationList needs from the host server.
type ListDeps interface {
	FederationConfig() *Config
	ResolveIssuer(ctx core.HandlerContext) string
	LogError(msg string, args ...any)
}

// HandleFederationList serves GET /.well-known/openid-federation-list
// — returns a JSON listing of configured subordinate entities (OpenID
// Federation 1.0 §8.2).
func HandleFederationList(deps ListDeps, ctx core.HandlerContext) {
	cfg := deps.FederationConfig()
	if cfg == nil || !cfg.hasSubordinates() {
		ctx.JSON(http.StatusOK, ListResponse{Subordinates: []ListEntry{}})
		return
	}
	entries := make([]ListEntry, 0, len(cfg.Subordinates))
	for _, sub := range cfg.Subordinates {
		entry := ListEntry{EntityID: sub.EntityID}
		if len(sub.Keys) > 0 {
			if tp, err := jwkThumbprint(sub.Keys[0]); err == nil {
				entry.JWKSThrumbprint = tp
			}
		}
		entries = append(entries, entry)
	}
	ctx.ResponseWriter().Header().Set("Cache-Control", "public, max-age="+cacheAgeSeconds(cfg.cacheTTL()))
	ctx.JSON(http.StatusOK, ListResponse{Subordinates: entries})
}

func jwkThumbprint(key core.JWK) (string, error) {
	required := map[string]any{"kty": key.Kty}
	switch key.Kty {
	case "EC":
		required["crv"] = key.Crv
		required["x"] = key.X
		required["y"] = key.Y
	case "RSA":
		required["n"] = key.N
		required["e"] = key.E
	case "OKP":
		required["crv"] = key.Crv
		required["x"] = key.X
	}
	norm, err := json.Marshal(required)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(norm)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func cacheAgeSeconds(d time.Duration) string {
	return fmt.Sprintf("%.0f", d.Seconds())
}
