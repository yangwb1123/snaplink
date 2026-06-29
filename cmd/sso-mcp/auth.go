package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"google.golang.org/grpc/connectivity"
)

const (
	headerAuthorization   = "Authorization"
	headerWWWAuthenticate = "WWW-Authenticate"
	bearerPrefix          = "Bearer "

	pathMCP    = "/mcp"
	pathPRM    = "/.well-known/oauth-protected-resource"
	pathLivez  = "/livez"
	pathReadyz = "/readyz"
)

// newRSGate is the OAuth 2.0 Resource Server gate for the HTTP transport. It
// validates the agent's bearer (signature+exp via JWKS), then enforces that the
// token's aud contains this server's resource URI and its scopes contain the
// required scope. Failures => 401 + RFC 9728 WWW-Authenticate.
func newRSGate(intro introspector, cfg *Config, next http.Handler) http.Handler {
	prmURL := strings.TrimRight(cfg.ResourceURI, "/") + pathPRM
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			challenge(w, prmURL, "") // missing token: omit error= per snaplink convention
			return
		}
		subj, err := intro.ValidateToken(r.Context(), tok)
		if err != nil || !contains(subj.Audience, cfg.ResourceURI) || !contains(subj.Scopes, cfg.RequiredScope) {
			challenge(w, prmURL, "invalid_token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get(headerAuthorization)
	if !strings.HasPrefix(h, bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(h[len(bearerPrefix):])
}

func challenge(w http.ResponseWriter, prmURL, errCode string) {
	v := `Bearer resource_metadata="` + prmURL + `"`
	if errCode != "" {
		v += `, error="` + errCode + `"`
	}
	w.Header().Set(headerWWWAuthenticate, v)
	w.WriteHeader(http.StatusUnauthorized)
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func prmHandler(cfg *Config) http.HandlerFunc {
	body, _ := json.Marshal(map[string]any{
		"resource":              cfg.ResourceURI,
		"authorization_servers": []string{cfg.Issuer},
	})
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

func livezHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"alive"}`))
	}
}

func readyzHandler(sc *snaplinkClient) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Trigger a connect attempt and report not-ready only if the conn has
		// permanently failed. Lazy gRPC starts Idle, which is acceptable.
		sc.conn.Connect()
		if sc.conn.GetState() == connectivity.Shutdown {
			http.Error(w, `{"status":"unready"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	}
}
