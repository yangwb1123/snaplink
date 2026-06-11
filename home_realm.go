package sso

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/snaplink/sso/connections"
)

// PathHomeRealm is the opt-in B2B home-realm-discovery endpoint: given a login
// identifier (email), it returns the enterprise connection serving that domain
// so the login UI routes the user to their organization's upstream IdP.
const PathHomeRealm = "/auth/home-realm"

// Home-realm-discovery response keys.
const (
	keyHRFound        = "found"
	keyHRConnectionID = "connection_id"
	keyHRType         = "type"
	keyHRTenantID     = "tenant_id"
	keyHRDisplayName  = "display_name"
)

// WithConnectionStore wires per-organization enterprise connections (B2B) and
// mounts the home-realm-discovery endpoint (PathHomeRealm). Nil/unset = the
// endpoint is NOT mounted (byte-identical). The store maps email domains to a
// tenant's upstream IdP connection; a login UI calls this to route a user to
// their org's IdP. (Wiring a resolved connection into the actual upstream login
// flow is a separate step.)
func WithConnectionStore(store connections.Store) Option {
	return func(s *Server) { s.connectionStore = store }
}

// handleHomeRealm resolves a login identifier (email/domain) to the enterprise
// connection serving it and returns the routing decision WITHOUT any connection
// secrets — only the id + display metadata a UI needs to start the federated
// flow. A miss returns {"found": false} (fall back to the default login); this
// is a routing decision (which IdP), NOT a credential oracle.
func (s *Server) handleHomeRealm(ctx HandlerContext) {
	r := ctx.Request()
	hint := strings.TrimSpace(r.URL.Query().Get("login_hint"))
	if hint == "" {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var b struct {
				LoginHint  string `json:"login_hint"`
				Identifier string `json:"identifier"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			if hint = strings.TrimSpace(b.LoginHint); hint == "" {
				hint = strings.TrimSpace(b.Identifier)
			}
		} else {
			_ = r.ParseForm()
			if hint = strings.TrimSpace(r.FormValue("login_hint")); hint == "" {
				hint = strings.TrimSpace(r.FormValue("identifier"))
			}
		}
	}

	conn, err := connections.Resolve(r.Context(), s.connectionStore, hint)
	if errors.Is(err, connections.ErrNoConnection) {
		ctx.JSON(http.StatusOK, map[string]any{keyHRFound: false})
		return
	}
	if err != nil {
		s.logErrorCtx(ctx, "home-realm discovery failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		keyHRFound:        true,
		keyHRConnectionID: conn.ID,
		keyHRType:         string(conn.Type),
		keyHRTenantID:     conn.TenantID,
		keyHRDisplayName:  conn.DisplayName,
	})
}
