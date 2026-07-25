package sso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/snaplink/sso/domains/authenticators/device"
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/connections/provider"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/security"
)

// resolveLoginRequest handles JAR request_uri URL-fetch and PAR consume. Returns
// true if the request is fully handled (caller should return immediately).
func (s *Server) resolveLoginRequest(ctx HandlerContext, req *login.Request) bool {
	if req.RequestURI != "" && security.IsJARFetchableURI(req.RequestURI) {
		return s.fetchJARRequestURI(ctx, req)
	}
	if req.RequestURI != "" {
		return s.consumePARRequest(ctx, req)
	}
	return false
}

// fetchJARRequestURI resolves an RFC 9101 request_uri pointing at a fetchable
// URL: validate the client + per-client request_uri allowlist, fetch the signed
// request object, and stash it on req.Request for downstream verification.
// Returns true (response written) on any failure; false on success.
func (s *Server) fetchJARRequestURI(ctx HandlerContext, req *login.Request) bool {
	if s.jarFetcher == nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
		return true
	}
	if req.ClientID == "" || s.clientStore == nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
		return true
	}
	c, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
		return true
	}
	if !security.IsRequestURIAllowed(req.RequestURI, c.AllowedRequestURIs) {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
		return true
	}
	body, err := s.jarFetcher.Fetch(ctx.Request().Context(), req.RequestURI)
	if err != nil {
		s.logErrorCtx(ctx, "jar fetch failed", "error", err, "client", req.ClientID, "uri", req.RequestURI)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
		return true
	}
	req.Request = string(body)
	return false
}

// consumePARRequest consumes an RFC 9126 pushed authorization request and merges
// its stored parameters into req. Returns true (response written) on a missing
// PAR store or an unknown/expired request_uri; false on success.
func (s *Server) consumePARRequest(ctx HandlerContext, req *login.Request) bool {
	if s.parStore == nil {
		ctx.JSON(http.StatusNotImplemented, s.authzErrorBodyWithState(ctx, ErrPARNotConfigured, req.State))
		return true
	}
	stored, err := s.parStore.Consume(ctx.Request().Context(), req.RequestURI)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequestURI, req.State))
		return true
	}
	// RFC 9126 §4: when client_id is present in the request, it MUST match the
	// client that pushed the PAR. An attacker who substitutes a different request_uri
	// (e.g. one from their own PAR) while keeping the victim client's client_id in the
	// URL would otherwise have the stored redirect_uri silently overwritten to theirs.
	if req.ClientID != "" && stored.ClientID != "" && req.ClientID != stored.ClientID {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequestURI, req.State))
		return true
	}
	mergeStoredPARRequest(req, stored)
	return false
}

// mergeStoredPARRequest merges a consumed PAR record's non-empty fields into req.
// RFC 9126: the pushed parameters are authoritative over caller-supplied ones.
func mergeStoredPARRequest(req *login.Request, stored *oauth.PARRequest) {
	if stored.ClientID != "" {
		req.ClientID = stored.ClientID
	}
	if stored.ResponseType != "" {
		req.ResponseType = stored.ResponseType
	}
	if stored.RedirectURI != "" {
		req.RedirectURI = stored.RedirectURI
	}
	if len(stored.Scope) > 0 {
		req.Scope = stored.Scope
	}
	if stored.State != "" {
		req.State = stored.State
	}
	if stored.Nonce != "" {
		req.Nonce = stored.Nonce
	}
	if stored.CodeChallenge != "" {
		req.CodeChallenge = stored.CodeChallenge
		req.CodeChallengeMethod = stored.CodeChallengeMethod
	}
	if len(stored.Resource) > 0 {
		req.Resource = stored.Resource
	}
	if len(stored.AuthorizationDetails) > 0 {
		req.AuthorizationDetails = oauth.CloneRawJSON(stored.AuthorizationDetails)
	}
	if stored.LoginHint != "" {
		req.LoginHint = stored.LoginHint
	}
	if stored.ResponseMode != "" {
		req.ResponseMode = stored.ResponseMode
	}
	if stored.ACRValues != "" {
		req.ACRValues = stored.ACRValues
	}
	if stored.UILocales != "" {
		req.UILocales = stored.UILocales
	}
	if len(stored.Claims) > 0 {
		req.Claims = oauth.CloneRawJSON(stored.Claims)
	}
}

// handlePromptNone handles the OIDC prompt=none silent renewal branch.
// It validates the client, checks residency, authorizes scopes, and
// delegates to handleSilentRenewal. Always writes a response (either
// renewed tokens or login_required).
func (s *Server) handlePromptNone(ctx HandlerContext, prompts []string, req *login.Request) {
	if req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrMissingClientID, req.State))
		return
	}
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBodyWithState(ctx, ErrClientStoreNotConfigured, req.State))
		return
	}
	c, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, s.authzErrorBodyWithState(ctx, ErrInvalidClient, req.State))
		return
	}
	if !c.Active {
		ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, ErrInactiveClient, req.State))
		return
	}
	if !clientTenantOK(ctx, c) {
		ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, ErrTenantMismatch, req.State))
		return
	}
	if s.residencyGateLogin(ctx, c.ID, "silent_renewal", c.TenantID) {
		return
	}
	granted, scopeErr := oauth.GrantedScopes(req.Scope, c)
	if scopeErr != nil {
		s.recordLoginFailure(ctx, req.ClientID, "silent_renewal", ErrInvalidScope)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidScope, req.State))
		return
	}
	req.Scope = granted
	s.handleSilentRenewal(ctx, prompts, oidc.SilentRenewalRequest{
		ClientID:             req.ClientID,
		Scope:                req.Scope,
		State:                req.State,
		Nonce:                req.Nonce,
		Resource:             req.Resource,
		AuthorizationDetails: req.AuthorizationDetails,
		IDTokenHint:          req.IDTokenHint,
		MaxAge:               req.MaxAge,
	}, c)
}

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
	// keyHRConnectionRequired marks an /auth/login provider-discovery response
	// that resolved to an enterprise connection: the client MUST authenticate
	// via the named connection's upstream IdP rather than the provider list.
	keyHRConnectionRequired = "connection_required"
)

// resolveHomeRealm does B2B home-realm discovery for the interactive login
// flow: it maps a login hint (email) to the enterprise connection serving its
// domain. Returns false when no store is wired, the hint is empty, no
// connection matches, or the resolved connection belongs to a different tenant
// than the request (cross-tenant HRD isolation).
//
// Domain-ownership enforcement is intentionally NOT reimplemented here: it is
// delegated entirely to connections.Resolve -> Store.ByDomain, which only
// matches a domain once its claim has been promoted to routing owner — either
// because the store was built with connections.WithDomainVerificationRequired
// (config connections.domain_verification.enabled) and the specific domain
// passed its DNS-TXT challenge, or because the store is running in the
// default (opt-out) mode, where every declared domain auto-promotes at Upsert
// for byte-identical legacy routing. A connection whose domain was never
// declared, or whose claim is still DomainPending under the opted-in mode,
// therefore never reaches this function as a match — see
// domains/connections/domain_verification.go and
// memory_domain_verification.go (reconcileClaimsLocked/promoteDomainLocked)
// for the enforcement itself.
func (s *Server) resolveHomeRealm(ctx HandlerContext, loginHint string) (*connections.Connection, bool) {
	if s.connectionStore == nil || strings.TrimSpace(loginHint) == "" {
		return nil, false
	}
	conn, err := connections.Resolve(ctx.Request().Context(), s.connectionStore, loginHint)
	if err != nil {
		return nil, false
	}
	// Guard cross-tenant routing: reject when the request carries a resolved
	// tenant that disagrees with the connection's tenant — the email domain
	// may be globally registered but must not route to another org's IdP.
	if r, ok := tenant.FromHandlerContext(ctx); ok && r != nil && r.Tenant != nil &&
		r.Tenant.ID != "" && conn.TenantID != "" && conn.TenantID != r.Tenant.ID {
		return nil, false
	}
	return conn, true
}

// WithConnectionStore wires per-organization enterprise connections (B2B) and
// mounts the home-realm-discovery endpoint (PathHomeRealm). Nil/unset = the
// endpoint is NOT mounted (byte-identical). The store maps email domains to a
// tenant's upstream IdP connection; a login UI calls this to route a user to
// their org's IdP. Pair with WithConnectionAuthenticatorFactory to also
// dispatch the actual upstream login through the resolved connection. Whether
// a domain match requires proven DNS ownership before it is trusted for
// routing is the STORE's own config, not this option's: construct store with
// connections.WithDomainVerificationRequired (config
// connections.domain_verification.enabled) to require it, or leave it unset
// for the historical opt-out behavior — see resolveHomeRealm's doc.
func WithConnectionStore(store connections.Store) Option {
	return func(s *Server) { s.connectionStore = store }
}

// WithProviderStore wires the third-party login provider store. When wired,
// the /api/v1/admin/providers CRUD routes are mounted; without it the routes
// are NOT mounted and the build is byte-identical to a build without the
// feature.
func WithProviderStore(store provider.Store) Option {
	return func(s *Server) { s.providerStore = store }
}

// WithDeviceStore wires the device tracking store. When wired, the server
// automatically registers/updates devices on each login and surfaces device
// info in the login response. Without it, device tracking is not performed.
func WithDeviceStore(store device.Store) Option {
	return func(s *Server) { s.deviceStore = store }
}

// WithDevicePolicy configures device policy rules (max devices, fingerprint
// requirements, etc.). Zero values mean "no restriction". When combined with
// WithDeviceStore, the policy is enforced at login time.
func WithDevicePolicy(p device.Policy) Option {
	return func(s *Server) { s.devicePolicy = p }
}

// WithLoginHistoryStore wires the login history store. When wired, each
// successful login is recorded with device/IP/provider context for the
// self-service login history view. No-op when nil.
func WithLoginHistoryStore(h device.HistoryStore) Option {
	return func(s *Server) { s.loginHistory = h }
}

// WithConnectionAuthenticatorFactory wires the RUNTIME half of enterprise
// connections: after home-realm discovery routes a login to a connection (the
// connection_required directive), the UI re-posts /auth/login with
// provider=<connection id>, and the factory turns the stored connection
// config into a live upstream authenticator dispatched exactly like a
// statically-registered provider. Inert without WithConnectionStore (there is
// nothing to resolve ids against); nil/unset = connection ids never resolve
// as providers — byte-identical to the HRD-directive-only build.
func WithConnectionAuthenticatorFactory(f connections.AuthenticatorFactory) Option {
	return func(s *Server) { s.connectionAuthFactory = f }
}

// resolveEnabledConnection resolves an enterprise-connection id for runtime
// dispatch: store lookup + enabled gate. Every miss collapses to an error the
// CALLER must render as the SAME wire response as an unknown provider
// (anti-enumeration: a probe must not distinguish "no such connection" /
// "disabled" / "misconfigured" from "no such provider").
func (s *Server) resolveEnabledConnection(ctx context.Context, id string) (*connections.Connection, error) {
	if s.connectionStore == nil || s.connectionAuthFactory == nil || id == "" {
		return nil, connections.ErrNoConnection
	}
	conn, err := s.connectionStore.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !conn.Enabled {
		return nil, connections.ErrNoConnection
	}
	return conn, nil
}

// connectionLoginAuthenticator resolves an enterprise-connection id to its live
// upstream authenticator via the wired factory, applying the same cross-tenant
// guard as resolveHomeRealm: a request served under one tenant's hostname must
// not dispatch through another org's connection (rendered as unknown-provider,
// never tenant_mismatch — the connection's existence is not disclosed). Both
// legs of the federated flow route through here — /auth/login dispatch AND the
// /auth/callback round-trip — so the guard and the anti-enumeration collapse
// hold identically on entry and return. The factory owns surfacing build
// failures to the operator (audit + log); this stays response-path-silent so
// the caller renders the generic unknown-provider error.
func (s *Server) connectionLoginAuthenticator(ctx HandlerContext, id string) (Authenticator, error) {
	rctx := ctx.Request().Context()
	conn, err := s.resolveEnabledConnection(rctx, id)
	if err != nil {
		return nil, err
	}
	if r, ok := tenant.FromHandlerContext(ctx); ok && r != nil && r.Tenant != nil &&
		r.Tenant.ID != "" && conn.TenantID != "" && conn.TenantID != r.Tenant.ID {
		return nil, connections.ErrNoConnection
	}
	return s.connectionAuthFactory.AuthenticatorFor(rctx, conn)
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
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	// Guard cross-tenant routing: the /auth/home-realm endpoint is served
	// under a specific tenant's hostname; a connection that belongs to a
	// different tenant must not be disclosed or routed to.
	if res, ok := tenant.FromHandlerContext(ctx); ok && res != nil && res.Tenant != nil &&
		res.Tenant.ID != "" && conn.TenantID != "" && conn.TenantID != res.Tenant.ID {
		ctx.JSON(http.StatusOK, map[string]any{keyHRFound: false})
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
