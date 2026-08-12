package generate

// handlerTemplate generates a new HTTP handler following the hexagonal
// pattern actually used throughout this codebase (AGENTS.md §4: "Hexagonal
// extraction: HandleX(deps Deps, ctx) free functions in domain packages.
// *sso.Server satisfies Deps via accessors.go") — see e.g.
// domains/permissions/handlers.go or domains/federation/health/handler.go
// for real examples this template mirrors. It is deliberately NOT a plain
// net/http.Handler: that shape is reserved in this repo for infra probe
// endpoints (/livez, /readyz, /metrics), never business endpoints.
const handlerTemplate = `package {{.Package}}

import (
	"net/http"
	// "strings" is needed only by the Content-Type guard example in
	// handle{{.Name}}Post — uncomment both together when you activate it.

	"github.com/yangwb1123/snaplink/shared/core"
)

// {{.Name}}Deps defines the dependencies Handle{{.Name}} needs. A composition
// root's *sso.Server satisfies this via one-line accessor methods (see
// accessors.go / server_*.go for the pattern) — add an accessor there for
// each dependency you list here.
type {{.Name}}Deps interface {
	// TODO: Add required dependencies, e.g.:
	// core.UserProvider
	// SrvLogger() spi.Logger
}

// Handle{{.Name}} handles {{.Description}} requests. Wire it into a
// core.Router with router.GET(core.PathUserInfo, func(ctx core.HandlerContext) {
// Handle{{.Name}}(deps, ctx) }) — endpoint paths are the core.Path*
// constants in shared/core/consts.go, never inline literal strings — or
// delegate to it from a thin one-line (*sso.Server) method the same way
// domains/federation/health/handler.go's HandleListPeerHealth is wired from
// server_federation.go.
func Handle{{.Name}}(deps {{.Name}}Deps, ctx core.HandlerContext) {
	switch ctx.Request().Method {
	case http.MethodGet:
		handle{{.Name}}Get(deps, ctx)
	case http.MethodPost:
		handle{{.Name}}Post(deps, ctx)
	case http.MethodPut:
		handle{{.Name}}Put(deps, ctx)
	case http.MethodDelete:
		handle{{.Name}}Delete(deps, ctx)
	default:
		ctx.JSON(http.StatusMethodNotAllowed, core.ErrorBody(core.ErrInvalidRequest))
	}
}

// handle{{.Name}}Get processes GET requests.
// TODO: Replace with your read operations (list, get by ID, search).
func handle{{.Name}}Get(deps {{.Name}}Deps, ctx core.HandlerContext) {
	// TODO: Replace with your GET logic, e.g.:
	//
	// id := ctx.Param("id")
	// entity, err := deps.Get(ctx.Request().Context(), id)
	// if err != nil {
	// 	ctx.JSON(http.StatusNotFound, core.ErrorBody("not_found"))
	// 	return
	// }
	// ctx.JSON(http.StatusOK, entity)
	//
	// After filling in your logic, remove this marker.

	ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotSupported))
}

// handle{{.Name}}Post processes POST requests.
// TODO: Replace with your create operations.
func handle{{.Name}}Post(deps {{.Name}}Deps, ctx core.HandlerContext) {
	// TODO: Replace with your POST logic, e.g.:
	//
	// var req CreateRequest
	// // Credential-adjacent routes bind form bodies only; reject other
	// // Content-Types (including JSON) before binding, per the B4-4
	// // server posture. HasPrefix tolerates ";charset=UTF-8" suffixes.
	// if !strings.HasPrefix(ctx.Request().Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
	// 	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
	// 	return
	// }
	// if err := ctx.Bind(&req); err != nil {
	// 	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
	// 	return
	// }
	// entity, err := deps.Create(ctx.Request().Context(), req)
	// if err != nil {
	// 	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
	// 	return
	// }
	// ctx.JSON(http.StatusCreated, entity)
	//
	// After filling in your logic, remove this marker.

	ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotSupported))
}

// handle{{.Name}}Put processes PUT requests.
// TODO: Replace with your update operations.
func handle{{.Name}}Put(deps {{.Name}}Deps, ctx core.HandlerContext) {
	// TODO: Replace with your PUT logic.
	// After filling in your logic, remove this marker.

	ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotSupported))
}

// handle{{.Name}}Delete processes DELETE requests.
// TODO: Replace with your delete operations.
func handle{{.Name}}Delete(deps {{.Name}}Deps, ctx core.HandlerContext) {
	// TODO: Replace with your DELETE logic.
	// After filling in your logic, remove this marker.

	ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotSupported))
}

// Example request/response types (uncomment and customize as needed):

// CreateRequest represents the request body for creating a {{.LowerName}}.
// type CreateRequest struct {
// 	// TODO: Add request fields.
// 	// Example:
// 	// Name     string            ` + "`" + `json:"name" validate:"required"` + "`" + `
// 	// Metadata map[string]string ` + "`" + `json:"metadata"` + "`" + `
// }

// {{.Name}}Response represents the response for a {{.LowerName}} entity.
// type {{.Name}}Response struct {
// 	// TODO: Add response fields.
// 	// Example:
// 	// ID        string            ` + "`" + `json:"id"` + "`" + `
// 	// Name      string            ` + "`" + `json:"name"` + "`" + `
// 	// CreatedAt time.Time         ` + "`" + `json:"created_at"` + "`" + `
// 	// Metadata  map[string]string ` + "`" + `json:"metadata,omitempty"` + "`" + `
// }
`

// grantTemplate generates a new custom OAuth 2.0 grant type handler,
// implementing the REAL extension point this codebase provides:
// oauth.GrantHandler (protocols/oauth/grant_handler.go) — GrantType() string
// + Handle(ctx core.HandlerContext, client *core.Client, req
// oauth.TokenRequest, dpopJKT, mtlsX5T string), registered via
// sso.WithCustomGrant. See interfaces/sso/server_setup.go's
// saml2BearerHandler for the simplest real (production) example this
// template mirrors. This is deliberately NOT the built-in grant switch
// (authorization_code/client_credentials/refresh_token are special-cased in
// the server, not extension points) — GrantHandler is for NEW grant types
// only.
const grantTemplate = `package {{.Package}}

import (
	"net/http"

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// {{.Name}}GrantHandler implements oauth.GrantHandler for the
// {{.Description}} grant type. Register it once at boot:
//
//	sso.WithCustomGrant(&{{.Package}}.{{.Name}}GrantHandler{ /* deps */ })
//
// The production example this template mirrors is saml2BearerHandler at
// interfaces/sso/server_setup.go, the grant the server registers via
// sso.WithSAML2BearerGrant.
type {{.Name}}GrantHandler struct {
	// TODO: Add whatever dependencies this grant needs, e.g. a
	// func(client *core.Client) (string, core.TokenIssuer, error) accessor to
	// mint tokens, a core.ClientStore, a domain-specific validator, or a
	// Roles(ctx context.Context, userID, clientID string) ([]string, error)
	// accessor mirroring permissions.Provider.Roles (domains/permissions/
	// provider.go; wiring pattern at interfaces/sso/accessors_handlers.go)
	// for the B4-1 roles claim.
}

// GrantType returns the grant_type value clients send at /token.
// TODO: Return the URN/string clients will send, e.g.
// "urn:ietf:params:oauth:grant-type:{{.LowerName}}" for a URN-style custom
// grant (the RFC 8693 / OIDC CIBA convention), or a bare string
// ("{{.LowerName}}") for a simple custom type.
func (h *{{.Name}}GrantHandler) GrantType() string {
	return "{{.LowerName}}"
}

// Handle processes /token requests for this grant type. The caller
// (server_token.go's dispatchCustomGrant) has already authenticated the
// client and checked its GrantTypes allowlist; Handle MUST write a response
// — success or error — via ctx on every code path. Per this codebase's
// oracle-leak hardening (AGENTS.md §3): unknown/expired/consumed/mismatched
// grant state maps to a plain 400 invalid_grant, never a distinguishing
// detail.
func (h *{{.Name}}GrantHandler) Handle(ctx core.HandlerContext, client *core.Client, req oauth.TokenRequest, dpopJKT, mtlsX5T string) {
	// TODO: Replace with your {{.Description}} grant validation and token
	// issuance. Standard pattern:
	//
	// 1. Validate grant-specific parameters (e.g. req.Assertion for a
	//    JWT/SAML-bearer-style grant, req.Scope/req.Resource otherwise):
	//
	//    if req.Assertion == "" {
	//    	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
	//    	return
	//    }
	//
	// 2. Authorize the requested scopes against the client's AllowedScopes
	//    allowlist (RFC 6749 §3.3) via oauth.GrantedScopes — the SAME gate
	//    every built-in issuance entry applies (CIBA at
	//    protocols/oauth/handle_ciba.go, client_credentials at
	//    internal/handler/tokengrant/token_client_credentials.go), so a
	//    custom grant must not mint tokens past the per-client gate. The
	//    dispatch-level registry seam (rejectUnregisteredScopes →
	//    scoperegistry.RejectUnregistered, wired via sso.WithScopeRegistry /
	//    oauth.scope_registry.enabled) already rejected unregistered
	//    REQUEST-borne scopes before this handler ran. This example covers
	//    only request-borne scopes; the internal-mint registry check is
	//    intentionally not shown — a handler that composes scopes beyond
	//    the request MUST run scoperegistry.RejectUnregistered on the
	//    effective set before issuance, exactly as token_client_credentials.go
	//    does (the dispatch seam cannot see them).
	//
	//    grantedScopes, err := oauth.GrantedScopes(oauth.SplitScope(req.Scope), client)
	//    if err != nil {
	//    	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
	//    	return
	//    }
	//
	// 3. Resolve the resource owner's role codes before issuance: the B4-1
	//    roles claim source is the dedicated Subject.Roles field ([]string,
	//    emitted as a top-level roles claim only when non-empty — same
	//    guard discipline as the AMR claim, see
	//    infrastructure/defaultimpl/issue_payload.go), populated from an
	//    accessor mirroring permissions.Provider.Roles(ctx, userID, clientID)
	//    (domains/permissions/provider.go; wiring pattern at
	//    interfaces/sso/accessors_handlers.go). That call site feeds
	//    conditional-access groups and fails open; the server's own mint
	//    path instead resolves codes from the TenantUserStore roster
	//    (subjectRoles in interfaces/sso/server_oauth.go). A custom grant
	//    with no roster access may mirror the (ctx, userID, clientID)
	//    accessor shape, projecting each role.Code into the []string this
	//    field takes. The 500 on accessor failure is deliberate: minting
	//    without roles would silently under-claim the token, so unlike the
	//    fail-open advisory path this example fails closed.
	//
	//    roles, err := h.Roles(ctx.Request().Context(), resourceOwnerID, client.ID)
	//    if err != nil {
	//    	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
	//    	return
	//    }
	//
	// 4. Mint a token via the same path every built-in grant uses, passing
	//    the VALIDATED grantedScopes (never the raw request scope string)
	//    and the resolved roles. The issuerForClient accessor resolves the
	//    minting strategy and the TokenIssuer; that TokenIssuer stamps the
	//    operator-configured issuer into the token's iss claim (the server
	//    wires it from server.issuer via sso.WithIssuer, interfaces/sso/
	//    options.go) — never a request-derived value. If the grant needs the
	//    issuer identifier itself (RFC 9207 iss parity with the discovery
	//    document), mirror the exported accessor (*sso.Server).ResolveIssuer(ctx)
	//    (interfaces/sso/accessors.go, wrapping resolveIssuer at interfaces/
	//    sso/server_discovery.go): the configured WithIssuer value wins when
	//    set and not the DefaultIssuer sentinel (shared/core/consts_oauth.go);
	//    only the sentinel falls back to the request base URL. The B4-1
	//    allowlist contract forbids Host-derived issuer values: never take
	//    the iss claim from the request Host header, a proxy-forwarded Host
	//    header, or the request base URL helper — iss must equal the
	//    identifier the server publishes via discovery (RFC 9207 §2
	//    mix-up detection).
	//
	//    strategy, issuer, err := h.issuerForClient(client)
	//    if err != nil {
	//    	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
	//    	return
	//    }
	//    token, err := issuer.Issue(ctx.Request().Context(), &core.Subject{
	//    	ID:       resourceOwnerID, // if applicable
	//    	ClientID: client.ID,
	//    	TenantID: client.TenantID,
	//    	Roles:    roles,
	//    }, grantedScopes)
	//    if err != nil {
	//    	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
	//    	return
	//    }
	//    ctx.JSON(http.StatusOK, map[string]any{
	//    	core.KeyAccessToken: token.AccessToken,
	//    	core.KeyTokenType:   token.TokenType,
	//    	core.KeyExpiresIn:   token.ExpiresIn,
	//    	core.KeyScope:       token.Scope,
	//    })
	//
	// After filling in your logic, remove this marker. Until then, this
	// safely fails closed with the same invalid_grant every unimplemented/
	// unrecognized grant state returns elsewhere in this codebase.

	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
}
`
