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

	"github.com/snaplink/sso/shared/core"
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
// core.Router with router.GET("/path", func(ctx core.HandlerContext) {
// Handle{{.Name}}(deps, ctx) }), or delegate to it from a thin one-line
// (*sso.Server) method the same way domains/federation/health/handler.go's
// HandleListPeerHealth is wired from server_federation.go.
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
		ctx.JSON(http.StatusMethodNotAllowed, core.ErrorBody("method_not_allowed"))
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

	ctx.JSON(http.StatusNotImplemented, core.ErrorBody("not_implemented"))
}

// handle{{.Name}}Post processes POST requests.
// TODO: Replace with your create operations.
func handle{{.Name}}Post(deps {{.Name}}Deps, ctx core.HandlerContext) {
	// TODO: Replace with your POST logic, e.g.:
	//
	// var req CreateRequest
	// if err := ctx.Bind(&req); err != nil {
	// 	ctx.JSON(http.StatusBadRequest, core.ErrorBody("invalid_request"))
	// 	return
	// }
	// entity, err := deps.Create(ctx.Request().Context(), req)
	// if err != nil {
	// 	ctx.JSON(http.StatusInternalServerError, core.ErrorBody("create_failed"))
	// 	return
	// }
	// ctx.JSON(http.StatusCreated, entity)
	//
	// After filling in your logic, remove this marker.

	ctx.JSON(http.StatusNotImplemented, core.ErrorBody("not_implemented"))
}

// handle{{.Name}}Put processes PUT requests.
// TODO: Replace with your update operations.
func handle{{.Name}}Put(deps {{.Name}}Deps, ctx core.HandlerContext) {
	// TODO: Replace with your PUT logic.
	// After filling in your logic, remove this marker.

	ctx.JSON(http.StatusNotImplemented, core.ErrorBody("not_implemented"))
}

// handle{{.Name}}Delete processes DELETE requests.
// TODO: Replace with your delete operations.
func handle{{.Name}}Delete(deps {{.Name}}Deps, ctx core.HandlerContext) {
	// TODO: Replace with your DELETE logic.
	// After filling in your logic, remove this marker.

	ctx.JSON(http.StatusNotImplemented, core.ErrorBody("not_implemented"))
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
// sso.WithCustomGrant. See interfaces/sso/options_saml2_bearer.go's
// saml2BearerHandler for the simplest real (production) example this
// template mirrors. This is deliberately NOT the built-in grant switch
// (authorization_code/client_credentials/refresh_token are special-cased in
// the server, not extension points) — GrantHandler is for NEW grant types
// only.
const grantTemplate = `package {{.Package}}

import (
	"net/http"

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// {{.Name}}GrantHandler implements oauth.GrantHandler for the
// {{.Description}} grant type. Register it once at boot:
//
//	sso.WithCustomGrant(&{{.Package}}.{{.Name}}GrantHandler{ /* deps */ })
type {{.Name}}GrantHandler struct {
	// TODO: Add whatever dependencies this grant needs, e.g. a
	// func(client *core.Client) (string, core.TokenIssuer, error) accessor to
	// mint tokens, a core.ClientStore, or a domain-specific validator.
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
	// 2. Mint a token via the same path every built-in grant uses:
	//
	//    strategy, issuer, err := h.issuerForClient(client)
	//    if err != nil {
	//    	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
	//    	return
	//    }
	//    token, err := issuer.Issue(ctx.Request().Context(), &core.Subject{
	//    	ID:       resourceOwnerID, // if applicable
	//    	ClientID: client.ID,
	//    }, scopes)
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
