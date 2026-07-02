package generate

// handlerTemplate generates a new HTTP handler following the hexagonal pattern.
// Handlers process HTTP requests and delegate business logic to domain services.
const handlerTemplate = `package {{.Package}}

import (
	"encoding/json"
	"net/http"

	"github.com/snaplink/sso/shared/core"
)

// {{.Name}}Handler handles {{.Description}} requests.
// Follows the hexagonal architecture pattern: handlers are thin HTTP adapters
// that delegate business logic to domain services via the Deps interface.
type {{.Name}}Handler struct {
	deps {{.Name}}Deps
}

// {{.Name}}Deps defines the dependencies this handler needs.
// The Server struct satisfies this interface via accessors.go.
type {{.Name}}Deps interface {
	// TODO: Add required dependencies.
	// Examples:
	// core.UserProvider
	// core.ClientStore
	// core.SessionManager
	// core.TokenIssuer
	// spi.Logger
}

// New{{.Name}}Handler creates a new {{.Name}} handler.
func New{{.Name}}Handler(deps {{.Name}}Deps) *{{.Name}}Handler {
	return &{{.Name}}Handler{deps: deps}
}

// ServeHTTP implements http.Handler.
// Routes requests to the appropriate handler method based on HTTP method.
func (h *{{.Name}}Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleGet(w, r)
	case http.MethodPost:
		h.handlePost(w, r)
	case http.MethodPut:
		h.handlePut(w, r)
	case http.MethodDelete:
		h.handleDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGet processes GET requests.
// TODO: Implement read operations (list, get by ID, search).
func (h *{{.Name}}Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement GET logic.
	// Example pattern:
	// 1. Parse query parameters
	// 2. Call domain service via h.deps
	// 3. Encode response as JSON
	// 
	// id := r.URL.Query().Get("id")
	// entity, err := h.deps.Get(r.Context(), id)
	// if err != nil {
	// 	writeError(w, http.StatusNotFound, "not found")
	// 	return
	// }
	// writeJSON(w, http.StatusOK, entity)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "{{.LowerName}} GET not implemented",
	})
}

// handlePost processes POST requests.
// TODO: Implement create operations.
func (h *{{.Name}}Handler) handlePost(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement POST logic.
	// Example pattern:
	// 1. Decode request body
	// 2. Validate input
	// 3. Call domain service via h.deps
	// 4. Return created resource with 201 status
	// 
	// var req CreateRequest
	// if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
	// 	writeError(w, http.StatusBadRequest, "invalid request body")
	// 	return
	// }
	// 
	// entity, err := h.deps.Create(r.Context(), req)
	// if err != nil {
	// 	writeError(w, http.StatusInternalServerError, "create failed")
	// 	return
	// }
	// 
	// writeJSON(w, http.StatusCreated, entity)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "{{.LowerName}} POST not implemented",
	})
}

// handlePut processes PUT requests.
// TODO: Implement update operations.
func (h *{{.Name}}Handler) handlePut(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement PUT logic.
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "{{.LowerName}} PUT not implemented",
	})
}

// handleDelete processes DELETE requests.
// TODO: Implement delete operations.
func (h *{{.Name}}Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement DELETE logic.
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "{{.LowerName}} DELETE not implemented",
	})
}

// writeJSON encodes data as JSON and writes it to the response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Response already started; log the error but can't change status.
		http.Error(w, "encode response failed", http.StatusInternalServerError)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
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

// grantTemplate generates a new OAuth grant handler.
// Grants implement OAuth 2.0 flows (authorization_code, client_credentials, etc.)
const grantTemplate = `package {{.Package}}

import (
	"context"
	"fmt"
	"net/http"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

// {{.Name}}GrantHandler handles the {{.Description}} OAuth grant type.
// Implements the hexagonal pattern: pure functions in Handle*(deps, ctx) that
// the Server delegates to.
type {{.Name}}GrantHandler struct {
	deps {{.Name}}GrantDeps
}

// {{.Name}}GrantDeps defines dependencies for the {{.Name}} grant.
// The Server struct satisfies this via accessors.go.
type {{.Name}}GrantDeps interface {
	// TODO: Add required dependencies for your grant type.
	// Common patterns:
	// core.ClientStore        // validate client_id
	// core.TokenIssuer        // issue access/refresh tokens
	// core.SessionManager     // create/manage sessions
	// core.UserProvider       // validate resource owner (for ROPC)
	// spi.Logger              // audit logging
}

// New{{.Name}}GrantHandler creates a new {{.Name}} grant handler.
func New{{.Name}}GrantHandler(deps {{.Name}}GrantDeps) *{{.Name}}GrantHandler {
	return &{{.Name}}GrantHandler{deps: deps}
}

// HandleToken processes /token requests for grant_type={{.LowerName}}.
// This is the main entry point called by the Server's token endpoint.
func (h *{{.Name}}GrantHandler) HandleToken(ctx context.Context, req *core.TokenRequest) (*core.TokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("token request is nil")
	}

	// TODO: Implement {{.Description}} grant logic.
	// 
	// Standard pattern:
	// 1. Validate grant-specific parameters from req
	// 2. Authenticate the client (req.ClientID + req.ClientSecret)
	// 3. Validate grant-specific requirements
	// 4. Issue tokens via deps.TokenIssuer
	// 5. Return TokenResponse with access_token, refresh_token (if applicable)
	// 
	// Example for a custom grant:
	// 
	// // Validate grant-specific parameters
	// customParam := req.Parameters["custom_param"]
	// if customParam == "" {
	// 	return nil, &core.OAuthError{
	// 		Code:        "invalid_request",
	// 		Description: "missing custom_param",
	// 	}
	// }
	// 
	// // Authenticate client
	// client, err := h.deps.GetClient(ctx, req.ClientID)
	// if err != nil {
	// 	return nil, &core.OAuthError{
	// 		Code:        "invalid_client",
	// 		Description: "client authentication failed",
	// 	}
	// }
	// 
	// // Validate client is allowed to use this grant
	// if !client.IsGrantAllowed("{{.LowerName}}") {
	// 	return nil, &core.OAuthError{
	// 		Code:        "unauthorized_client",
	// 		Description: "client not authorized for {{.LowerName}} grant",
	// 	}
	// }
	// 
	// // Issue tokens
	// accessToken, err := h.deps.IssueAccessToken(ctx, &core.TokenClaims{
	// 	ClientID: client.ID,
	// 	Subject:  resourceOwnerID, // if applicable
	// 	Scope:    req.Scope,
	// })
	// if err != nil {
	// 	return nil, fmt.Errorf("issue access token: %w", err)
	// }
	// 
	// return &core.TokenResponse{
	// 	AccessToken: accessToken,
	// 	TokenType:   "Bearer",
	// 	ExpiresIn:   3600,
	// 	Scope:       req.Scope,
	// }, nil

	return nil, fmt.Errorf("{{.LowerName}} grant not implemented")
}

// ValidateRequest performs grant-specific request validation.
// Called before HandleToken to reject malformed requests early.
func (h *{{.Name}}GrantHandler) ValidateRequest(req *core.TokenRequest) error {
	if req == nil {
		return fmt.Errorf("request is nil")
	}

	// TODO: Add grant-specific validation.
	// Example:
	// if req.Parameters["custom_param"] == "" {
	// 	return &core.OAuthError{
	// 		Code:        "invalid_request",
	// 		Description: "custom_param is required",
	// 	}
	// }

	return nil
}

// HandleRevoke processes token revocation for tokens issued by this grant.
// Optional: implement if your grant needs custom revocation logic.
func (h *{{.Name}}GrantHandler) HandleRevoke(ctx context.Context, token string) error {
	// TODO: Implement revocation if needed.
	// Example:
	// return h.deps.RevokeToken(ctx, token)
	return nil
}

// HandleIntrospect processes token introspection for tokens issued by this grant.
// Optional: implement if your grant needs custom introspection logic.
func (h *{{.Name}}GrantHandler) HandleIntrospect(ctx context.Context, token string) (*core.IntrospectionResponse, error) {
	// TODO: Implement introspection if needed.
	// Example:
	// claims, err := h.deps.ValidateToken(ctx, token)
	// if err != nil {
	// 	return &core.IntrospectionResponse{Active: false}, nil
	// }
	// return &core.IntrospectionResponse{
	// 	Active:    true,
	// 	ClientID:  claims.ClientID,
	// 	Scope:     claims.Scope,
	// 	ExpiresAt: claims.ExpiresAt,
	// }, nil
	return nil, fmt.Errorf("{{.LowerName}} introspection not implemented")
}

// ServeHTTP implements http.Handler for direct HTTP handling.
// Optional: use if you need custom HTTP endpoints beyond /token.
func (h *{{.Name}}GrantHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement custom HTTP endpoints if needed.
	// Example:
	// switch r.URL.Path {
	// case "/{{.LowerName}}/authorize":
	// 	h.handleAuthorize(w, r)
	// case "/{{.LowerName}}/callback":
	// 	h.handleCallback(w, r)
	// default:
	// 	http.NotFound(w, r)
	// }
	http.NotFound(w, r)
}

// Example request types (uncomment and customize as needed):

// {{.Name}}Request represents the grant-specific parameters.
// type {{.Name}}Request struct {
// 	// TODO: Add grant-specific fields.
// 	// Example:
// 	// CustomParam string ` + "`" + `json:"custom_param" form:"custom_param"` + "`" + `
// 	// ResourceID  string ` + "`" + `json:"resource_id" form:"resource_id"` + "`" + `
// }
`
