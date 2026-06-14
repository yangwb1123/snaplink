// Package scim provides a SCIM 2.0 (RFC 7643 schema / RFC 7644 protocol)
// User provisioning surface composed over the existing core.UserProvider.
//
// It adds NO new datastore: create/replace/delete route through
// core.UserProvider.CreateOrUpdate / Delete, and read/list through
// GetByID / List — so SCIM provisioning works against any backend wired
// into the server (memory, SQLite, or a custom store) with zero schema
// change. SCIM-only attributes that core.User has no dedicated field for
// (userName, active, name sub-attributes, non-primary emails) are stored
// in core.User.Attributes under a "scim:" namespace and round-tripped
// losslessly (see user.go).
//
// The Handler is transport-agnostic: it satisfies http.Handler and does
// its own method + path dispatch (mirroring cmd/sso-server's
// compliance_routes pattern) so it can be mounted either standalone or on
// the SSO router behind admin auth. It is intentionally UNAUTHENTICATED
// on its own — SCIM leaks and mutates the entire user directory, so the
// caller MUST gate it (the cmd wiring mounts it under the admin Bearer
// middleware).
package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/permissions"
)

// IDGenerator mints the storage id for a newly created resource. The
// default uses crypto/rand; tests inject a deterministic generator. WHY
// an interface: SCIM clients send no id on create (the server owns it),
// and we don't want to hard-wire a particular id scheme into the handler.
type IDGenerator func() string

// Handler serves the SCIM 2.0 User endpoints over a core.UserProvider.
// Construct with NewHandler. The zero value is not usable.
type Handler struct {
	users core.UserProvider
	// basePath is the absolute mount prefix (e.g. "/api/v1/scim/v2"),
	// trimmed of a trailing slash. Used both to strip the prefix during
	// dispatch and to build absolute meta.location values.
	basePath string
	// recorder is optional; nil disables audit (the handler still
	// functions). Reuses the server's admin user events.
	recorder *audit.Recorder
	newID    IDGenerator
	now      func() time.Time
	// groups is nil unless WithGroups wired a permissions.Provider. When
	// nil the /Groups routes 404 (groups aren't provisioned) — the User
	// surface keeps working independently.
	groups *groupRole
	// meResolver maps an incoming request to the authenticated subject's user
	// id for the /Me alias (RFC 7644 §3.11). Nil leaves /Me returning 501 —
	// the handler can't know who the caller is without the embedder wiring its
	// auth context in. Kept as a plain func so scim stays decoupled from the
	// auth middleware package.
	meResolver func(*http.Request) (string, bool)
}

// Option configures a Handler.
type Option func(*Handler)

// WithRecorder wires audit emission. SCIM create/replace/delete reuse the
// existing admin user events (EventAdminUserCreated/Updated/Deleted) so
// they land in the same audit stream as the gRPC/REST admin API rather
// than introducing a parallel event vocabulary.
func WithRecorder(r *audit.Recorder) Option {
	return func(h *Handler) { h.recorder = r }
}

// WithIDGenerator overrides the resource id minting strategy (tests use
// this for deterministic ids).
func WithIDGenerator(gen IDGenerator) Option {
	return func(h *Handler) {
		if gen != nil {
			h.newID = gen
		}
	}
}

// WithClock overrides the time source (tests use this for stable meta
// timestamps).
func WithClock(now func() time.Time) Option {
	return func(h *Handler) {
		if now != nil {
			h.now = now
		}
	}
}

// WithGroups enables the SCIM /Groups resource, mapping each group onto a
// permissions.Role under clientID: the group's server-minted id is the
// Role.Code, displayName is the Role.Name, and members are the users
// assigned that role. An IdP group push therefore drives the same RBAC
// model the rest of the server reads. clientID is the app the IdP
// provisions for (""— the demo/default bucket — is valid). Omit this
// option to leave /Groups unmounted (User provisioning still works).
func WithGroups(perms permissions.Provider, clientID string) Option {
	return func(h *Handler) {
		if perms != nil {
			h.groups = &groupRole{perms: perms, clientID: clientID}
		}
	}
}

// WithMeResolver enables the SCIM /Me alias (RFC 7644 §3.11) by supplying a
// function that extracts the authenticated subject's user id from the request
// (e.g. reading the auth middleware's actor from the request context). /Me then
// dispatches GET/PUT/PATCH/DELETE against that user's own resource. Omit this
// option (the default) to leave /Me returning 501 — the handler cannot resolve
// "the caller" on its own.
func WithMeResolver(resolve func(*http.Request) (string, bool)) Option {
	return func(h *Handler) {
		if resolve != nil {
			h.meResolver = resolve
		}
	}
}

// NewHandler builds a SCIM Handler over users. basePath is the absolute
// URL prefix the handler is mounted under (used to strip the route prefix
// and to render meta.location); pass "" if mounting at the root.
func NewHandler(users core.UserProvider, basePath string, opts ...Option) *Handler {
	h := &Handler{
		users:    users,
		basePath: strings.TrimRight(basePath, "/"),
		newID:    randomID,
		now:      func() time.Time { return time.Now().UTC() },
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

var _ http.Handler = (*Handler)(nil)

// ServeHTTP dispatches on method + the SCIM-relative path (the path with
// basePath stripped). It tolerates a trailing slash on collection routes.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rel := h.relPath(r.URL.Path)
	switch {
	case rel == pathServiceProviderConfig && r.Method == http.MethodGet:
		h.writeJSON(w, http.StatusOK, serviceProviderConfig())
	case rel == pathSchemas && r.Method == http.MethodGet:
		// GET /Schemas returns the implemented schemas as a ListResponse
		// (RFC 7643 §7 / RFC 7644 §4): connectors enumerate here. Group is
		// advertised only when WithGroups wired it, so a connector doesn't
		// push groups to a deployment that drops them.
		schemas := []SchemaResource{userSchema()}
		if h.groups != nil {
			schemas = append(schemas, groupSchema())
		}
		h.writeJSON(w, http.StatusOK, schemasListResponse(schemas))
	case rel == pathBulk && r.Method == http.MethodPost:
		h.bulk(w, r)
	case rel == pathMe:
		h.me(w, r)
	case rel == pathUsers || rel == pathUsers+"/":
		switch r.Method {
		case http.MethodPost:
			h.createUser(w, r)
		case http.MethodGet:
			h.listUsers(w, r)
		default:
			h.writeError(w, newError(http.StatusMethodNotAllowed, "", "method not allowed on /Users"))
		}
	case strings.HasPrefix(rel, pathUsers+"/"):
		id := strings.TrimPrefix(rel, pathUsers+"/")
		// A nested segment (".../Users/a/b") is not a single resource id.
		if id == "" || strings.Contains(id, "/") {
			h.writeError(w, newError(http.StatusNotFound, "", "resource not found"))
			return
		}
		switch r.Method {
		case http.MethodGet:
			h.getUser(w, r, id)
		case http.MethodPut:
			h.replaceUser(w, r, id)
		case http.MethodPatch:
			h.patchUser(w, r, id)
		case http.MethodDelete:
			h.deleteUser(w, r, id)
		default:
			h.writeError(w, newError(http.StatusMethodNotAllowed, "", "method not allowed on /Users/{id}"))
		}
	case h.groups != nil && (rel == pathGroups || rel == pathGroups+"/"):
		switch r.Method {
		case http.MethodPost:
			h.createGroup(w, r)
		case http.MethodGet:
			h.listGroups(w, r)
		default:
			h.writeError(w, newError(http.StatusMethodNotAllowed, "", "method not allowed on /Groups"))
		}
	case h.groups != nil && strings.HasPrefix(rel, pathGroups+"/"):
		id := strings.TrimPrefix(rel, pathGroups+"/")
		if id == "" || strings.Contains(id, "/") {
			h.writeError(w, newError(http.StatusNotFound, "", "resource not found"))
			return
		}
		switch r.Method {
		case http.MethodGet:
			h.getGroup(w, r, id)
		case http.MethodPut:
			h.replaceGroup(w, r, id)
		case http.MethodPatch:
			h.patchGroup(w, r, id)
		case http.MethodDelete:
			h.deleteGroup(w, r, id)
		default:
			h.writeError(w, newError(http.StatusMethodNotAllowed, "", "method not allowed on /Groups/{id}"))
		}
	default:
		h.writeError(w, newError(http.StatusNotFound, "", "unknown SCIM endpoint"))
	}
}

// relPath strips the mount prefix, yielding the SCIM-relative path the
// dispatcher matches on. When basePath isn't a prefix of urlPath (the
// handler was invoked directly in a test with a SCIM-relative URL) the
// path passes through unchanged.
func (h *Handler) relPath(urlPath string) string {
	if h.basePath != "" && strings.HasPrefix(urlPath, h.basePath) {
		return urlPath[len(h.basePath):]
	}
	return urlPath
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	res, ok := h.decode(w, r)
	if !ok {
		return
	}
	// userName is REQUIRED on the core User schema (RFC 7643 §4.1.1).
	if strings.TrimSpace(res.UserName) == "" {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidValue, "userName is required"))
		return
	}
	id := h.newID()
	// Guard against an id collision (newID is random, but a custom
	// generator could clash) AND enforce userName uniqueness. WHY a
	// read-then-write (not compare-and-swap): core.UserProvider exposes
	// no atomic insert, so two concurrent creates of the same userName
	// could both pass this check. That is an accepted limitation of
	// composing over the existing SPI without a redesign — SCIM
	// provisioning is admin-gated and connectors serialize per-resource,
	// so the race is not reachable in practice. A future Groups/PATCH
	// slice that needs strict uniqueness should add an indexed SPI.
	if _, err := h.users.GetByID(r.Context(), id); err == nil {
		h.writeError(w, newError(http.StatusConflict, scimTypeUniqueness, "generated id already exists"))
		return
	}
	if dup, err := h.userNameExists(r.Context(), res.UserName, ""); err != nil {
		h.writeError(w, h.storageError(err))
		return
	} else if dup {
		h.writeError(w, newError(http.StatusConflict, scimTypeUniqueness, "userName already exists"))
		return
	}

	u := res.toUser(id)
	now := h.now()
	u.CreatedAt = now
	u.UpdatedAt = now
	if err := h.users.CreateOrUpdate(r.Context(), u); err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	h.audit(r, audit.EventAdminUserCreated, id)
	h.writeJSON(w, http.StatusCreated, userToResource(u, h.location(id)))
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request, id string) {
	u, err := h.users.GetByID(r.Context(), id)
	if errors.Is(err, core.ErrNoSuchUser) {
		h.writeError(w, newError(http.StatusNotFound, "", "user not found"))
		return
	}
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	h.writeJSON(w, http.StatusOK, userToResource(u, h.location(id)))
}

func (h *Handler) replaceUser(w http.ResponseWriter, r *http.Request, id string) {
	existing, err := h.users.GetByID(r.Context(), id)
	if errors.Is(err, core.ErrNoSuchUser) {
		// PUT to an unknown resource is a 404, not an upsert: SCIM PUT
		// replaces an EXISTING resource (RFC 7644 §3.5.1).
		h.writeError(w, newError(http.StatusNotFound, "", "user not found"))
		return
	}
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	res, ok := h.decode(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(res.UserName) == "" {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidValue, "userName is required"))
		return
	}
	// id is read-only (RFC 7643 §3.1 / §7 mutability=readOnly): a body
	// that carries a DIFFERENT id is a mutability violation.
	if res.ID != "" && res.ID != id {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeMutability, "id is immutable"))
		return
	}
	// userName must stay unique against OTHER users.
	if dup, err := h.userNameExists(r.Context(), res.UserName, id); err != nil {
		h.writeError(w, h.storageError(err))
		return
	} else if dup {
		h.writeError(w, newError(http.StatusConflict, scimTypeUniqueness, "userName already exists"))
		return
	}

	u := res.toUser(id)
	// Replace is a full overwrite of the resource attributes, but the
	// creation timestamp is immutable — preserve it from the stored row.
	u.CreatedAt = existing.CreatedAt
	u.UpdatedAt = h.now()
	if err := h.users.CreateOrUpdate(r.Context(), u); err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	h.audit(r, audit.EventAdminUserUpdated, id)
	h.writeJSON(w, http.StatusOK, userToResource(u, h.location(id)))
}

// patchUser applies a SCIM PATCH (RFC 7644 §3.5.2) to a stored user. WHY
// load -> userToResource -> apply ops -> toUser: PATCH mutates the SAME
// Resource view that create/replace produce, so the attribute<->core.User
// mapping stays single-source. The deprovision case Azure AD / Okta send
// (replace active=false) flows straight through to scim:active. PATCH is
// all-or-nothing: a failing op aborts before any write.
func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request, id string) {
	existing, err := h.users.GetByID(r.Context(), id)
	if errors.Is(err, core.ErrNoSuchUser) {
		h.writeError(w, newError(http.StatusNotFound, "", "user not found"))
		return
	}
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	ops, ok := h.decodePatch(w, r)
	if !ok {
		return
	}

	res := userToResource(existing, "")
	if e, ok := applyUserPatch(&res, ops); !ok {
		h.writeError(w, e)
		return
	}
	// userName is REQUIRED (RFC 7643 §4.1.1): a PATCH must not leave it
	// blank (e.g. replace userName="").
	if strings.TrimSpace(res.UserName) == "" {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidValue, "userName is required"))
		return
	}
	if dup, err := h.userNameExists(r.Context(), res.UserName, id); err != nil {
		h.writeError(w, h.storageError(err))
		return
	} else if dup {
		h.writeError(w, newError(http.StatusConflict, scimTypeUniqueness, "userName already exists"))
		return
	}

	u := res.toUser(id)
	u.CreatedAt = existing.CreatedAt
	u.UpdatedAt = h.now()
	if err := h.users.CreateOrUpdate(r.Context(), u); err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	h.audit(r, audit.EventAdminUserUpdated, id)
	h.writeJSON(w, http.StatusOK, userToResource(u, h.location(id)))
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, id string) {
	// Probe existence first: core.UserProvider.Delete is idempotent
	// (missing id -> nil), but SCIM DELETE on an unknown resource MUST
	// be 404 (RFC 7644 §3.6), so we can't blindly return 204.
	if _, err := h.users.GetByID(r.Context(), id); err != nil {
		if errors.Is(err, core.ErrNoSuchUser) {
			h.writeError(w, newError(http.StatusNotFound, "", "user not found"))
			return
		}
		h.writeError(w, h.storageError(err))
		return
	}
	if err := h.users.Delete(r.Context(), id); err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	h.audit(r, audit.EventAdminUserDeleted, id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	all, err := h.users.List(r.Context())
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	startIndex, count, perr := paginationParams(r)
	if perr != nil {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidValue, perr.Error()))
		return
	}

	// Project to SCIM resources, then apply ?filter= over that view BEFORE
	// pagination (RFC 7644 §3.4.2.2): filtering narrows the result set, and
	// totalResults/itemsPerPage must reflect the FILTERED set, not the raw
	// store size. Filtering over the Resource shape (not core.User) keeps
	// the attribute semantics identical to what a GET returns.
	resources := make([]Resource, 0, len(all))
	for _, u := range all {
		resources = append(resources, userToResource(u, h.location(u.ID)))
	}
	resources, ferr := h.filterUsers(r, resources)
	if ferr != nil {
		h.writeError(w, *ferr)
		return
	}

	total := len(resources)
	// startIndex is 1-based (RFC 7644 §3.4.2.4). Translate to a 0-based
	// slice offset, clamped to the bounds.
	lo := startIndex - 1
	if lo > total {
		lo = total
	}
	hi := lo + count
	if hi > total {
		hi = total
	}
	page := resources[lo:hi]

	h.writeJSON(w, http.StatusOK, ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(page),
		Resources:    page,
	})
}

// filterUsers applies the optional ?filter= query parameter to a User
// resource slice (RFC 7644 §3.4.2.2). An absent/blank filter returns the
// slice unchanged. A malformed filter returns a SCIM 400 invalidFilter
// pointer so the caller writes the error and stops (rather than silently
// returning everything, which would mislead a connector reconciling on the
// filter result).
func (h *Handler) filterUsers(r *http.Request, in []Resource) ([]Resource, *ErrorResponse) {
	raw := trimFilter(r.URL.Query().Get(queryFilter))
	if raw == "" {
		return in, nil
	}
	expr, err := parseFilter(raw)
	if err != nil {
		e := newError(http.StatusBadRequest, scimTypeInvalidFilter, "malformed filter expression")
		return nil, &e
	}
	out := make([]Resource, 0, len(in))
	for _, res := range in {
		if matchesUser(res, expr) {
			out = append(out, res)
		}
	}
	return out, nil
}

// userNameExists reports whether some user OTHER than excludeID carries
// userName. WHY a List scan: core.UserProvider has no userName index
// (userName lives in Attributes), so uniqueness is enforced here over the
// existing List API rather than by adding a new SPI method. Empty
// userName is treated as not-a-duplicate (the caller validates required
// separately).
func (h *Handler) userNameExists(ctx context.Context, userName, excludeID string) (bool, error) {
	if userName == "" {
		return false, nil
	}
	all, err := h.users.List(ctx)
	if err != nil {
		return false, err
	}
	for _, u := range all {
		if u.ID == excludeID {
			continue
		}
		if u.Attributes[attrUserName] == userName {
			return true, nil
		}
	}
	return false, nil
}

// decode reads and validates the SCIM JSON request body into a Resource.
// On failure it writes the SCIM error and returns ok=false.
func (h *Handler) decode(w http.ResponseWriter, r *http.Request) (Resource, bool) {
	var res Resource
	// Default active=true: a create/replace that omits "active" provisions
	// an ENABLED account (RFC 7643 §4.1.1 — active is a deprovision flag).
	res.Active = true
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&res); err != nil {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidSyntax, "request body is not valid SCIM JSON"))
		return Resource{}, false
	}
	return res, true
}

// decodePatch reads and validates a SCIM PATCH body (RFC 7644 §3.5.2).
// An empty Operations array is rejected: a PATCH with no operations is a
// malformed request, not a no-op (the spec requires at least one op).
func (h *Handler) decodePatch(w http.ResponseWriter, r *http.Request) ([]PatchOperation, bool) {
	var req PatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidSyntax, "request body is not valid SCIM PATCH JSON"))
		return nil, false
	}
	if len(req.Operations) == 0 {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidValue, "PATCH requires at least one operation"))
		return nil, false
	}
	return req.Operations, true
}

// location builds the absolute User resource URL for meta.location.
// Returns "" when no base path is configured (a relative mount).
func (h *Handler) location(id string) string {
	return h.locationFor(pathUsers, id)
}

// groupLocation builds the absolute Group resource URL for meta.location.
func (h *Handler) groupLocation(id string) string {
	return h.locationFor(pathGroups, id)
}

// locationFor builds an absolute resource URL under a collection path.
// Returns "" when no base path is configured (a relative mount), matching
// the User behavior so meta.location is omitted rather than rendered
// relative.
func (h *Handler) locationFor(collection, id string) string {
	if h.basePath == "" {
		return ""
	}
	return h.basePath + collection + "/" + id
}

// storageError maps an unexpected store error to a SCIM 500. core.User
// store errors carry no oracle risk here (the surface is admin-only), so
// the detail is passed through to aid operators.
func (h *Handler) storageError(err error) ErrorResponse {
	return newError(http.StatusInternalServerError, "", err.Error())
}

// audit emits the reused admin user event, stamping the data subject and
// (when present) the admin actor from the request context.
func (h *Handler) audit(r *http.Request, typ audit.EventType, subjectID string) {
	if h.recorder == nil {
		return
	}
	e := &audit.Event{
		Type:      typ,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: h.now(),
	}
	if actor, clientID, ok := actorFromContext(r.Context()); ok {
		e.ActorID = actor
		e.ClientID = clientID
	}
	audit.SetMeta(e, "subject", subjectID)
	audit.SetMeta(e, "via", "scim")
	h.recorder.Record(context.Background(), e)
}

func (h *Handler) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", contentTypeSCIM)
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) writeError(w http.ResponseWriter, e ErrorResponse) {
	code, _ := strconv.Atoi(e.Status)
	if code == 0 {
		code = http.StatusInternalServerError
	}
	h.writeJSON(w, code, e)
}

// schemasListResponse wraps the schema set in the ListResponse envelope.
// Schemas are not Resources, so this builds the envelope directly rather
// than reusing ListResponse (whose Resources field is []Resource).
func schemasListResponse(schemas []SchemaResource) map[string]any {
	return map[string]any{
		"schemas":      []string{SchemaListResponse},
		"totalResults": len(schemas),
		"startIndex":   1,
		"itemsPerPage": len(schemas),
		"Resources":    schemas,
	}
}
