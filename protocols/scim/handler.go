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
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
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
	if h.dispatchMeta(w, r, rel) {
		return
	}
	if h.dispatchUsers(w, r, rel) {
		return
	}
	if h.dispatchGroups(w, r, rel) {
		return
	}
	h.writeError(w, newError(http.StatusNotFound, "", "unknown SCIM endpoint"))
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
