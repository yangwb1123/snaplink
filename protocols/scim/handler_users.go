package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

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
	// Trim whitespace but preserve the caller's casing — RFC 7643 §7.6 defines
	// caseExact=false as a comparison rule, not a normalization directive.
	// userNameExists uses strings.EqualFold for case-insensitive uniqueness.
	res.UserName = strings.TrimSpace(res.UserName)
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
	h.writeUserResource(w, http.StatusCreated, UserToResource(u, h.location(id)))
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
	res := UserToResource(u, h.location(id))
	version := stampUserVersion(&res)
	// If-None-Match: a GET whose cached ETag still matches gets 304 with no
	// body (RFC 7644 §3.14 / RFC 7232 §3.2), saving the client a re-parse.
	if ifNoneMatchMatches(r, version) {
		if version != "" {
			w.Header().Set(headerETag, version)
		}
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.writeUserResource(w, http.StatusOK, res)
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
	// If-Match: reject a replace whose expected version is stale (a
	// concurrent edit moved it on) BEFORE consuming the body (RFC 7644
	// §3.14).
	if !ifMatchSatisfied(r, currentUserVersion(existing, h.location(id))) {
		h.writeError(w, preconditionFailed())
		return
	}
	res, ok := h.decode(w, r)
	if !ok {
		return
	}
	// Trim whitespace; casing is preserved — see createUser for rationale.
	res.UserName = strings.TrimSpace(res.UserName)
	if !h.validateReplaceUser(w, r, res, id) {
		return
	}

	// PUT overwrites the SCIM-modeled attributes but MUST preserve server-managed
	// state no SCIM client can re-supply (Provider, password_hash, OIDC claims) —
	// a full toUser() would wipe them. The creation timestamp is immutable.
	u := res.toUserPreserving(id, existing)
	u.CreatedAt = existing.CreatedAt
	u.UpdatedAt = h.now()
	if err := h.users.CreateOrUpdate(r.Context(), u); err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	h.audit(r, audit.EventAdminUserUpdated, id)
	h.writeUserResource(w, http.StatusOK, UserToResource(u, h.location(id)))
}

// validateReplaceUser enforces the PUT body invariants: userName is required,
// id is read-only (a differing body id is a mutability violation, RFC 7643
// §3.1/§7), userName must stay unique against OTHER users, and manager
// references must not form a cycle. It writes the SCIM error and returns
// false on the first violation.
func (h *Handler) validateReplaceUser(w http.ResponseWriter, r *http.Request, res Resource, id string) bool {
	if strings.TrimSpace(res.UserName) == "" {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidValue, "userName is required"))
		return false
	}
	if res.ID != "" && res.ID != id {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeMutability, "id is immutable"))
		return false
	}
	if dup, err := h.userNameExists(r.Context(), res.UserName, id); err != nil {
		h.writeError(w, h.storageError(err))
		return false
	} else if dup {
		h.writeError(w, newError(http.StatusConflict, scimTypeUniqueness, "userName already exists"))
		return false
	}
	// Manager cycle check: ensure setting this manager doesn't create a cycle.
	if !h.validateManagerRef(w, r, res, id) {
		return false
	}
	return true
}

// validateManagerRef checks whether the enterprise manager reference in res
// would create a cycle (userID -> manager -> ... -> userID). Returns true
// when the manager reference is valid or absent; writes the SCIM error and
// returns false when a cycle is detected.
func (h *Handler) validateManagerRef(w http.ResponseWriter, r *http.Request, res Resource, id string) bool {
	ext := res.EnterpriseExtension
	if ext == nil || ext.Manager == nil || ext.Manager.Value == "" {
		return true // no manager reference to validate
	}
	managerID := ext.Manager.Value
	getManager := func(ctx context.Context, uid string) (string, error) {
		u, err := h.users.GetByID(ctx, uid)
		if err != nil {
			return "", err
		}
		// Extract the manager ID from stored Attributes (same namespace
		// the enterprise extension round-trips through).
		raw := u.Attributes[attrManager]
		if raw == "" {
			return "", nil
		}
		var mgr ManagerRef
		if err := json.Unmarshal([]byte(raw), &mgr); err != nil {
			return "", nil // best-effort: treat unparseable as no manager
		}
		return mgr.Value, nil
	}
	if err := DetectManagerCycle(r.Context(), id, managerID, getManager); err != nil {
		if errors.Is(err, ErrManagerCycle) {
			h.writeError(w, newError(http.StatusConflict, scimTypeMutability, "manager reference creates a cycle"))
			return false
		}
		h.writeError(w, h.storageError(err))
		return false
	}
	return true
}

// patchUser applies a SCIM PATCH (RFC 7644 §3.5.2) to a stored user. WHY
// load -> UserToResource -> apply ops -> toUser: PATCH mutates the SAME
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
	// If-Match: reject a stale PATCH before applying any op (RFC 7644 §3.14).
	if !ifMatchSatisfied(r, currentUserVersion(existing, h.location(id))) {
		h.writeError(w, preconditionFailed())
		return
	}
	ops, ok := h.decodePatch(w, r)
	if !ok {
		return
	}

	res := UserToResource(existing, "")
	if e, ok := applyUserPatch(&res, ops); !ok {
		h.writeError(w, e)
		return
	}
	if h.patchUserCommit(w, r, res, id, existing) {
		return
	}
}

// patchUserCommit validates userName, checks uniqueness, validates the manager
// reference (cycle detection), persists the patched user, and emits the audit
// event. Returns true when it has written an error and the caller must stop.
func (h *Handler) patchUserCommit(w http.ResponseWriter, r *http.Request, res Resource, id string, existing *core.User) bool {
	normalized, ok := h.normalizeAndCheckUserName(w, r, res.UserName, id)
	if !ok {
		return true
	}
	res.UserName = normalized
	// Manager cycle check: ensure the patched manager reference doesn't
	// create a cycle (applies whether the PATCH added, changed, or left
	// the manager unchanged).
	if !h.validateManagerRef(w, r, res, id) {
		return true
	}
	// PATCH is a partial update (RFC 7644 §3.5.2); toUserPreserving keeps non-SCIM state.
	u := res.toUserPreserving(id, existing)
	u.CreatedAt = existing.CreatedAt
	u.UpdatedAt = h.now()
	if err := h.users.CreateOrUpdate(r.Context(), u); err != nil {
		h.writeError(w, h.storageError(err))
		return true
	}
	h.audit(r, audit.EventAdminUserUpdated, id)
	h.writeUserResource(w, http.StatusOK, UserToResource(u, h.location(id)))
	return false
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, id string) {
	// Probe existence first: core.UserProvider.Delete is idempotent
	// (missing id -> nil), but SCIM DELETE on an unknown resource MUST
	// be 404 (RFC 7644 §3.6), so we can't blindly return 204.
	existing, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, core.ErrNoSuchUser) {
			h.writeError(w, newError(http.StatusNotFound, "", "user not found"))
			return
		}
		h.writeError(w, h.storageError(err))
		return
	}
	// If-Match: a conditional DELETE only proceeds when the caller's version
	// is current (RFC 7644 §3.14), guarding against deleting a resource that
	// changed since the caller last read it.
	if !ifMatchSatisfied(r, currentUserVersion(existing, h.location(id))) {
		h.writeError(w, preconditionFailed())
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
		resources = append(resources, UserToResource(u, h.location(u.ID)))
	}
	resources, ferr := h.filterUsers(r, resources)
	if ferr != nil {
		h.writeError(w, *ferr)
		return
	}
	// Sort the FILTERED set before paginating (RFC 7644 §3.4.2.3): the page
	// must be a window into the fully ordered result.
	sortUsers(resources, parseSortSpec(r))

	total := len(resources)
	lo, hi := pageBounds(startIndex, count, total)
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
