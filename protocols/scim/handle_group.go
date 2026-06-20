package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/platform/audit"
)

// Group handlers (RFC 7643 §4.2 + RFC 7644 CRUD/PATCH). A SCIM Group is a
// permissions.Role under h.groups.clientID; membership is the set of
// users assigned that role. These reuse the existing admin role audit
// events (EventAdminRole*) so group provisioning lands in the same audit
// stream as the gRPC/REST permission admin API.

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	g, ok := h.decodeGroup(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(g.DisplayName) == "" {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidValue, "displayName is required"))
		return
	}
	id := h.newID()
	// The group id is the Role.Code. AddRole rejects a duplicate code with
	// ErrRoleExists; a random id colliding is near-impossible but a custom
	// generator could clash, so the conflict is mapped to SCIM uniqueness.
	role := permissions.Role{Code: id, Name: g.DisplayName}
	if err := h.groups.perms.AddRole(r.Context(), h.groups.clientID, role); err != nil {
		if errors.Is(err, permissions.ErrRoleExists) {
			h.writeError(w, newError(http.StatusConflict, scimTypeUniqueness, "group id already exists"))
			return
		}
		h.writeError(w, h.storageError(err))
		return
	}
	// Grant the initial members. WHY after AddRole (not transactional): the
	// permissions SPI has no multi-op transaction; AddRole then per-member
	// AddRoleToUser is the same shape the admin API uses, and a partial
	// failure surfaces as a 500 the connector retries (idempotent adds).
	members := g.memberValues()
	for _, uid := range members {
		if err := h.groups.addMember(r.Context(), uid, id); err != nil {
			h.writeError(w, h.storageError(err))
			return
		}
	}
	h.auditGroup(r, audit.EventAdminRoleAdded, id)
	h.writeGroupResource(w, http.StatusCreated, roleToGroup(role, members, h.groupLocation(id)))
}

func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request, id string) {
	role, found, err := h.groups.findRole(r.Context(), id)
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	if !found {
		h.writeError(w, newError(http.StatusNotFound, "", "group not found"))
		return
	}
	members, err := h.groups.members(r.Context(), id)
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	g := roleToGroup(role, members, h.groupLocation(id))
	version := stampGroupVersion(&g)
	// If-None-Match: an unchanged group read returns 304 (RFC 7644 §3.14).
	if ifNoneMatchMatches(r, version) {
		if version != "" {
			w.Header().Set(headerETag, version)
		}
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.writeGroupResource(w, http.StatusOK, g)
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	roles, err := h.groups.listRoles(r.Context())
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	startIndex, count, perr := paginationParams(r)
	if perr != nil {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidValue, perr.Error()))
		return
	}

	resources, merr := h.materializeGroups(r, roles)
	if merr != nil {
		h.writeError(w, *merr)
		return
	}
	resources, ferr := h.filterGroups(r, resources)
	if ferr != nil {
		h.writeError(w, *ferr)
		return
	}
	// Sort the filtered set before paginating (RFC 7644 §3.4.2.3).
	sortGroups(resources, parseSortSpec(r))

	total := len(resources)
	lo, hi := pageBounds(startIndex, count, total)
	page := resources[lo:hi]

	h.writeJSON(w, http.StatusOK, GroupListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(page),
		Resources:    page,
	})
}

// materializeGroups projects every role into a GroupResource, resolving each
// group's membership. WHY resolve members for ALL groups (not just the page):
// filtering + totalResults must see the full set BEFORE pagination (RFC 7644
// §3.4.2.2), and a `members eq` filter needs each group's membership. This is
// the same per-role members() call the unfiltered path makes, just over the
// whole role list (acceptable at operator-defined group scale — see filter.go
// performance note). A non-nil pointer carries the SCIM error to write.
func (h *Handler) materializeGroups(r *http.Request, roles []permissions.Role) ([]GroupResource, *ErrorResponse) {
	resources := make([]GroupResource, 0, len(roles))
	for _, role := range roles {
		members, err := h.groups.members(r.Context(), role.Code)
		if err != nil {
			e := h.storageError(err)
			return nil, &e
		}
		resources = append(resources, roleToGroup(role, members, h.groupLocation(role.Code)))
	}
	return resources, nil
}

// filterGroups applies the optional ?filter= query parameter to a Group
// resource slice (RFC 7644 §3.4.2.2). An absent/blank filter returns the
// slice unchanged; a malformed filter returns a SCIM 400 invalidFilter
// pointer for the caller to write.
func (h *Handler) filterGroups(r *http.Request, in []GroupResource) ([]GroupResource, *ErrorResponse) {
	raw := trimFilter(r.URL.Query().Get(queryFilter))
	if raw == "" {
		return in, nil
	}
	expr, err := parseFilter(raw)
	if err != nil {
		e := newError(http.StatusBadRequest, scimTypeInvalidFilter, "malformed filter expression")
		return nil, &e
	}
	out := make([]GroupResource, 0, len(in))
	for _, g := range in {
		if matchesGroup(g, expr) {
			out = append(out, g)
		}
	}
	return out, nil
}

// replaceGroup is SCIM PUT (RFC 7644 §3.5.1): a full overwrite. It sets
// displayName and reconciles membership to EXACTLY the body's members[]
// (diff add/remove against the current set), 404 on an unknown group, and
// rejects a body id that disagrees with the path (id is read-only).
func (h *Handler) replaceGroup(w http.ResponseWriter, r *http.Request, id string) {
	role, found, err := h.groups.findRole(r.Context(), id)
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	if !found {
		h.writeError(w, newError(http.StatusNotFound, "", "group not found"))
		return
	}
	if err := h.checkGroupIfMatch(r, role, id); err != nil {
		h.writeError(w, *err)
		return
	}
	g, ok := h.decodeGroup(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(g.DisplayName) == "" {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidValue, "displayName is required"))
		return
	}
	if g.ID != "" && g.ID != id {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeMutability, "id is immutable"))
		return
	}

	role.Name = g.DisplayName
	if err := h.groups.perms.UpdateRole(r.Context(), h.groups.clientID, role); err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	desired := g.memberValues()
	if err := h.reconcileMembers(r.Context(), id, desired); err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	h.auditGroup(r, audit.EventAdminRoleUpdated, id)
	h.writeGroupResource(w, http.StatusOK, roleToGroup(role, desired, h.groupLocation(id)))
}

// patchGroup applies a SCIM PATCH (RFC 7644 §3.5.2) to a group:
// displayName replace and members add/replace/remove. Members are the
// path Azure AD / Okta use to push group-membership deltas one operation
// at a time. PATCH is all-or-nothing: a failing op aborts before any
// membership write.
func (h *Handler) patchGroup(w http.ResponseWriter, r *http.Request, id string) {
	role, found, err := h.groups.findRole(r.Context(), id)
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	if !found {
		h.writeError(w, newError(http.StatusNotFound, "", "group not found"))
		return
	}
	if err := h.checkGroupIfMatch(r, role, id); err != nil {
		h.writeError(w, *err)
		return
	}
	ops, ok := h.decodePatch(w, r)
	if !ok {
		return
	}

	// Validate every op BEFORE mutating, so a malformed later op can't leave
	// a half-applied membership change behind (the permissions SPI has no
	// rollback). The plan holds the membership mutations to run only once the
	// whole op list type-checks.
	newName, nameChanged, plan, e, ok := planGroupPatch(role.Name, ops)
	if !ok {
		h.writeError(w, e)
		return
	}

	if nameChanged {
		role.Name = newName
		if err := h.groups.perms.UpdateRole(r.Context(), h.groups.clientID, role); err != nil {
			h.writeError(w, h.storageError(err))
			return
		}
	}
	if e := h.runMemberPlan(r.Context(), id, plan); e != nil {
		h.writeError(w, *e)
		return
	}

	members, err := h.groups.members(r.Context(), id)
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	h.auditGroup(r, audit.EventAdminRoleUpdated, id)
	h.writeGroupResource(w, http.StatusOK, roleToGroup(role, members, h.groupLocation(id)))
}

// planGroupPatch validates the full PATCH op list against the group schema
// WITHOUT touching the store, returning the resulting displayName (and whether
// it changed) plus the deferred membership mutations. ok=false carries the
// SCIM error from the first invalid op.
func planGroupPatch(currentName string, ops []PatchOperation) (newName string, nameChanged bool, plan []groupMemberMutation, e ErrorResponse, ok bool) {
	newName = currentName
	for _, op := range ops {
		oe, mut, nameSet, name, opOK := planGroupOp(op)
		if !opOK {
			return "", false, nil, oe, false
		}
		if nameSet {
			newName = name
			nameChanged = true
		}
		plan = append(plan, mut...)
	}
	return newName, nameChanged, plan, ErrorResponse{}, true
}

// runMemberPlan executes the deferred membership mutations in order, stopping
// at the first store error.
func (h *Handler) runMemberPlan(ctx context.Context, id string, plan []groupMemberMutation) *ErrorResponse {
	for _, m := range plan {
		if e := h.runMemberMutation(ctx, id, m); e != nil {
			return e
		}
	}
	return nil
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request, id string) {
	// An If-Match on DELETE requires loading the current version first; with
	// no precondition header this stays a single RemoveRole (RFC 7644 §3.14).
	if strings.TrimSpace(r.Header.Get(headerIfMatch)) != "" {
		role, found, err := h.groups.findRole(r.Context(), id)
		if err != nil {
			h.writeError(w, h.storageError(err))
			return
		}
		if !found {
			h.writeError(w, newError(http.StatusNotFound, "", "group not found"))
			return
		}
		if perr := h.checkGroupIfMatch(r, role, id); perr != nil {
			h.writeError(w, *perr)
			return
		}
	}
	if err := h.groups.perms.RemoveRole(r.Context(), h.groups.clientID, id); err != nil {
		if errors.Is(err, permissions.ErrRoleNotFound) {
			h.writeError(w, newError(http.StatusNotFound, "", "group not found"))
			return
		}
		h.writeError(w, h.storageError(err))
		return
	}
	h.auditGroup(r, audit.EventAdminRoleRemoved, id)
	w.WriteHeader(http.StatusNoContent)
}

// checkGroupIfMatch enforces an If-Match precondition on a group write
// (RFC 7644 §3.14). It resolves the group's current membership to compute
// the same version a GET returns, then compares against the header. A nil
// return means proceed; a non-nil pointer carries the SCIM error to write.
func (h *Handler) checkGroupIfMatch(r *http.Request, role permissions.Role, id string) *ErrorResponse {
	if strings.TrimSpace(r.Header.Get(headerIfMatch)) == "" {
		return nil
	}
	members, err := h.groups.members(r.Context(), id)
	if err != nil {
		e := h.storageError(err)
		return &e
	}
	if !ifMatchSatisfied(r, currentGroupVersion(role, members, h.groupLocation(id))) {
		e := preconditionFailed()
		return &e
	}
	return nil
}

// reconcileMembers drives the current membership of roleCode to exactly
// desired: add the missing, remove the extra. Used by PUT and by a
// members "replace" PATCH op.
func (h *Handler) reconcileMembers(ctx context.Context, roleCode string, desired []string) error {
	current, err := h.groups.members(ctx, roleCode)
	if err != nil {
		return err
	}
	want := make(map[string]struct{}, len(desired))
	for _, v := range desired {
		want[v] = struct{}{}
	}
	have := make(map[string]struct{}, len(current))
	for _, v := range current {
		have[v] = struct{}{}
	}
	for v := range want {
		if _, ok := have[v]; !ok {
			if err := h.groups.addMember(ctx, v, roleCode); err != nil {
				return err
			}
		}
	}
	for v := range have {
		if _, ok := want[v]; !ok {
			if err := h.groups.removeMember(ctx, v, roleCode); err != nil {
				return err
			}
		}
	}
	return nil
}

// decodeGroup reads and validates a SCIM Group request body. On failure
// it writes the SCIM error and returns ok=false.
func (h *Handler) decodeGroup(w http.ResponseWriter, r *http.Request) (GroupResource, bool) {
	var g GroupResource
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		h.writeError(w, newError(http.StatusBadRequest, scimTypeInvalidSyntax, "request body is not valid SCIM JSON"))
		return GroupResource{}, false
	}
	return g, true
}

// auditGroup emits the reused admin role event for a group mutation,
// stamping the group id as the subject and the admin actor when present.
func (h *Handler) auditGroup(r *http.Request, typ audit.EventType, groupID string) {
	if h.recorder == nil {
		return
	}
	e := &audit.Event{Type: typ, Outcome: audit.OutcomeSuccess, Timestamp: h.now()}
	if actor, clientID, ok := actorFromContext(r.Context()); ok {
		e.ActorID = actor
		e.ClientID = clientID
	}
	audit.SetMeta(e, "subject", groupID)
	audit.SetMeta(e, "via", "scim")
	h.recorder.Record(context.Background(), e)
}
