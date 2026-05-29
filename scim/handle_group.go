package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/permissions"
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
	h.writeJSON(w, http.StatusCreated, roleToGroup(role, members, h.groupLocation(id)))
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
	h.writeJSON(w, http.StatusOK, roleToGroup(role, members, h.groupLocation(id)))
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
	total := len(roles)
	lo := startIndex - 1
	if lo > total {
		lo = total
	}
	hi := lo + count
	if hi > total {
		hi = total
	}
	page := roles[lo:hi]

	resources := make([]GroupResource, 0, len(page))
	for _, role := range page {
		members, err := h.groups.members(r.Context(), role.Code)
		if err != nil {
			h.writeError(w, h.storageError(err))
			return
		}
		resources = append(resources, roleToGroup(role, members, h.groupLocation(role.Code)))
	}
	h.writeJSON(w, http.StatusOK, GroupListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(page),
		Resources:    resources,
	})
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
	h.writeJSON(w, http.StatusOK, roleToGroup(role, desired, h.groupLocation(id)))
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
	ops, ok := h.decodePatch(w, r)
	if !ok {
		return
	}

	// Validate every op BEFORE mutating, so a malformed later op can't
	// leave a half-applied membership change behind (the permissions SPI
	// has no rollback). plan holds the membership mutations to run only
	// once the whole op list type-checks.
	newName := role.Name
	nameChanged := false
	var plan []groupMemberMutation
	for _, op := range ops {
		e, mut, nameSet, name, ok := planGroupOp(op)
		if !ok {
			h.writeError(w, e)
			return
		}
		if nameSet {
			newName = name
			nameChanged = true
		}
		plan = append(plan, mut...)
	}

	if nameChanged {
		role.Name = newName
		if err := h.groups.perms.UpdateRole(r.Context(), h.groups.clientID, role); err != nil {
			h.writeError(w, h.storageError(err))
			return
		}
	}
	for _, m := range plan {
		if e := h.runMemberMutation(r.Context(), id, m); e != nil {
			h.writeError(w, *e)
			return
		}
	}

	members, err := h.groups.members(r.Context(), id)
	if err != nil {
		h.writeError(w, h.storageError(err))
		return
	}
	h.auditGroup(r, audit.EventAdminRoleUpdated, id)
	h.writeJSON(w, http.StatusOK, roleToGroup(role, members, h.groupLocation(id)))
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request, id string) {
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

// groupMemberMutation is one planned membership change (add or remove a
// single member) or a full replace of the member set, deferred until the
// whole PATCH op list has been validated.
type groupMemberMutation struct {
	// replace, when true, sets membership to exactly members; otherwise
	// add/remove the single member in member.
	replace bool
	members []string
	member  string
	add     bool
}

// planGroupOp validates one PATCH op against the group schema and returns
// the membership mutations + any displayName change it implies, WITHOUT
// touching the store. ok=false carries the SCIM error to return.
func planGroupOp(op PatchOperation) (e ErrorResponse, muts []groupMemberMutation, nameSet bool, name string, ok bool) {
	verb := op.normalizedOp()
	switch verb {
	case patchOpAdd, patchOpReplace, patchOpRemove:
	default:
		return newError(http.StatusBadRequest, scimTypeInvalidValue, "unsupported PATCH op: "+op.Op), nil, false, "", false
	}
	if verb == patchOpRemove && op.Path == "" {
		return newError(http.StatusBadRequest, scimTypeNoTarget, "remove requires a path"), nil, false, "", false
	}

	// Path-less add/replace: a {displayName: ..., members: [...]} object.
	if op.Path == "" {
		var obj map[string]json.RawMessage
		if len(op.Value) == 0 {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "PATCH op missing value"), nil, false, "", false
		}
		if err := json.Unmarshal(op.Value, &obj); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidSyntax, "PATCH value is not an object"), nil, false, "", false
		}
		for key, v := range obj {
			switch strings.ToLower(key) {
			case strings.ToLower(pathAttrDisplayName):
				var s string
				if err := json.Unmarshal(v, &s); err != nil {
					return newError(http.StatusBadRequest, scimTypeInvalidValue, "displayName must be a string"), nil, false, "", false
				}
				nameSet, name = true, s
			case strings.ToLower(pathAttrMembers):
				vals, ferr := memberValuesFromRaw(v)
				if ferr != nil {
					return *ferr, nil, false, "", false
				}
				muts = append(muts, groupMemberMutation{replace: true, members: vals})
			default:
				return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported PATCH path: "+key), nil, false, "", false
			}
		}
		return ErrorResponse{}, muts, nameSet, name, true
	}

	pp, pok := parsePatchPath(op.Path)
	if !pok {
		return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported PATCH path: "+op.Path), nil, false, "", false
	}
	switch {
	case pp.isAttr(pathAttrDisplayName) && pp.sub == "":
		if verb == patchOpRemove {
			return ErrorResponse{}, nil, true, "", true // clear displayName
		}
		var s string
		if err := json.Unmarshal(op.Value, &s); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "displayName must be a string"), nil, false, "", false
		}
		return ErrorResponse{}, nil, true, s, true

	case pp.isAttr(pathAttrMembers) && pp.sub == "":
		if verb == patchOpRemove {
			// Unfiltered members remove drops the whole set (RFC 7644
			// §3.5.2.2). A filtered remove ("members[value eq ...]") is
			// rejected by parsePatchPath above as an unsupported path.
			return ErrorResponse{}, []groupMemberMutation{{replace: true, members: nil}}, false, "", true
		}
		vals, ferr := memberValuesFromRaw(op.Value)
		if ferr != nil {
			return *ferr, nil, false, "", false
		}
		if verb == patchOpReplace {
			return ErrorResponse{}, []groupMemberMutation{{replace: true, members: vals}}, false, "", true
		}
		// add: append each member individually (idempotent per member).
		for _, v := range vals {
			muts = append(muts, groupMemberMutation{member: v, add: true})
		}
		return ErrorResponse{}, muts, false, "", true
	}
	return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported PATCH path: "+op.Path), nil, false, "", false
}

// memberValuesFromRaw decodes a PATCH members value (an array of member
// objects) into the de-duplicated set of member ids. A malformed value
// returns a SCIM error pointer.
func memberValuesFromRaw(raw json.RawMessage) ([]string, *ErrorResponse) {
	var members []GroupMember
	if err := json.Unmarshal(raw, &members); err != nil {
		e := newError(http.StatusBadRequest, scimTypeInvalidValue, "members must be an array of member objects")
		return nil, &e
	}
	g := GroupResource{Members: members}
	return g.memberValues(), nil
}

// runMemberMutation executes one planned membership mutation.
func (h *Handler) runMemberMutation(ctx context.Context, roleCode string, m groupMemberMutation) *ErrorResponse {
	if m.replace {
		if err := h.reconcileMembers(ctx, roleCode, m.members); err != nil {
			e := h.storageError(err)
			return &e
		}
		return nil
	}
	var err error
	if m.add {
		err = h.groups.addMember(ctx, m.member, roleCode)
	} else {
		err = h.groups.removeMember(ctx, m.member, roleCode)
	}
	if err != nil {
		e := h.storageError(err)
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
