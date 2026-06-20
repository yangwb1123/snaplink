package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// Group PATCH planning + membership mutation (RFC 7644 §3.5.2). Split from
// handle_group.go to keep each file within the maintainability budget. The
// PATCH handler validates every op into a deferred plan BEFORE touching the
// store (the permissions SPI has no rollback), then runs the plan.

// groupMemberMutation is one planned membership change (add or remove a
// single member), a full replace of the member set, or a filtered remove,
// deferred until the whole PATCH op list has been validated.
type groupMemberMutation struct {
	// replace, when true, sets membership to exactly members; otherwise
	// add/remove the single member in member.
	replace bool
	members []string
	member  string
	add     bool
	// removeFilter, when non-nil, removes every CURRENT member whose value
	// (the member id) satisfies the value-path filter (RFC 7644 §3.5.2
	// "members[value eq \"x\"]"). Resolved against live membership at apply
	// time because planGroupOp runs without the store.
	removeFilter filterExpr
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
		return planGroupRootMerge(op.Value)
	}

	pp, pok := parsePatchPath(op.Path)
	if !pok {
		return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported PATCH path: "+op.Path), nil, false, "", false
	}
	return planGroupPathOp(verb, pp, op.Value, op.Path)
}

// planGroupRootMerge validates a path-less add/replace whose value is a
// {displayName: ..., members: [...]} object, returning the implied
// displayName change and membership replace.
func planGroupRootMerge(value json.RawMessage) (e ErrorResponse, muts []groupMemberMutation, nameSet bool, name string, ok bool) {
	var obj map[string]json.RawMessage
	if len(value) == 0 {
		return newError(http.StatusBadRequest, scimTypeInvalidValue, "PATCH op missing value"), nil, false, "", false
	}
	if err := json.Unmarshal(value, &obj); err != nil {
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

// planGroupPathOp validates a targeted (path-bearing) group PATCH op against
// the displayName or members attribute. rawPath is the original op.Path, kept
// only for the unsupported-path error detail.
func planGroupPathOp(verb string, pp patchPath, value json.RawMessage, rawPath string) (e ErrorResponse, muts []groupMemberMutation, nameSet bool, name string, ok bool) {
	switch {
	case pp.isAttr(pathAttrDisplayName) && pp.sub == "":
		if verb == patchOpRemove {
			return ErrorResponse{}, nil, true, "", true // clear displayName
		}
		var s string
		if err := json.Unmarshal(value, &s); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "displayName must be a string"), nil, false, "", false
		}
		return ErrorResponse{}, nil, true, s, true

	case pp.isAttr(pathAttrMembers) && pp.filter != nil:
		return planGroupMembersFiltered(verb, pp)

	case pp.isAttr(pathAttrMembers) && pp.sub == "":
		return planGroupMembers(verb, value)
	}
	return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported PATCH path: "+rawPath), nil, false, "", false
}

// planGroupMembersFiltered validates a value-path members op (RFC 7644 §3.5.2
// — "members[value eq \"<id>\"]"): the connector targets member(s) by a value
// filter, the per-member delta Azure AD / Okta send. Only remove is meaningful
// on a member element (a member ref is immutable per RFC 7643 §4.2 — added or
// removed, never edited in place), so add/replace on a filtered member path is
// rejected. The filter is resolved against the CURRENT membership at apply time
// (planGroupOp has no membership), so an arbitrary value filter — not just a
// literal id — works.
func planGroupMembersFiltered(verb string, pp patchPath) (e ErrorResponse, muts []groupMemberMutation, nameSet bool, name string, ok bool) {
	if verb != patchOpRemove {
		return newError(http.StatusBadRequest, scimTypeInvalidPath, "members value-path supports remove only"), nil, false, "", false
	}
	return ErrorResponse{}, []groupMemberMutation{{removeFilter: pp.filter}}, false, "", true
}

// planGroupMembers validates an unfiltered members add/replace/remove op.
func planGroupMembers(verb string, value json.RawMessage) (e ErrorResponse, muts []groupMemberMutation, nameSet bool, name string, ok bool) {
	if verb == patchOpRemove {
		// Unfiltered members remove drops the whole set (RFC 7644 §3.5.2.2).
		// A filtered remove is handled by the value-path branch.
		return ErrorResponse{}, []groupMemberMutation{{replace: true, members: nil}}, false, "", true
	}
	vals, ferr := memberValuesFromRaw(value)
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
	if m.removeFilter != nil {
		return h.removeMembersMatching(ctx, roleCode, m.removeFilter)
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

// removeMembersMatching removes every current member of roleCode whose id
// satisfies the value-path filter (RFC 7644 §3.5.2). It resolves the live
// membership, evaluates the filter per member (the filter addresses the
// member element's sub-attributes: value/type/display), and removes the
// matches. A filter that matches no current member is a no-op success: PATCH
// member removal is idempotent (Azure AD re-sends removes), so a noTarget
// error here would spuriously fail a retried deprovision.
func (h *Handler) removeMembersMatching(ctx context.Context, roleCode string, filter filterExpr) *ErrorResponse {
	current, err := h.groups.members(ctx, roleCode)
	if err != nil {
		e := h.storageError(err)
		return &e
	}
	for _, id := range current {
		if !filter.match(memberElementAttrs(id)) {
			continue
		}
		if err := h.groups.removeMember(ctx, id, roleCode); err != nil {
			e := h.storageError(err)
			return &e
		}
	}
	return nil
}

// memberElementAttrs builds the attrLookup for ONE group member so a
// value-path filter ("value eq \"<id>\"") evaluates against that member's
// sub-attributes (RFC 7644 §3.5.2). The membership model carries only the
// member id (value); type is the constant "User" and display is unset, but
// both are exposed so a filter naming them still resolves rather than erroring.
func memberElementAttrs(id string) attrLookup {
	return func(path string) ([]string, bool) {
		switch path {
		case "value":
			return single(id)
		case "type":
			return single(resourceTypeUser)
		}
		return nil, false
	}
}
