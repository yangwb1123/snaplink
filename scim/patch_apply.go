package scim

import (
	"encoding/json"
	"net/http"
	"strings"
)

// applyUserPatch applies an ordered PATCH op list (RFC 7644 §3.5.2) to a
// User Resource in place. The Resource is built from the stored user
// before this runs and written back after, so PATCH reuses the same
// attribute<->core.User mapping as create/replace (single source of
// truth). Ops apply in sequence; the FIRST failing op aborts and returns
// its SCIM error with the rest unapplied (the caller persists nothing on
// error, so PATCH is all-or-nothing from the client's POV).
//
// Supported: op add|replace|remove over a top-level attribute, the
// name.<sub> nested form, and a path-less add/replace whose value is a
// {attr: val} object. Unsupported paths/ops return scimTypeInvalidPath /
// invalidValue rather than silently no-op'ing, so a connector learns the
// limit instead of believing a deprovision took.
func applyUserPatch(res *Resource, ops []PatchOperation) (ErrorResponse, bool) {
	for _, op := range ops {
		if e, ok := applyUserOp(res, op); !ok {
			return e, false
		}
	}
	return ErrorResponse{}, true
}

func applyUserOp(res *Resource, op PatchOperation) (ErrorResponse, bool) {
	verb := op.normalizedOp()
	switch verb {
	case patchOpAdd, patchOpReplace, patchOpRemove:
	default:
		return newError(http.StatusBadRequest, scimTypeInvalidValue, "unsupported PATCH op: "+op.Op), false
	}

	// remove REQUIRES a path (RFC 7644 §3.5.2.2): a remove without a
	// target is a no-target error, not a whole-resource wipe.
	if verb == patchOpRemove && op.Path == "" {
		return newError(http.StatusBadRequest, scimTypeNoTarget, "remove requires a path"), false
	}

	// Path-less add/replace: Value is a {attr: rawValue} object merged
	// into the resource root (RFC 7644 §3.5.2.1/.3 — the common Azure AD
	// "replace {active:false}" deprovision shape).
	if op.Path == "" {
		return applyUserRootMerge(res, op.Value)
	}

	pp, ok := parsePatchPath(op.Path)
	if !ok {
		return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported PATCH path: "+op.Path), false
	}
	return applyUserPathOp(res, verb, pp, op.Value)
}

// applyUserRootMerge handles a path-less add/replace whose value object
// names one or more attributes. Each recognized key is applied; an
// unrecognized key is rejected (scimTypeInvalidPath) so the client isn't
// misled that an unsupported attribute was set.
func applyUserRootMerge(res *Resource, raw json.RawMessage) (ErrorResponse, bool) {
	if len(raw) == 0 {
		return newError(http.StatusBadRequest, scimTypeInvalidValue, "PATCH op missing value"), false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return newError(http.StatusBadRequest, scimTypeInvalidSyntax, "PATCH value is not an object"), false
	}
	for key, v := range obj {
		// "schemas" is a protocol field, not a mutable attribute: some
		// connectors echo it inside the value object, so skip it rather
		// than fail the op as an unsupported path.
		if strings.EqualFold(key, "schemas") {
			continue
		}
		// replace semantics for each named attribute (path-less add over a
		// singular attribute is equivalent to replace per §3.5.2.1).
		if e, ok := applyUserPathOp(res, patchOpReplace, patchPath{attr: strings.ToLower(key)}, v); !ok {
			return e, false
		}
	}
	return ErrorResponse{}, true
}

// applyUserPathOp applies one op to one parsed attribute path.
func applyUserPathOp(res *Resource, verb string, pp patchPath, raw json.RawMessage) (ErrorResponse, bool) {
	switch {
	case pp.isAttr(pathAttrID):
		// id is read-only (RFC 7643 §7 mutability=readOnly): any PATCH that
		// targets it is a mutability violation, not a silent no-op.
		return newError(http.StatusBadRequest, scimTypeMutability, "id is immutable"), false

	case pp.isAttr(pathAttrActive):
		if verb == patchOpRemove {
			// Removing the deprovision flag restores the default (active).
			res.Active = true
			return ErrorResponse{}, true
		}
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "active must be a boolean"), false
		}
		res.Active = b
		return ErrorResponse{}, true

	case pp.isAttr(pathAttrUserName):
		if verb == patchOpRemove {
			// userName is required (RFC 7643 §4.1.1); removing it would
			// leave an unidentifiable user.
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "userName is required and cannot be removed"), false
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "userName must be a string"), false
		}
		res.UserName = s
		return ErrorResponse{}, true

	case pp.isAttr(pathAttrDisplayName):
		if verb == patchOpRemove {
			res.DisplayName = ""
			return ErrorResponse{}, true
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "displayName must be a string"), false
		}
		res.DisplayName = s
		return ErrorResponse{}, true

	case pp.isAttr(pathAttrExternalID):
		if verb == patchOpRemove {
			res.ExternalID = ""
			return ErrorResponse{}, true
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "externalId must be a string"), false
		}
		res.ExternalID = s
		return ErrorResponse{}, true

	case pp.isAttr(pathAttrName):
		return applyUserName(res, verb, pp, raw)

	case pp.isAttr(pathAttrEmails):
		return applyUserEmails(res, verb, raw)
	}
	return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported PATCH path"), false
}

// applyUserName handles the "name" complex attribute and its "name.<sub>"
// sub-attribute form.
func applyUserName(res *Resource, verb string, pp patchPath, raw json.RawMessage) (ErrorResponse, bool) {
	if pp.sub != "" {
		// name.<sub>: set one sub-attribute, allocating name if absent.
		if res.Name == nil {
			res.Name = &Name{}
		}
		var s string
		if verb != patchOpRemove {
			if err := json.Unmarshal(raw, &s); err != nil {
				return newError(http.StatusBadRequest, scimTypeInvalidValue, "name sub-attribute must be a string"), false
			}
		}
		switch pp.sub {
		case subNameFormatted:
			res.Name.Formatted = s
		case subNameFamily:
			res.Name.FamilyName = s
		case subNameGiven:
			res.Name.GivenName = s
		case subNameMiddle:
			res.Name.MiddleName = s
		case subNamePrefix:
			res.Name.HonorificPrefix = s
		case subNameSuffix:
			res.Name.HonorificSuffix = s
		default:
			return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported name sub-attribute"), false
		}
		if res.Name.empty() {
			res.Name = nil
		}
		return ErrorResponse{}, true
	}
	// Whole "name" object.
	if verb == patchOpRemove {
		res.Name = nil
		return ErrorResponse{}, true
	}
	var n Name
	if err := json.Unmarshal(raw, &n); err != nil {
		return newError(http.StatusBadRequest, scimTypeInvalidValue, "name must be an object"), false
	}
	if n.empty() {
		res.Name = nil
	} else {
		res.Name = &n
	}
	return ErrorResponse{}, true
}

// applyUserEmails handles the multi-valued "emails" attribute. add
// appends to the existing set; replace overwrites it; remove (no filter)
// clears it (RFC 7644 §3.5.2.2 — unfiltered multi-valued remove drops all
// values).
func applyUserEmails(res *Resource, verb string, raw json.RawMessage) (ErrorResponse, bool) {
	if verb == patchOpRemove {
		res.Emails = nil
		return ErrorResponse{}, true
	}
	var emails []Email
	if err := json.Unmarshal(raw, &emails); err != nil {
		return newError(http.StatusBadRequest, scimTypeInvalidValue, "emails must be an array"), false
	}
	if verb == patchOpAdd {
		res.Emails = append(res.Emails, emails...)
	} else {
		res.Emails = emails
	}
	return ErrorResponse{}, true
}
