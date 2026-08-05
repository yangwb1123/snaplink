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
		return applyUserActive(res, verb, raw)

	case pp.isAttr(pathAttrUserName):
		if verb == patchOpRemove {
			// userName is required (RFC 7643 §4.1.1); removing it would
			// leave an unidentifiable user.
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "userName is required and cannot be removed"), false
		}
		return setUserStringAttr(&res.UserName, verb, raw, "userName")

	case pp.isAttr(pathAttrDisplayName):
		return setUserStringAttr(&res.DisplayName, verb, raw, "displayName")

	case pp.isAttr(pathAttrExternalID):
		return setUserStringAttr(&res.ExternalID, verb, raw, "externalId")

	case pp.isAttr(pathAttrName):
		return applyUserName(res, verb, pp, raw)

	case pp.isAttr(pathAttrEmails):
		if pp.filter != nil {
			return applyUserEmailsFiltered(res, verb, pp, raw)
		}
		return applyUserEmails(res, verb, raw)

	case pp.isAttr(pathAttrEmployeeNumber), pp.isAttr(pathAttrCostCenter),
		pp.isAttr(pathAttrOrganization), pp.isAttr(pathAttrDivision), pp.isAttr(pathAttrDepartment):
		return applyEnterpriseStringAttr(res, verb, pp.attr, raw)

	case pp.isAttr(pathAttrManager):
		return applyEnterpriseManager(res, verb, raw)
	}
	return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported PATCH path"), false
}

// applyEnterpriseStringAttr sets/clears one simple enterprise-extension
// string attribute (RFC 7643 §4.1, Enterprise), allocating
// EnterpriseExtension lazily and dropping it back to nil once every field
// in it is left empty by the update.
func applyEnterpriseStringAttr(res *Resource, verb, attr string, raw json.RawMessage) (ErrorResponse, bool) {
	if res.EnterpriseExtension == nil {
		res.EnterpriseExtension = &EnterpriseExtension{}
	}
	dst := enterpriseStringField(res.EnterpriseExtension, attr)
	if verb == patchOpRemove {
		*dst = ""
	} else if err := json.Unmarshal(raw, dst); err != nil {
		return newError(http.StatusBadRequest, scimTypeInvalidValue, attr+" must be a string"), false
	}
	if res.EnterpriseExtension.empty() {
		res.EnterpriseExtension = nil
	}
	return ErrorResponse{}, true
}

// enterpriseStringField returns a pointer to the EnterpriseExtension field
// addressed by attr (already validated against a matching isAttr case, so
// the switch is exhaustive here).
func enterpriseStringField(e *EnterpriseExtension, attr string) *string {
	switch {
	case strings.EqualFold(attr, pathAttrEmployeeNumber):
		return &e.EmployeeNumber
	case strings.EqualFold(attr, pathAttrCostCenter):
		return &e.CostCenter
	case strings.EqualFold(attr, pathAttrOrganization):
		return &e.Organization
	case strings.EqualFold(attr, pathAttrDivision):
		return &e.Division
	default:
		return &e.Department
	}
}

// applyEnterpriseManager handles the "manager" complex attribute (RFC 7643
// §4.1, Enterprise): remove clears the reference; add/replace assign the
// whole {value, displayName, $ref} object. This only shapes the value onto
// the resource -- the manager-cycle check runs later, over the fully
// assembled Resource, in validateManagerRef.
func applyEnterpriseManager(res *Resource, verb string, raw json.RawMessage) (ErrorResponse, bool) {
	if res.EnterpriseExtension == nil {
		res.EnterpriseExtension = &EnterpriseExtension{}
	}
	if verb == patchOpRemove {
		res.EnterpriseExtension.Manager = nil
	} else {
		var m ManagerRef
		if err := json.Unmarshal(raw, &m); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "manager must be an object"), false
		}
		if m.Value == "" {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "manager.value is required"), false
		}
		res.EnterpriseExtension.Manager = &m
	}
	if res.EnterpriseExtension.empty() {
		res.EnterpriseExtension = nil
	}
	return ErrorResponse{}, true
}

// applyUserActive sets/clears the "active" deprovision flag. remove restores
// the default (active=true, RFC 7643 §4.1.1).
func applyUserActive(res *Resource, verb string, raw json.RawMessage) (ErrorResponse, bool) {
	if verb == patchOpRemove {
		res.Active = true
		return ErrorResponse{}, true
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return newError(http.StatusBadRequest, scimTypeInvalidValue, "active must be a boolean"), false
	}
	res.Active = b
	return ErrorResponse{}, true
}

// setUserStringAttr sets/clears a singular string attribute of the resource.
// remove clears it; add/replace assign the JSON string value. label names the
// attribute in the type-mismatch error.
func setUserStringAttr(dst *string, verb string, raw json.RawMessage, label string) (ErrorResponse, bool) {
	if verb == patchOpRemove {
		*dst = ""
		return ErrorResponse{}, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return newError(http.StatusBadRequest, scimTypeInvalidValue, label+" must be a string"), false
	}
	*dst = s
	return ErrorResponse{}, true
}

// applyUserName handles the "name" complex attribute and its "name.<sub>"
// sub-attribute form.
func applyUserName(res *Resource, verb string, pp patchPath, raw json.RawMessage) (ErrorResponse, bool) {
	if pp.sub != "" {
		return applyUserNameSub(res, verb, pp.sub, raw)
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

// applyUserNameSub sets one "name.<sub>" sub-attribute, allocating name if
// absent and dropping it back to nil when the op leaves every sub empty.
func applyUserNameSub(res *Resource, verb, sub string, raw json.RawMessage) (ErrorResponse, bool) {
	if res.Name == nil {
		res.Name = &Name{}
	}
	var s string
	if verb != patchOpRemove {
		if err := json.Unmarshal(raw, &s); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "name sub-attribute must be a string"), false
		}
	}
	dst := nameSubField(res.Name, sub)
	if dst == nil {
		return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported name sub-attribute"), false
	}
	*dst = s
	if res.Name.empty() {
		res.Name = nil
	}
	return ErrorResponse{}, true
}

// nameSubField returns a pointer to the Name field addressed by sub, or nil
// for an unknown sub-attribute.
func nameSubField(n *Name, sub string) *string {
	switch sub {
	case subNameFormatted:
		return &n.Formatted
	case subNameFamily:
		return &n.FamilyName
	case subNameGiven:
		return &n.GivenName
	case subNameMiddle:
		return &n.MiddleName
	case subNamePrefix:
		return &n.HonorificPrefix
	case subNameSuffix:
		return &n.HonorificSuffix
	}
	return nil
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

// applyUserEmailsFiltered applies a value-path PATCH op to the emails
// element(s) matching the path's value filter (RFC 7644 §3.5.2 —
// "emails[type eq \"work\"].value"). The filter is evaluated against each
// element; the op then acts on the matches:
//   - remove (no sub): drop the matching elements.
//   - remove (sub): clear that sub-attribute on the matching elements.
//   - add/replace (sub): set that sub-attribute on the matching elements.
//   - add/replace (no sub): overwrite the matching elements with the value
//     object (the value is a single email object).
//
// A filter that matches no element is a noTarget error (RFC 7644 §3.5.2.3 /
// Table 9): the client targeted an element that does not exist, which it
// should learn rather than believe the op took.
func applyUserEmailsFiltered(res *Resource, verb string, pp patchPath, raw json.RawMessage) (ErrorResponse, bool) {
	matched := false
	for i := range res.Emails {
		if !pp.filter.match(attrView{resolve: emailElementAttrs(res.Emails[i])}) {
			continue
		}
		matched = true
		if e, ok := applyEmailElementOp(&res.Emails[i], verb, pp.sub, raw); !ok {
			return e, false
		}
	}
	if verb == patchOpRemove && pp.sub == "" {
		// Element-level remove: filter out the matched elements after the scan
		// (mutating the slice mid-range would skip elements).
		kept := res.Emails[:0]
		for _, e := range res.Emails {
			if !pp.filter.match(attrView{resolve: emailElementAttrs(e)}) {
				kept = append(kept, e)
			}
		}
		res.Emails = kept
	}
	if !matched {
		return newError(http.StatusBadRequest, scimTypeNoTarget, "no emails element matches the value filter"), false
	}
	return ErrorResponse{}, true
}

// applyEmailElementOp applies one op to a single matched email element. sub
// is the lower-cased sub-attribute after the value filter (value|type|
// primary), or "" to act on the whole element. The element-level remove is
// handled by the caller (it drops the element entirely), so a remove reaching
// here always carries a sub.
func applyEmailElementOp(e *Email, verb, sub string, raw json.RawMessage) (ErrorResponse, bool) {
	if sub == "" {
		if verb == patchOpRemove {
			return ErrorResponse{}, true // element drop handled by caller
		}
		// add/replace the whole element with the supplied object.
		var ne Email
		if err := json.Unmarshal(raw, &ne); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "emails element must be an object"), false
		}
		*e = ne
		return ErrorResponse{}, true
	}
	switch sub {
	case "value":
		return setEmailStringSub(&e.Value, verb, raw, "emails value")
	case "type":
		return setEmailStringSub(&e.Type, verb, raw, "emails type")
	case "primary":
		if verb == patchOpRemove {
			e.Primary = false
			return ErrorResponse{}, true
		}
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return newError(http.StatusBadRequest, scimTypeInvalidValue, "emails primary must be a boolean"), false
		}
		e.Primary = b
		return ErrorResponse{}, true
	}
	return newError(http.StatusBadRequest, scimTypeInvalidPath, "unsupported emails sub-attribute"), false
}

// setEmailStringSub sets/clears a string sub-attribute of an email element.
func setEmailStringSub(dst *string, verb string, raw json.RawMessage, label string) (ErrorResponse, bool) {
	if verb == patchOpRemove {
		*dst = ""
		return ErrorResponse{}, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return newError(http.StatusBadRequest, scimTypeInvalidValue, label+" must be a string"), false
	}
	*dst = s
	return ErrorResponse{}, true
}

// emailElementAttrs builds the attrLookup for ONE email element so a
// value-path filter ("type eq \"work\"") evaluates against that element's
// sub-attributes (RFC 7644 §3.5.2: the filter inside [..] addresses the
// multi-valued element's sub-attributes, not the whole resource).
func emailElementAttrs(e Email) attrLookup {
	return func(path string) ([]string, bool) {
		switch path {
		case "value":
			return single(e.Value)
		case "type":
			return single(e.Type)
		case "primary":
			return []string{boolText(e.Primary)}, true
		}
		return nil, false
	}
}
