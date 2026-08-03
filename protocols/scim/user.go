package scim

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// Resource is the SCIM 2.0 core User representation (RFC 7643 §4.1). Only
// the attributes this slice implements are modeled; unknown attributes on
// inbound JSON are ignored (RFC 7644 §3.3 permits servers to drop
// attributes they don't support rather than fail). The shape is faithful
// to the wire so off-the-shelf provisioning connectors (Okta, Azure AD,
// OneLogin) interoperate.
type Resource struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId,omitempty"`
	UserName   string   `json:"userName,omitempty"`
	Name       *Name    `json:"name,omitempty"`
	// DisplayName is a free-form label; we back it with core.User.Name.
	DisplayName string  `json:"displayName,omitempty"`
	Emails      []Email `json:"emails,omitempty"`
	// Active defaults to true on create when omitted (RFC 7643 §4.1.1
	// describes active as a deprovisioning flag; absence means active).
	Active bool  `json:"active"`
	Meta   *Meta `json:"meta,omitempty"`

	// EnterpriseExtension carries RFC 7643 §4.1 enterprise User attributes
	// (employeeNumber, costCenter, department, manager, etc.) on INBOUND
	// SCIM JSON. The field's JSON key matches the enterprise schema URN so
	// off-the-shelf provisioning connectors (Okta, Azure AD, OneLogin) that
	// send the enterprise extension in the schemas array auto-populate it.
	// On OUTBOUND (UserToResource) this field is reconstructed from
	// core.User.Attributes under the "scim:" namespace, and the schema URN
	// is appended to Schemas only when at least one enterprise attribute is
	// present.
	EnterpriseExtension *EnterpriseExtension `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
}

// EnterpriseExtension holds the enterprise User attributes defined in
// RFC 7643 §4.1 (Enterprise User Extension). These are the attributes that
// enterprise SCIM provisioning connectors send for HR/org data.
type EnterpriseExtension struct {
	EmployeeNumber string      `json:"employeeNumber,omitempty"`
	CostCenter     string      `json:"costCenter,omitempty"`
	Organization   string      `json:"organization,omitempty"`
	Division       string      `json:"division,omitempty"`
	Department     string      `json:"department,omitempty"`
	Manager        *ManagerRef `json:"manager,omitempty"`
}

// ManagerRef is the enterprise manager reference (RFC 7643 §4.1,
// Enterprise). Value is the manager's user ID (required); displayName is
// a human-readable label (optional, best-effort round-tripped).
type ManagerRef struct {
	Value       string `json:"value"`
	DisplayName string `json:"displayName,omitempty"`
	// Ref is an optional URI reference to the manager's SCIM resource
	// (RFC 7643 §3.1). Best-effort round-tripped when present.
	Ref string `json:"$ref,omitempty"`
}

// empty reports whether no enterprise attribute is set, so PATCH can drop
// an all-empty EnterpriseExtension back to nil instead of rendering an
// empty extension block.
func (e *EnterpriseExtension) empty() bool {
	if e == nil {
		return true
	}
	return e.EmployeeNumber == "" && e.CostCenter == "" && e.Organization == "" &&
		e.Division == "" && e.Department == "" && e.Manager == nil
}

// Name is the SCIM complex "name" attribute (RFC 7643 §4.1.1).
type Name struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

// empty reports whether no name sub-attribute is set (so an all-empty
// Name is dropped from output rather than rendered as "name":{}).
func (n *Name) empty() bool {
	if n == nil {
		return true
	}
	return n.Formatted == "" && n.FamilyName == "" && n.GivenName == "" &&
		n.MiddleName == "" && n.HonorificPrefix == "" && n.HonorificSuffix == ""
}

// Email is one element of the multi-valued "emails" attribute
// (RFC 7643 §4.1.2). Type is typically "work"/"home"; Primary marks the
// preferred address (at most one true per RFC 7643 §2.4).
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Meta is the common resource metadata (RFC 7643 §3.1).
type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
	Version      string `json:"version,omitempty"`
}

// ListResponse is the mandatory envelope for any multi-valued GET
// (RFC 7644 §3.4.2). StartIndex + ItemsPerPage are 1-based per the spec.
type ListResponse struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	StartIndex   int        `json:"startIndex"`
	ItemsPerPage int        `json:"itemsPerPage"`
	Resources    []Resource `json:"Resources"`
}

// primaryEmail returns the value of the primary email, or the first
// email when none is flagged primary, or "" when there are none.
func (r *Resource) primaryEmail() string {
	if len(r.Emails) == 0 {
		return ""
	}
	for _, e := range r.Emails {
		if e.Primary && e.Value != "" {
			return e.Value
		}
	}
	return r.Emails[0].Value
}

// toUser projects a SCIM Resource onto a core.User. id is the storage id
// to assign (the caller mints it on create, or carries it through on
// replace). SCIM-only attributes that core.User has no field for are
// stashed in Attributes under the "scim:" namespace so a later GET
// reconstructs the exact resource. core.User timestamps are managed by
// the caller (create sets both, replace preserves CreatedAt).
func (r *Resource) toUser(id string) *core.User {
	u := &core.User{
		ID:         id,
		ExternalID: r.ExternalID,
		Email:      r.primaryEmail(),
		Username:   r.UserName,
		Attributes: map[string]string{},
	}
	// displayName backs core.User.Name; fall back to the formatted name
	// so a connector that only sends name.formatted still populates it.
	display := r.DisplayName
	if display == "" && r.Name != nil {
		display = r.Name.Formatted
	}
	u.Name = display

	setAttr(u.Attributes, attrUserName, r.UserName)
	// active is always persisted (true/false) so its absence on a later
	// read is unambiguous — an unset active reads back as the create
	// default rather than as "false".
	if r.Active {
		u.Attributes[attrActive] = activeTrue
	} else {
		u.Attributes[attrActive] = activeFalse
	}
	if r.Name != nil {
		setAttr(u.Attributes, attrNameFormatted, r.Name.Formatted)
		setAttr(u.Attributes, attrNameGiven, r.Name.GivenName)
		setAttr(u.Attributes, attrNameFamily, r.Name.FamilyName)
		setAttr(u.Attributes, attrNameMiddle, r.Name.MiddleName)
		setAttr(u.Attributes, attrNamePrefix, r.Name.HonorificPrefix)
		setAttr(u.Attributes, attrNameSuffix, r.Name.HonorificSuffix)
	}
	// Preserve any non-primary emails (type/primary metadata) that the
	// single core.User.Email field can't hold.
	if extra := nonPrimaryEmails(r); len(extra) > 0 {
		if b, err := json.Marshal(extra); err == nil {
			u.Attributes[attrEmailsExtra] = string(b)
		}
	}
	// Enterprise extension attributes (RFC 7643 §4.1). Stored in Attributes
	// under the "scim:" namespace, same pattern as core SCIM fields.
	applyEnterpriseAttrs(u.Attributes, r.EnterpriseExtension)
	if len(u.Attributes) == 0 {
		u.Attributes = nil
	}
	return u
}

// toUserPreserving projects the resource onto a COPY of the EXISTING stored
// user: it overwrites the SCIM-modeled fields (ExternalID/Email/Name and the
// "scim:"-namespaced attribute keys) but carries over every server-managed field
// SCIM does not model — the Provider linkage and all non-"scim:" attributes
// (password_hash / password_hash_format, OIDC claim attributes, ...). RFC 7644
// PATCH (§3.5.2) and PUT must not destroy attributes they did not touch; the
// plain toUser builds a fresh Attributes map and would silently wipe them.
func (r *Resource) toUserPreserving(id string, existing *core.User) *core.User {
	modeled := r.toUser(id) // fresh user: only scim: keys + ExternalID/Email/Name
	merged := map[string]string{}
	for k, v := range existing.Attributes {
		if !strings.HasPrefix(k, scimAttrPrefix) {
			merged[k] = v // preserve server-managed / claim attributes
		}
	}
	for k, v := range modeled.Attributes {
		merged[k] = v // the recomputed scim: keys win
	}
	if len(merged) == 0 {
		merged = nil
	}
	return &core.User{
		ID:         id,
		ExternalID: modeled.ExternalID,
		Provider:   existing.Provider, // server-managed, not SCIM-modeled
		Email:      modeled.Email,
		Username:   modeled.Username,
		Name:       modeled.Name,
		Attributes: merged,
	}
}

// nonPrimaryEmails returns the emails NOT selected as primaryEmail, so
// they can be round-tripped through Attributes. The chosen primary is
// reconstructed from core.User.Email on read.
func nonPrimaryEmails(r *Resource) []Email {
	primary := r.primaryEmail()
	var out []Email
	seenPrimary := false
	for _, e := range r.Emails {
		if !seenPrimary && e.Value == primary {
			seenPrimary = true
			continue
		}
		out = append(out, e)
	}
	return out
}

// UserToResource rebuilds a SCIM Resource from a stored core.User,
// inverting toUser. location is the absolute resource URL stamped into
// meta.location (RFC 7643 §3.1) — pass "" to omit it.
func UserToResource(u *core.User, location string) Resource {
	r := Resource{
		Schemas:     []string{SchemaUser},
		ID:          u.ID,
		ExternalID:  u.ExternalID,
		DisplayName: u.Name,
	}
	attrs := u.Attributes
	r.UserName = storedUserName(u)
	// active defaults to true when the attribute was never persisted
	// (e.g. a user created outside SCIM via the admin API): an
	// account with no explicit deprovision flag is active.
	r.Active = attrs[attrActive] != activeFalse

	n := &Name{
		Formatted:       attrs[attrNameFormatted],
		GivenName:       attrs[attrNameGiven],
		FamilyName:      attrs[attrNameFamily],
		MiddleName:      attrs[attrNameMiddle],
		HonorificPrefix: attrs[attrNamePrefix],
		HonorificSuffix: attrs[attrNameSuffix],
	}
	if !n.empty() {
		r.Name = n
	}

	r.Emails = emailsFromUser(u)

	// Enterprise extension attributes: reconstruct from Attributes
	// when any enterprise field is present. Add the enterprise schema URN
	// to Schemas so enterprise SCIM connectors (Okta, Azure AD, OneLogin)
	// recognize the resource as supporting the enterprise extension.
	if ext := enterpriseFromUser(u); ext != nil {
		r.EnterpriseExtension = ext
		r.Schemas = append(r.Schemas, SchemaEnterpriseUser)
	}

	r.Meta = &Meta{
		ResourceType: resourceTypeUser,
		Location:     location,
	}
	if !u.CreatedAt.IsZero() {
		r.Meta.Created = u.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !u.UpdatedAt.IsZero() {
		r.Meta.LastModified = u.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return r
}

func storedUserName(u *core.User) string {
	if u.Username != "" {
		return u.Username
	}
	return u.Attributes[attrUserName]
}

// emailsFromUser reconstructs the emails array: the primary from
// core.User.Email, then any non-primary emails stashed in Attributes.
func emailsFromUser(u *core.User) []Email {
	var emails []Email
	if u.Email != "" {
		emails = append(emails, Email{Value: u.Email, Primary: true, Type: "work"})
	}
	if raw := u.Attributes[attrEmailsExtra]; raw != "" {
		var extra []Email
		if err := json.Unmarshal([]byte(raw), &extra); err == nil {
			emails = append(emails, extra...)
		}
	}
	return emails
}

// applyEnterpriseAttrs writes enterprise extension attributes into attrs.
// Helper extracted to keep toUser under the 50-line budget.
func applyEnterpriseAttrs(attrs map[string]string, ext *EnterpriseExtension) {
	if ext == nil {
		return
	}
	setAttr(attrs, attrEmployeeNumber, ext.EmployeeNumber)
	setAttr(attrs, attrCostCenter, ext.CostCenter)
	setAttr(attrs, attrOrganization, ext.Organization)
	setAttr(attrs, attrDivision, ext.Division)
	setAttr(attrs, attrDepartment, ext.Department)
	if ext.Manager != nil && ext.Manager.Value != "" {
		// Marshal the full ManagerRef so value + displayName + $ref survive
		// the round-trip through core.User.Attributes.
		if b, err := json.Marshal(ext.Manager); err == nil {
			attrs[attrManager] = string(b)
		}
	}
}

// enterpriseFromUser reconstructs the enterprise extension from stored
// core.User.Attributes. Returns nil when no enterprise attribute is present,
// so the SCIM output is clean (no empty enterprise block).
func enterpriseFromUser(u *core.User) *EnterpriseExtension {
	attrs := u.Attributes
	if attrs == nil {
		return nil
	}
	if attrs[attrEmployeeNumber] == "" &&
		attrs[attrCostCenter] == "" &&
		attrs[attrOrganization] == "" &&
		attrs[attrDivision] == "" &&
		attrs[attrDepartment] == "" &&
		attrs[attrManager] == "" {
		return nil
	}
	ext := &EnterpriseExtension{
		EmployeeNumber: attrs[attrEmployeeNumber],
		CostCenter:     attrs[attrCostCenter],
		Organization:   attrs[attrOrganization],
		Division:       attrs[attrDivision],
		Department:     attrs[attrDepartment],
	}
	if raw := attrs[attrManager]; raw != "" {
		var mgr ManagerRef
		if err := json.Unmarshal([]byte(raw), &mgr); err == nil {
			ext.Manager = &mgr
		}
	}
	return ext
}

// setAttr writes k=v only when v is non-empty, keeping Attributes lean.
func setAttr(m map[string]string, k, v string) {
	if strings.TrimSpace(v) != "" {
		m[k] = v
	}
}

// ErrManagerCycle is returned by DetectManagerCycle when a manager
// reference would create a cycle (A → B → A).
var ErrManagerCycle = errors.New("scim: manager cycle detected")

// maxManagerCycleDepth is the maximum number of manager hops DetectManagerCycle
// traverses before giving up.
const maxManagerCycleDepth = 10

// DetectManagerCycle checks whether setting managerID as the manager of
// userID would create a cycle (userID → managerID → ... → userID). It
// walks the manager chain from managerID up to maxManagerCycleDepth hops,
// using getManager to resolve each node's manager. Returns ErrManagerCycle
// when a cycle is detected, nil otherwise.
//
// getManager retrieves the manager ID for a given userID, called at most
// maxManagerCycleDepth times. Errors from getManager are propagated as-is.
func DetectManagerCycle(ctx context.Context, userID, managerID string,
	getManager func(ctx context.Context, userID string) (string, error),
) error {
	if managerID == "" || userID == "" {
		return nil
	}
	if userID == managerID {
		return ErrManagerCycle
	}
	visited := map[string]bool{userID: true}
	current := managerID
	for depth := 0; depth < maxManagerCycleDepth; depth++ {
		if visited[current] {
			return ErrManagerCycle
		}
		visited[current] = true
		next, err := getManager(ctx, current)
		if err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		current = next
	}
	return nil
}
