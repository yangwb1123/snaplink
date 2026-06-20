package scim

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/core"
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
	if len(u.Attributes) == 0 {
		u.Attributes = nil
	}
	return u
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

// userToResource rebuilds a SCIM Resource from a stored core.User,
// inverting toUser. location is the absolute resource URL stamped into
// meta.location (RFC 7643 §3.1) — pass "" to omit it.
func userToResource(u *core.User, location string) Resource {
	r := Resource{
		Schemas:     []string{SchemaUser},
		ID:          u.ID,
		ExternalID:  u.ExternalID,
		DisplayName: u.Name,
	}
	attrs := u.Attributes
	r.UserName = attrs[attrUserName]
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

// setAttr writes k=v only when v is non-empty, keeping Attributes lean.
func setAttr(m map[string]string, k, v string) {
	if strings.TrimSpace(v) != "" {
		m[k] = v
	}
}
