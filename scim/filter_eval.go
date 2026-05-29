package scim

import "strings"

// Filter evaluation against SCIM resources (RFC 7644 §3.4.2.2). These
// build the attrLookup the AST nodes in filter.go walk, projecting a
// Resource / GroupResource into the flat, lower-cased attribute view the
// grammar addresses. Only the attributes this slice models are resolvable
// (userName, active, emails, name.*, displayName, members, externalId,
// meta.*); a filter naming any other attribute resolves to "not present",
// so `unknownAttr pr` is false and `unknownAttr eq x` never matches —
// rather than erroring, which would reject otherwise-valid connector
// filters that probe optional attributes.

// matchesUser reports whether res satisfies expr.
func matchesUser(res Resource, expr filterExpr) bool {
	return expr.match(userAttrs(res))
}

// matchesGroup reports whether g satisfies expr.
func matchesGroup(g GroupResource, expr filterExpr) bool {
	return expr.match(groupAttrs(g))
}

// userAttrs returns the attribute resolver for a User Resource. Paths are
// the lower-cased forms the tokenizer produces. Multi-valued emails return
// one entry per address so a comparison matches ANY value (RFC 7644
// §3.4.2.2); the emails.* sub-attribute forms (value/type/primary) are
// resolvable too so `emails.value eq` works alongside the bare `emails eq`.
func userAttrs(res Resource) attrLookup {
	return func(path string) ([]string, bool) {
		switch path {
		case "username":
			return single(res.UserName)
		case "displayname":
			return single(res.DisplayName)
		case "externalid":
			return single(res.ExternalID)
		case "id":
			return single(res.ID)
		case "active":
			// active is always modeled (it defaults true): expose the
			// canonical bool text so `active eq true|false` compares.
			return []string{boolText(res.Active)}, true
		case "emails", "emails.value":
			return emailValues(res.Emails), len(res.Emails) > 0
		case "emails.type":
			return emailTypes(res.Emails), len(res.Emails) > 0
		case "emails.primary":
			return emailPrimaries(res.Emails), len(res.Emails) > 0
		case "name.formatted":
			return nameSub(res.Name, func(n *Name) string { return n.Formatted })
		case "name.familyname":
			return nameSub(res.Name, func(n *Name) string { return n.FamilyName })
		case "name.givenname":
			return nameSub(res.Name, func(n *Name) string { return n.GivenName })
		case "name.middlename":
			return nameSub(res.Name, func(n *Name) string { return n.MiddleName })
		case "name.honorificprefix":
			return nameSub(res.Name, func(n *Name) string { return n.HonorificPrefix })
		case "name.honorificsuffix":
			return nameSub(res.Name, func(n *Name) string { return n.HonorificSuffix })
		case "name":
			// The whole "name" complex attribute is "present" when any
			// sub-attribute is set; comparison against it is undefined in
			// SCIM, so it only meaningfully supports "pr".
			if res.Name.empty() {
				return nil, false
			}
			return []string{res.Name.Formatted}, true
		case "meta.resourcetype":
			return metaField(res.Meta, func(m *Meta) string { return m.ResourceType })
		case "meta.created":
			return metaField(res.Meta, func(m *Meta) string { return m.Created })
		case "meta.lastmodified":
			return metaField(res.Meta, func(m *Meta) string { return m.LastModified })
		case "meta.location":
			return metaField(res.Meta, func(m *Meta) string { return m.Location })
		}
		return nil, false
	}
}

// groupAttrs returns the attribute resolver for a Group Resource. members
// is multi-valued (the member ids); members.value resolves the same set so
// both `members eq x` and `members.value eq x` work.
func groupAttrs(g GroupResource) attrLookup {
	return func(path string) ([]string, bool) {
		switch path {
		case "displayname":
			return single(g.DisplayName)
		case "id":
			return single(g.ID)
		case "members", "members.value":
			return memberValueSet(g.Members), len(g.Members) > 0
		case "members.display":
			return memberDisplaySet(g.Members), len(g.Members) > 0
		case "members.type":
			return memberTypeSet(g.Members), len(g.Members) > 0
		case "meta.resourcetype":
			return metaField(g.Meta, func(m *Meta) string { return m.ResourceType })
		case "meta.location":
			return metaField(g.Meta, func(m *Meta) string { return m.Location })
		}
		return nil, false
	}
}

// single wraps one scalar as a present single-valued attribute. An empty
// string is still "present" (the attribute is modeled) but won't satisfy
// "pr" (presentNode treats empty as absent for presence) — matching the
// SCIM distinction between a modeled-but-empty and an unmodeled attribute.
func single(v string) ([]string, bool) { return []string{v}, true }

// boolText renders a Go bool as the SCIM canonical literal.
func boolText(b bool) string {
	if b {
		return activeTrue
	}
	return activeFalse
}

// nameSub resolves one name sub-attribute via getter, reporting present
// only when name itself is set and the sub-attribute is non-empty.
func nameSub(n *Name, get func(*Name) string) ([]string, bool) {
	if n == nil {
		return nil, false
	}
	v := get(n)
	if v == "" {
		return nil, false
	}
	return []string{v}, true
}

// metaField resolves one meta sub-attribute via getter.
func metaField(m *Meta, get func(*Meta) string) ([]string, bool) {
	if m == nil {
		return nil, false
	}
	v := get(m)
	if v == "" {
		return nil, false
	}
	return []string{v}, true
}

// emailValues / emailTypes / emailPrimaries flatten the multi-valued
// emails attribute into the per-value slices the evaluator matches against.
func emailValues(emails []Email) []string {
	out := make([]string, 0, len(emails))
	for _, e := range emails {
		out = append(out, e.Value)
	}
	return out
}

func emailTypes(emails []Email) []string {
	out := make([]string, 0, len(emails))
	for _, e := range emails {
		out = append(out, e.Type)
	}
	return out
}

func emailPrimaries(emails []Email) []string {
	out := make([]string, 0, len(emails))
	for _, e := range emails {
		out = append(out, boolText(e.Primary))
	}
	return out
}

// memberValueSet / memberDisplaySet / memberTypeSet flatten group members.
func memberValueSet(members []GroupMember) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.Value)
	}
	return out
}

func memberDisplaySet(members []GroupMember) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.Display)
	}
	return out
}

func memberTypeSet(members []GroupMember) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.Type)
	}
	return out
}

// trimFilter normalizes the inbound ?filter= query value. An all-whitespace
// filter is treated as no filter by the caller; this only trims surrounding
// space so a value like " userName eq \"a\" " parses.
func trimFilter(raw string) string { return strings.TrimSpace(raw) }
