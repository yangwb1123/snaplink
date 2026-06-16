package scim

import "testing"

// These tests exercise the attribute-projection paths in filter_eval.go that
// the existing filter tests don't reach: the meta.* sub-attributes, the
// emails.type / emails.primary multi-valued sub-attribute forms, and the
// members.display / members.type group projections. They evaluate real
// filters against real resources (no mocks) so a regression in any projector
// is caught at the filter layer it powers.

// sampleUserWithMeta returns a user carrying meta.* values so a filter naming
// meta.resourceType / meta.location resolves rather than reading as absent.
func sampleUserWithMeta() Resource {
	r := sampleUser()
	r.Meta = &Meta{
		ResourceType: resourceTypeUser,
		Created:      "2026-05-29T12:00:00Z",
		LastModified: "2026-05-29T12:00:00Z",
		Location:     "/api/v1/scim/v2/Users/id-1",
	}
	return r
}

// TestFilterUserMetaFields exercises metaField via filters over meta.*.
func TestFilterUserMetaFields(t *testing.T) {
	u := sampleUserWithMeta()
	cases := []struct {
		filter string
		want   bool
	}{
		{`meta.resourceType eq "User"`, true},
		{`meta.resourceType eq "Group"`, false},
		{`meta.resourceType pr`, true},
		{`meta.location co "Users/id-1"`, true},
		{`meta.created pr`, true},
		{`meta.lastModified pr`, true},
	}
	for _, tc := range cases {
		if got := matchesUser(u, mustParse(t, tc.filter)); got != tc.want {
			t.Errorf("matchesUser(%q) = %v, want %v", tc.filter, got, tc.want)
		}
	}
}

// TestFilterUserMetaAbsent: a user with no meta resolves every meta.* path as
// absent (metaField's nil-meta branch), so pr is false and eq never matches.
func TestFilterUserMetaAbsent(t *testing.T) {
	u := sampleUser() // no Meta set
	if matchesUser(u, mustParse(t, `meta.resourceType pr`)) {
		t.Error("meta.resourceType pr matched a user with no meta")
	}
	if matchesUser(u, mustParse(t, `meta.location eq "x"`)) {
		t.Error("meta.location eq matched a user with no meta")
	}
}

// TestFilterEmailSubAttributes exercises emails.type (emailTypes) and
// emails.primary (emailPrimaries) — the multi-valued sub-attribute projectors.
func TestFilterEmailSubAttributes(t *testing.T) {
	u := sampleUser() // work(primary) + home
	cases := []struct {
		filter string
		want   bool
	}{
		{`emails.type eq "work"`, true},
		{`emails.type eq "home"`, true},
		{`emails.type eq "other"`, false},
		// primary is multi-valued: one true (work) + one false (home), so both
		// literals match SOME element.
		{`emails.primary eq true`, true},
		{`emails.primary eq false`, true},
		{`emails.value co "home.example"`, true},
		{`emails.type pr`, true},
	}
	for _, tc := range cases {
		if got := matchesUser(u, mustParse(t, tc.filter)); got != tc.want {
			t.Errorf("matchesUser(%q) = %v, want %v", tc.filter, got, tc.want)
		}
	}
}

// TestFilterEmailSubAttributesNoEmails: a user with no emails resolves every
// emails.* path as absent, so pr is false.
func TestFilterEmailSubAttributesNoEmails(t *testing.T) {
	u := sampleUser()
	u.Emails = nil
	for _, f := range []string{`emails.type pr`, `emails.primary pr`, `emails.value pr`} {
		if matchesUser(u, mustParse(t, f)) {
			t.Errorf("%q matched a user with no emails", f)
		}
	}
}

// TestFilterGroupMemberSubAttributes exercises members.display
// (memberDisplaySet) and members.type (memberTypeSet) projectors via filters.
func TestFilterGroupMemberSubAttributes(t *testing.T) {
	g := GroupResource{
		Schemas:     []string{SchemaGroup},
		ID:          "grp-1",
		DisplayName: "Eng",
		Members: []GroupMember{
			{Value: "u1", Type: "User", Display: "User One"},
			{Value: "u2", Type: "User", Display: "User Two"},
		},
		Meta: &Meta{ResourceType: resourceTypeGroup, Location: "/Groups/grp-1"},
	}
	cases := []struct {
		filter string
		want   bool
	}{
		{`members.display eq "User One"`, true},
		{`members.display co "User"`, true},
		{`members.display eq "Nobody"`, false},
		{`members.type eq "User"`, true},
		{`members.type eq "Group"`, false},
		{`members.value eq "u2"`, true},
		{`meta.resourceType eq "Group"`, true},
		{`meta.location pr`, true},
	}
	for _, tc := range cases {
		if got := matchesGroup(g, mustParse(t, tc.filter)); got != tc.want {
			t.Errorf("matchesGroup(%q) = %v, want %v", tc.filter, got, tc.want)
		}
	}
}

// TestFilterGroupMemberSubAttributesEmpty: an empty-member group resolves the
// member.* sub-attribute paths as absent.
func TestFilterGroupMemberSubAttributesEmpty(t *testing.T) {
	g := GroupResource{Schemas: []string{SchemaGroup}, ID: "g", DisplayName: "Empty"}
	for _, f := range []string{`members.display pr`, `members.type pr`, `members.value pr`} {
		if matchesGroup(g, mustParse(t, f)) {
			t.Errorf("%q matched an empty group", f)
		}
	}
}

// TestFilterNameSubAbsent exercises nameSub's "name present but sub empty" and
// "name nil" branches: a name with only GivenName set leaves familyName etc.
// resolving as absent.
func TestFilterNameSubAbsent(t *testing.T) {
	u := sampleUser()
	u.Name = &Name{GivenName: "Alice"} // familyName/formatted unset
	if matchesUser(u, mustParse(t, `name.familyName pr`)) {
		t.Error("name.familyName pr matched when familyName unset")
	}
	if !matchesUser(u, mustParse(t, `name.givenName pr`)) {
		t.Error("name.givenName pr should match when set")
	}
	// honorific sub-attributes resolve through nameSub too.
	if matchesUser(u, mustParse(t, `name.honorificPrefix pr`)) {
		t.Error("name.honorificPrefix pr matched when unset")
	}

	// A nil name resolves every name.<sub> as absent (nameSub nil branch).
	u.Name = nil
	if matchesUser(u, mustParse(t, `name.givenName pr`)) {
		t.Error("name.givenName pr matched a nil name")
	}
	if matchesUser(u, mustParse(t, `name pr`)) {
		t.Error("name pr matched a nil name")
	}
}

// TestFilterIDAttribute exercises the id projector path on both resources.
func TestFilterIDAttribute(t *testing.T) {
	if !matchesUser(sampleUser(), mustParse(t, `id eq "id-1"`)) {
		t.Error("user id eq did not match")
	}
	g := GroupResource{Schemas: []string{SchemaGroup}, ID: "grp-9", DisplayName: "G"}
	if !matchesGroup(g, mustParse(t, `id eq "grp-9"`)) {
		t.Error("group id eq did not match")
	}
}
