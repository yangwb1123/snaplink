package sp

import (
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// These unit tests exercise the SP's INDEPENDENT re-assertion checks directly,
// proving they are real gates (defense-in-depth) and not dead code shadowed by
// crewjam — if a future crewjam default loosened, these would still reject.

func TestAudienceContains(t *testing.T) {
	mk := func(auds ...string) *saml.Assertion {
		a := &saml.Assertion{Conditions: &saml.Conditions{}}
		for _, v := range auds {
			a.Conditions.AudienceRestrictions = append(a.Conditions.AudienceRestrictions,
				saml.AudienceRestriction{Audience: saml.Audience{Value: v}})
		}
		return a
	}
	cases := []struct {
		name string
		a    *saml.Assertion
		want bool
	}{
		{"match", mk("https://sp.example.com"), true},
		{"match_among_many", mk("https://other", "https://sp.example.com"), true},
		{"no_match", mk("https://other"), false},
		{"empty_restrictions", mk(), false},
		{"nil_conditions", &saml.Assertion{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := audienceContains(c.a, "https://sp.example.com"); got != c.want {
				t.Errorf("audienceContains = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRecipientMatches(t *testing.T) {
	mk := func(recips ...string) *saml.Assertion {
		s := &saml.Subject{}
		for _, r := range recips {
			s.SubjectConfirmations = append(s.SubjectConfirmations, saml.SubjectConfirmation{
				SubjectConfirmationData: &saml.SubjectConfirmationData{Recipient: r},
			})
		}
		return &saml.Assertion{Subject: s}
	}
	const acs = "https://sp.example.com/acs"
	cases := []struct {
		name string
		a    *saml.Assertion
		want bool
	}{
		{"match", mk(acs), true},
		{"mismatch", mk("https://evil/acs"), false},
		{"one_mismatch_disqualifies", mk(acs, "https://evil/acs"), false},
		{"no_confirmation", &saml.Assertion{Subject: &saml.Subject{}}, false},
		{"nil_subject", &saml.Assertion{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := recipientMatches(c.a, acs); got != c.want {
				t.Errorf("recipientMatches = %v, want %v", got, c.want)
			}
		})
	}
}

func TestExpired(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	mk := func(condNB, condNOA, scNOA time.Time) *saml.Assertion {
		a := &saml.Assertion{
			Conditions: &saml.Conditions{NotBefore: condNB, NotOnOrAfter: condNOA},
			Subject:    &saml.Subject{},
		}
		if !scNOA.IsZero() {
			a.Subject.SubjectConfirmations = []saml.SubjectConfirmation{{
				SubjectConfirmationData: &saml.SubjectConfirmationData{NotOnOrAfter: scNOA},
			}}
		}
		return a
	}
	cases := []struct {
		name string
		a    *saml.Assertion
		want bool
	}{
		{"valid_window", mk(now.Add(-time.Minute), now.Add(time.Minute), now.Add(time.Minute)), false},
		{"conditions_expired", mk(now.Add(-time.Hour), now.Add(-time.Minute), time.Time{}), true},
		{"conditions_not_yet_valid", mk(now.Add(time.Minute), now.Add(time.Hour), time.Time{}), true},
		{"subjconf_expired", mk(now.Add(-time.Minute), now.Add(time.Hour), now.Add(-time.Second)), true},
		{"exactly_at_notonorafter_is_expired", mk(now.Add(-time.Minute), now, time.Time{}), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := expired(c.a, now); got != c.want {
				t.Errorf("expired = %v, want %v", got, c.want)
			}
		})
	}
}

func TestCountAssertions(t *testing.T) {
	const ns = `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`
	cases := []struct {
		name string
		xml  string
		want int
	}{
		{"one", `<saml:Response ` + ns + `><saml:Assertion/></saml:Response>`, 1},
		{"two", `<saml:Response ` + ns + `><saml:Assertion/><saml:Assertion/></saml:Response>`, 2},
		{"one_encrypted", `<saml:Response ` + ns + `><saml:EncryptedAssertion/></saml:Response>`, 1},
		{"mixed_plain_and_encrypted", `<saml:Response ` + ns + `><saml:Assertion/><saml:EncryptedAssertion/></saml:Response>`, 2},
		{"zero", `<saml:Response ` + ns + `></saml:Response>`, 0},
		{
			// An element named Assertion but in a DIFFERENT namespace must NOT count.
			"wrong_namespace_not_counted",
			`<r:Response xmlns:r="urn:other"><r:Assertion/></r:Response>`,
			0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countAssertions([]byte(c.xml)); got != c.want {
				t.Errorf("countAssertions = %d, want %d", got, c.want)
			}
		})
	}
}

func TestMapAttr(t *testing.T) {
	a := &SPAuthenticator{attrMap: map[string]string{
		"urn:oid:email": "email",
		"DisplayName":   "name", // matched via FriendlyName
	}}
	cases := []struct {
		name string
		attr saml.Attribute
		want string
	}{
		{"mapped_by_name", saml.Attribute{Name: "urn:oid:email"}, "email"},
		{"mapped_by_friendly", saml.Attribute{Name: "urn:oid:2.16.840", FriendlyName: "DisplayName"}, "name"},
		{"passthrough_name", saml.Attribute{Name: "department"}, "department"},
		{"passthrough_friendly_when_no_name", saml.Attribute{FriendlyName: "groups"}, "groups"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := a.mapAttr(c.attr); got != c.want {
				t.Errorf("mapAttr = %q, want %q", got, c.want)
			}
		})
	}

	// Nil map: pure passthrough.
	nilMap := &SPAuthenticator{}
	if got := nilMap.mapAttr(saml.Attribute{Name: "x"}); got != "x" {
		t.Errorf("nil-map mapAttr = %q, want x", got)
	}
}
