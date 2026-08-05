package scim

import (
	"errors"
	"strings"
	"testing"
)

// mustParse parses a filter that is expected to be valid.
func mustParse(t *testing.T, raw string) filterExpr {
	t.Helper()
	expr, err := parseFilter(raw)
	if err != nil {
		t.Fatalf("parseFilter(%q) unexpected error: %v", raw, err)
	}
	return expr
}

// sampleUser is a fixed User resource the evaluator tests match filters
// against. It exercises every modeled attribute family: a single-valued
// string (userName/displayName/externalId), a boolean (active), a complex
// name with sub-attributes, and a multi-valued emails array with mixed
// types/primary flags.
func sampleUser() Resource {
	return Resource{
		Schemas:     []string{SchemaUser},
		ID:          "id-1",
		UserName:    "Alice@Example.com",
		DisplayName: "Alice Smith",
		ExternalID:  "ext-42",
		Active:      true,
		Name: &Name{
			GivenName:  "Alice",
			FamilyName: "Smith",
			Formatted:  "Alice Smith",
		},
		Emails: []Email{
			{Value: "alice@example.com", Type: "work", Primary: true},
			{Value: "alice@home.example", Type: "home"},
		},
	}
}

// TestFilterComparisonOperators exercises each comparison operator against
// the sample user, covering both the matching and non-matching case so a
// regression in either direction is caught.
func TestFilterComparisonOperators(t *testing.T) {
	t.Parallel()
	u := sampleUser()
	cases := []struct {
		name   string
		filter string
		want   bool
	}{
		// eq is case-insensitive for non-caseExact strings (RFC 7644
		// §3.4.2.2): the stored "Alice@Example.com" matches a lower-cased
		// literal.
		{"eq case-insensitive match", `userName eq "alice@example.com"`, true},
		{"eq exact match", `userName eq "Alice@Example.com"`, true},
		{"eq no match", `userName eq "bob@example.com"`, false},
		// ne is the inverse of eq.
		{"ne true", `userName ne "bob@example.com"`, true},
		{"ne false", `userName ne "alice@example.com"`, false},
		// co/sw/ew substring family, case-insensitive.
		{"co match", `displayName co "smith"`, true},
		{"co no match", `displayName co "jones"`, false},
		{"sw match", `userName sw "alice"`, true},
		{"sw no match", `userName sw "bob"`, false},
		{"ew match", `userName ew ".com"`, true},
		{"ew no match", `userName ew ".org"`, false},
		// pr presence: a set attribute is present, an unset/absent one is not.
		{"pr present", `displayName pr`, true},
		{"pr absent attr", `nickName pr`, false},
		// boolean eq.
		{"active eq true", `active eq true`, true},
		{"active eq false", `active eq false`, false},
		// name sub-attribute addressing.
		{"name.familyName eq", `name.familyName eq "smith"`, true},
		{"name.givenName co", `name.givenName co "lic"`, true},
		// multi-valued emails: matches if ANY value matches.
		{"emails eq any", `emails eq "alice@home.example"`, true},
		{"emails.type eq", `emails.type eq "home"`, true},
		{"emails.type eq absent type", `emails.type eq "billing"`, false},
		// externalId.
		{"externalId eq", `externalId eq "ext-42"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expr := mustParse(t, tc.filter)
			if got := matchesUser(u, expr); got != tc.want {
				t.Errorf("matchesUser(%q) = %v, want %v", tc.filter, got, tc.want)
			}
		})
	}
}

// TestFilterOrderingOperators covers gt/ge/lt/le over both numeric and
// lexical comparisons.
func TestFilterOrderingOperators(t *testing.T) {
	t.Parallel()
	// A user whose externalId sorts lexically and whose displayName gives
	// a stable ordering anchor.
	u := Resource{UserName: "u", ExternalID: "m", Active: true}
	cases := []struct {
		filter string
		want   bool
	}{
		{`externalId gt "a"`, true},
		{`externalId gt "z"`, false},
		{`externalId ge "m"`, true},
		{`externalId lt "z"`, true},
		{`externalId lt "a"`, false},
		{`externalId le "m"`, true},
	}
	for _, tc := range cases {
		expr := mustParse(t, tc.filter)
		if got := matchesUser(u, expr); got != tc.want {
			t.Errorf("matchesUser(%q) = %v, want %v", tc.filter, got, tc.want)
		}
	}
}

// TestFilterNumericComparison checks that numeric literals compare
// numerically against a numeric-looking attribute value (here meta is not
// numeric, so we use a synthesized resource through the evaluator's number
// path via an attribute that holds a numeric string). externalId holds the
// numeric text to drive the numeric branch of orderCompare/literalEquals.
func TestFilterNumericComparison(t *testing.T) {
	t.Parallel()
	u := Resource{UserName: "u", ExternalID: "10", Active: true}
	if !matchesUser(u, mustParse(t, `externalId gt 9`)) {
		t.Error("10 gt 9 should match numerically")
	}
	if matchesUser(u, mustParse(t, `externalId gt 20`)) {
		t.Error("10 gt 20 should not match")
	}
	// 10 eq 10.0 numerically.
	if !matchesUser(u, mustParse(t, `externalId eq 10.0`)) {
		t.Error("10 eq 10.0 should match numerically")
	}
}

// TestFilterLogicalPrecedence locks the and-binds-tighter-than-or
// precedence (RFC 7644 §3.4.2.2 ABNF) and the effect of explicit grouping.
func TestFilterLogicalPrecedence(t *testing.T) {
	t.Parallel()
	u := sampleUser() // userName Alice, displayName "Alice Smith", active true

	// `userName eq "bob" or displayName co "Alice" and active eq false`
	// parses as `userName eq "bob" or (displayName co "Alice" and active eq
	// false)`. The right conjunction is false (active is true) and the left
	// is false (userName is not bob), so the whole expression is false.
	if matchesUser(u, mustParse(t, `userName eq "bob" or displayName co "Alice" and active eq false`)) {
		t.Error("precedence: or-of-(false, false-conjunction) should be false")
	}
	// Group the or so it binds first: `(userName eq "bob" or displayName co
	// "Alice") and active eq true` — left group true (displayName matches),
	// right true, so the whole is true.
	if !matchesUser(u, mustParse(t, `(userName eq "bob" or displayName co "Alice") and active eq true`)) {
		t.Error("grouping: (true or false) and true should be true")
	}
	// and binds both operands: both true -> true.
	if !matchesUser(u, mustParse(t, `userName sw "Alice" and active eq true`)) {
		t.Error("and of two true should be true")
	}
	// and with one false -> false.
	if matchesUser(u, mustParse(t, `userName sw "Alice" and active eq false`)) {
		t.Error("and with a false operand should be false")
	}
}

// TestFilterNot covers the negation operator, which must wrap a
// parenthesized sub-filter.
func TestFilterNot(t *testing.T) {
	t.Parallel()
	u := sampleUser()
	if !matchesUser(u, mustParse(t, `not (userName eq "bob")`)) {
		t.Error("not (false) should be true")
	}
	if matchesUser(u, mustParse(t, `not (userName eq "alice@example.com")`)) {
		t.Error("not (true) should be false")
	}
	// not combined with and: `active eq true and not (userName eq "bob")`.
	if !matchesUser(u, mustParse(t, `active eq true and not (userName eq "bob")`)) {
		t.Error("true and not(false) should be true")
	}
}

// TestFilterGrouping covers nested parentheses.
func TestFilterGrouping(t *testing.T) {
	t.Parallel()
	u := sampleUser()
	f := `((userName sw "Alice") and (active eq true)) or (externalId eq "nope")`
	if !matchesUser(u, mustParse(t, f)) {
		t.Errorf("nested grouping %q should match", f)
	}
}

// TestFilterUnknownAttribute confirms an unmodeled attribute never matches
// a comparison and is not present, but does NOT error (so a connector
// probing an optional attribute gets an empty result, not a 400).
func TestFilterUnknownAttribute(t *testing.T) {
	t.Parallel()
	u := sampleUser()
	if matchesUser(u, mustParse(t, `costCenter eq "x"`)) {
		t.Error("unknown attribute eq should not match")
	}
	if matchesUser(u, mustParse(t, `costCenter pr`)) {
		t.Error("unknown attribute pr should be false")
	}
	// ne against an absent attribute is true (the resource lacks the value).
	if !matchesUser(u, mustParse(t, `costCenter ne "x"`)) {
		t.Error("unknown attribute ne should be true")
	}
}

// TestFilterPresentEmptyValue confirms a modeled-but-empty attribute fails
// "pr" (RFC 7644 §3.4.2.2: pr requires a non-empty value).
func TestFilterPresentEmptyValue(t *testing.T) {
	t.Parallel()
	u := Resource{UserName: "u", DisplayName: "", Active: true}
	if matchesUser(u, mustParse(t, `displayName pr`)) {
		t.Error("empty displayName must not satisfy pr")
	}
	if !matchesUser(u, mustParse(t, `userName pr`)) {
		t.Error("non-empty userName must satisfy pr")
	}
}

// TestFilterCaseInsensitiveAttrAndKeyword checks that both attribute names
// and operator/logical keywords fold case (RFC 7643 §2.1 / RFC 7644
// §3.4.2.2).
func TestFilterCaseInsensitiveAttrAndKeyword(t *testing.T) {
	t.Parallel()
	u := sampleUser()
	// Upper-cased attribute name + upper-cased operator + upper-cased
	// logical keyword all resolve.
	if !matchesUser(u, mustParse(t, `USERNAME EQ "alice@example.com" AND ACTIVE EQ true`)) {
		t.Error("case-insensitive attr/op/keyword should match")
	}
	if !matchesUser(u, mustParse(t, `userName Eq "alice@example.com" Or userName Eq "x"`)) {
		t.Error("mixed-case keywords should parse and match")
	}
}

// TestFilterStringEscapes confirms the tokenizer honors JSON string
// escapes in a quoted literal.
func TestFilterStringEscapes(t *testing.T) {
	t.Parallel()
	u := Resource{UserName: `quote"inside`, Active: true}
	if !matchesUser(u, mustParse(t, `userName eq "quote\"inside"`)) {
		t.Error("escaped quote literal should match")
	}
	u2 := Resource{DisplayName: "tab\tsep", Active: true}
	if !matchesUser(u2, mustParse(t, `displayName eq "tab\tsep"`)) {
		t.Error("escaped tab literal should match")
	}
}

// TestFilterInvalid enumerates malformed filters that MUST fail with the
// errInvalidFilter sentinel (the handler maps this to scimType
// invalidFilter / HTTP 400).
func TestFilterInvalid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		filter string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"unterminated string", `userName eq "alice`},
		{"dangling operator", `userName eq`},
		{"operator without attribute", `eq "x"`},
		{"unknown operator", `userName xx "y"`},
		{"trailing tokens", `userName eq "a" "b"`},
		{"unbalanced open paren", `(userName eq "a"`},
		{"unbalanced close paren", `userName eq "a")`},
		{"not without paren", `not userName eq "a"`},

		{"co with non-string", `userName co 5`},
		{"sw with bool", `userName sw true`},
		{"bare value", `"alice"`},
		{"double operator", `userName eq eq "a"`},
		{"malformed number", `externalId gt 1.2.3`},
		{"lonely and", `and`},
		{"attribute then close", `userName)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFilter(tc.filter)
			if err == nil {
				t.Fatalf("parseFilter(%q) = nil error, want invalidFilter", tc.filter)
			}
			if !errors.Is(err, errInvalidFilter) {
				t.Errorf("parseFilter(%q) error = %v, want errInvalidFilter", tc.filter, err)
			}
		})
	}
}

// TestFilterGroupAttrs covers the Group resolver: displayName + the
// multi-valued members attribute.
func TestFilterGroupAttrs(t *testing.T) {
	t.Parallel()
	g := GroupResource{
		Schemas:     []string{SchemaGroup},
		ID:          "grp-1",
		DisplayName: "Engineering",
		Members: []GroupMember{
			{Value: "user-1", Type: resourceTypeUser},
			{Value: "user-2", Type: resourceTypeUser},
		},
	}
	cases := []struct {
		filter string
		want   bool
	}{
		{`displayName eq "engineering"`, true},
		{`displayName co "ngin"`, true},
		{`members eq "user-2"`, true},
		{`members eq "user-9"`, false},
		{`members pr`, true},
		{`displayName eq "sales"`, false},
		{`id eq "grp-1"`, true},
	}
	for _, tc := range cases {
		expr := mustParse(t, tc.filter)
		if got := matchesGroup(g, expr); got != tc.want {
			t.Errorf("matchesGroup(%q) = %v, want %v", tc.filter, got, tc.want)
		}
	}
}

// TestFilterDepthAndLengthLimits verifies the two DoS guards: a filter string
// that exceeds maxFilterLen is rejected before tokenizing, and a deeply-nested
// paren expression that exceeds maxFilterDepth is rejected during parsing.
// Neither test sends input that would actually overflow the stack — the guards
// must fire well before that point.
func TestFilterDepthAndLengthLimits(t *testing.T) {
	t.Parallel()
	// Length guard: build a string just over maxFilterLen. Content does not
	// need to be a valid filter — the length check fires first.
	overLen := strings.Repeat("x", maxFilterLen+1)
	_, err := parseFilter(overLen)
	if err == nil {
		t.Fatal("overlong filter: expected errInvalidFilter, got nil")
	}
	if !errors.Is(err, errInvalidFilter) {
		t.Errorf("overlong filter: got %v, want errInvalidFilter", err)
	}

	// Depth guard: build (((…(userName eq "a")…))) with depth = maxFilterDepth+1.
	// The string is well within maxFilterLen; the recursion guard must catch it.
	inner := `userName eq "a"`
	depth := maxFilterDepth + 1
	nested := strings.Repeat("(", depth) + inner + strings.Repeat(")", depth)
	_, err = parseFilter(nested)
	if err == nil {
		t.Fatal("over-depth filter: expected errInvalidFilter, got nil")
	}
	if !errors.Is(err, errInvalidFilter) {
		t.Errorf("over-depth filter: got %v, want errInvalidFilter", err)
	}

	// Boundary: exactly maxFilterDepth levels of nesting must still parse.
	// Builds a filter long enough to need a non-trivial depth but under the cap.
	boundary := strings.Repeat("(", maxFilterDepth) + inner + strings.Repeat(")", maxFilterDepth)
	if len(boundary) <= maxFilterLen {
		_, err = parseFilter(boundary)
		if err != nil {
			t.Errorf("at-limit depth filter: unexpected error: %v", err)
		}
	}
}

// TestFilterEmptyMembersPresence confirms an empty members set fails pr.
func TestFilterEmptyMembersPresence(t *testing.T) {
	t.Parallel()
	g := GroupResource{DisplayName: "Empty"}
	if matchesGroup(g, mustParse(t, `members pr`)) {
		t.Error("group with no members must not satisfy members pr")
	}
}
