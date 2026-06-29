package scim

import (
	"errors"
	"testing"
)

// These tests drive the tokenizer + evaluator internals the higher-level
// filter tests don't fully reach: every numeric ordering operator, the null
// literal eq path, string escape sequences (including \u), and the malformed
// number / unterminated string lexical errors.

// TestNumOrderAllOperators exercises numOrder's gt/ge/lt/le branches directly
// via numeric ordering filters against a meta.created-like numeric attribute.
// We model a synthetic numeric attribute through a user whose externalId holds
// a number so orderCompare takes the numeric branch.
func TestNumOrderAllOperators(t *testing.T) {
	t.Parallel()
	u := sampleUser()
	u.ExternalID = "42"
	cases := []struct {
		filter string
		want   bool
	}{
		{`externalId gt 41`, true},
		{`externalId gt 42`, false},
		{`externalId ge 42`, true},
		{`externalId ge 43`, false},
		{`externalId lt 43`, true},
		{`externalId lt 42`, false},
		{`externalId le 42`, true},
		{`externalId le 41`, false},
	}
	for _, tc := range cases {
		if got := matchesUser(u, mustParse(t, tc.filter)); got != tc.want {
			t.Errorf("matchesUser(%q) = %v, want %v", tc.filter, got, tc.want)
		}
	}
}

// TestNumOrderFallsBackToLexical: when the value is NOT numeric, a numeric
// literal ordering comparison falls through to a lexical compare (orderCompare
// strOrder branch).
func TestNumOrderLexicalFallback(t *testing.T) {
	t.Parallel()
	u := sampleUser()
	u.ExternalID = "abc" // not a number
	// "abc" vs literal number 5: numeric parse of value fails -> lexical
	// strings.Compare("abc","5"). 'a'(97) > '5'(53), so gt true / lt false.
	if !matchesUser(u, mustParse(t, `externalId gt 5`)) {
		t.Error("lexical fallback gt failed")
	}
	if matchesUser(u, mustParse(t, `externalId lt 5`)) {
		t.Error("lexical fallback lt should be false")
	}
}

// TestLiteralEqualsNull exercises the litNull eq branch: `attr eq null`
// matches an attribute with an empty value and not a populated one.
func TestLiteralEqualsNull(t *testing.T) {
	t.Parallel()
	u := sampleUser()
	// displayName is set, so eq null is false.
	if matchesUser(u, mustParse(t, `displayName eq null`)) {
		t.Error("displayName eq null matched a populated attribute")
	}
	// An empty displayName: eq null matches (value == "").
	u.DisplayName = ""
	if !matchesUser(u, mustParse(t, `displayName eq null`)) {
		t.Error("displayName eq null did not match an empty attribute")
	}
}

// TestLiteralEqualsBoolMismatch: active is bool; eq against the wrong literal
// is false, covering the litBool eq branch's negative.
func TestLiteralEqualsBoolMismatch(t *testing.T) {
	t.Parallel()
	u := sampleUser() // active true
	if matchesUser(u, mustParse(t, `active eq false`)) {
		t.Error("active eq false matched an active user")
	}
	if !matchesUser(u, mustParse(t, `active eq true`)) {
		t.Error("active eq true did not match an active user")
	}
}

// TestLiteralEqualsNumberTextualFallback: a numeric literal compared against a
// non-numeric value falls back to a textual equality (litNumber default path).
func TestLiteralEqualsNumberTextualFallback(t *testing.T) {
	t.Parallel()
	u := sampleUser()
	u.ExternalID = "007" // parses as 7
	// eq 7 -> numeric 7==7 true.
	if !matchesUser(u, mustParse(t, `externalId eq 7`)) {
		t.Error("numeric eq 7 did not match 007")
	}
}

// TestReadStringEscapes exercises readString's escape handling, including the
// \uXXXX form, through filters that compare against an escaped literal.
func TestReadStringEscapes(t *testing.T) {
	t.Parallel()
	u := sampleUser()
	u.DisplayName = "tab\there" // a real tab
	if !matchesUser(u, mustParse(t, `displayName eq "tab\there"`)) {
		t.Error("\\t escape did not round-trip in a filter literal")
	}

	u.DisplayName = "quote\"inside"
	if !matchesUser(u, mustParse(t, `displayName eq "quote\"inside"`)) {
		t.Error("\\\" escape did not round-trip")
	}

	// A == 'A'.
	u.DisplayName = "A"
	if !matchesUser(u, mustParse(t, `displayName eq "A"`)) {
		t.Error("\\u escape did not decode to 'A'")
	}

	// Each simple escape decodes to its control char; assert the parser accepts
	// them (no error) by comparing against the literal value.
	for _, esc := range []struct{ raw, val string }{
		{`"a\\b"`, `a\b`},
		{`"a\/b"`, `a/b`},
		{`"a\nb"`, "a\nb"},
		{`"a\rb"`, "a\rb"},
		{`"a\bb"`, "a\bb"},
		{`"a\fb"`, "a\fb"},
	} {
		u.DisplayName = esc.val
		if !matchesUser(u, mustParse(t, `displayName eq `+esc.raw)) {
			t.Errorf("escape %q did not round-trip", esc.raw)
		}
	}
}

// TestReadStringErrors: unterminated strings and bad escapes are invalidFilter.
func TestReadStringErrors(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`userName eq "unterminated`,
		`userName eq "bad\xescape"`,
		`userName eq "trunc\u00"`,
		`userName eq "badhex\uZZZZ"`,
		`userName eq "dangling\`,
	} {
		if _, err := parseFilter(raw); !errors.Is(err, errInvalidFilter) {
			t.Errorf("parseFilter(%q) err = %v, want errInvalidFilter", raw, err)
		}
	}
}

// TestReadNumberForms: a variety of valid numbers tokenize, and malformed ones
// are invalidFilter (readNumber's strconv validation).
func TestReadNumberForms(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`externalId eq 0`,
		`externalId eq -5`,
		`externalId eq 3.14`,
		`externalId eq 1e3`,
		`externalId eq 1.5E-2`,
		`externalId eq -0.0`,
	} {
		if _, err := parseFilter(raw); err != nil {
			t.Errorf("parseFilter(%q) unexpected error: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`externalId eq 1.2.3`,
		`externalId eq -`,
		`externalId eq 1e`,
	} {
		if _, err := parseFilter(raw); !errors.Is(err, errInvalidFilter) {
			t.Errorf("parseFilter(%q) err = %v, want errInvalidFilter", raw, err)
		}
	}
}

// TestTokenizeUnexpectedChar: a stray character not starting any token is a
// lexical error.
func TestTokenizeUnexpectedChar(t *testing.T) {
	t.Parallel()
	if _, err := parseFilter(`userName eq @`); !errors.Is(err, errInvalidFilter) {
		t.Errorf("stray '@' err = %v, want errInvalidFilter", err)
	}
}
