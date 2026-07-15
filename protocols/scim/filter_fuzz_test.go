package scim

import "testing"

// FuzzParseFilter drives parseFilter with adversarial ?filter= input —
// SCIM filters are user/connector controlled (Azure AD / Okta reconcile
// GET /Users?filter=...). The only contract under fuzz is "never panic,
// never hang": every malformed input must resolve to errInvalidFilter (or
// a valid parse), never a crash. maxFilterLen/maxFilterDepth (see filter.go)
// are the two DoS guards already in place; this fuzz target is regression
// insurance that hostile input (deep nesting, unterminated strings, null
// bytes, huge repetition, unicode) can't find a gap in them.
func FuzzParseFilter(f *testing.F) {
	seeds := []string{
		`userName eq "alice"`,
		`(userName eq "alice") and (active eq true)`,
		`not (userName eq "alice")`,
		`userName pr`,
		`externalId gt 9.5`,
		``,
		`(`,
		`)`,
		`"`,
		`"unterminated`,
		`userName eq "esc\u00`,
		`userName eq "\uZZZZ"`,
		"userName eq \x00",
		`emails[type eq "work"]`,
		`userName eq null`,
		`userName eq true and`,
		"(((((((((((((((((((((((((((((((((((((((((((((((((((((",
		`userName eq "` + string([]rune{0x1F600, 0x0, 0x10FFFF}) + `"`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseFilter panicked on %q: %v", raw, r)
			}
		}()
		expr, err := parseFilter(raw)
		if err != nil {
			return
		}
		// A successful parse must still be safe to evaluate against an
		// attribute lookup that never has anything — match must not panic
		// either, and must return a plain bool.
		_ = expr.match(func(string) ([]string, bool) { return nil, false })
	})
}
