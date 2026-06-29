package metrics

import "testing"

// TestSanitizeMethod is the cardinality-DoS regression guard: an arbitrary
// (attacker-chosen) HTTP method must collapse to a single "other" label so it
// cannot explode Prometheus label cardinality on the scraped /metrics endpoint,
// while standard methods pass through unchanged.
func TestSanitizeMethod(t *testing.T) {
	t.Parallel()
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"} {
		if got := sanitizeMethod(m); got != m {
			t.Errorf("sanitizeMethod(%q) = %q, want %q (standard method must pass through)", m, got, m)
		}
	}
	for _, m := range []string{"EVIL", "get", "", "FOOBAR", "X-CUSTOM", "POST ", "\x00"} {
		if got := sanitizeMethod(m); got != "other" {
			t.Errorf("sanitizeMethod(%q) = %q, want \"other\" (unbounded label not collapsed)", m, got)
		}
	}
}
