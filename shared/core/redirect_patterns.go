// Redirect-URI pattern grammar (the opt-in `redirect_uri_patterns` snaplink
// extension to RFC 7591 client metadata).
//
// The grammar, normalization rules, and security rationale are adjudicated in
// docs/design/redirect-uri-patterns.md. The implementation lives in THIS file
// (package core) because core is the dependency-free SPI/types/sentinels leaf
// (AGENTS.md §1 / the TestArchitecture_ImportBoundaries gate forbids it from
// importing any snaplink package) and the runtime gate
// (Client.IsRedirectURIValid in jwks.go) must consult it directly. Every
// provisioning surface — static-config boot validation, DCR register/update —
// calls the SAME two exported functions, so a provisioned pattern is matched
// by exactly the code that validated it, and the whole unit is fuzzable
// (redirect_patterns_fuzz_test.go).
// The design is deliberately narrow: https-only, fixed host, exactly one
// interior path-segment wildcard bounded by literals, no query/fragment/
// userinfo/percent-encoding in patterns, and deterministic normalization of
// both sides before comparison.
package core

import (
	"fmt"
	"net/url"
	"strings"
)

// literalChars is the RFC 3986 `pchar` set minus percent-encoding (patterns
// reject "%" entirely): unreserved (ALPHA / DIGIT / "-" / "." / "_" / "~")
// plus sub-delims plus ":" and "@". A literal segment may contain only these
// bytes; "*" inside a literal is a partial wildcard and rejected.
const literalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:@!$&'()*+,;="

// ValidateRedirectURIPattern checks that pattern is an acceptable
// redirect-URI pattern under the grammar in
// docs/design/redirect-uri-patterns.md. It returns a descriptive error on
// ANY deviation (fail-closed); an empty string and an unparseable or
// non-https URL are rejected like everything else. Every provisioning
// surface (config boot, DCR register/update) MUST reject an invalid pattern
// here before it can reach the runtime matcher.
func ValidateRedirectURIPattern(pattern string) error {
	_, err := compileRedirectPattern(pattern)
	return err
}

// MatchRedirectURIPattern reports whether uri satisfies pattern under the
// documented normalization rules (case-insensitive host, https default-port
// removal, per-segment percent-decoding, dot-segment collapse). Callers MUST
// have validated the pattern through a provisioning gate (Validate... or the
// store/config path that enforces it); a pattern that fails to compile
// degrades to no-match, never to a widened match — so a stale store row
// written by a pre-migration replica can never loosen the gate.
func MatchRedirectURIPattern(pattern, uri string) bool {
	p, err := compileRedirectPattern(pattern)
	if err != nil {
		return false
	}
	c, err := compileRedirectCandidate(uri)
	if err != nil {
		return false
	}
	if p.scheme != c.scheme || p.host != c.host || p.port != c.port {
		return false
	}
	if len(p.segments) != len(c.segments) {
		return false
	}
	for i, ps := range p.segments {
		if ps.wildcard {
			continue
		}
		if ps.literal != c.segments[i].literal {
			return false
		}
	}
	return true
}

// redirectCompiled is the normalized shape both sides are reduced to before
// comparison. port is "" or a non-default numeric port (https :443 is
// stripped by normalization).
type redirectCompiled struct {
	scheme   string
	host     string
	port     string
	segments []redirectSegment
}

// redirectSegment is one path segment: either the single wildcard or a
// literal.
type redirectSegment struct {
	literal  string
	wildcard bool
}

// compileRedirectPattern parses + validates a PATTERN (strict grammar) into
// its normalized form. Every rule below maps to a rejection in the design
// doc's Decision 2.
func compileRedirectPattern(pattern string) (*redirectCompiled, error) {
	if pattern == "" {
		return nil, fmt.Errorf("redirect pattern: empty pattern")
	}
	if strings.Contains(pattern, "%") {
		return nil, fmt.Errorf("redirect pattern: percent-encoding is not allowed in a pattern: %q", pattern)
	}
	u, err := url.Parse(pattern)
	if err != nil || !u.IsAbs() {
		return nil, fmt.Errorf("redirect pattern: not an absolute URL: %q", pattern)
	}
	if strings.ToLower(u.Scheme) != "https" {
		return nil, fmt.Errorf("redirect pattern: scheme must be https: %q", pattern)
	}
	if u.User != nil {
		return nil, fmt.Errorf("redirect pattern: userinfo is not allowed: %q", pattern)
	}
	if hasURIQueryOrFragment(u, pattern) {
		return nil, fmt.Errorf("redirect pattern: fragment/query are not allowed: %q", pattern)
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "*") {
		return nil, fmt.Errorf("redirect pattern: host must be a concrete name (no wildcards): %q", pattern)
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("redirect pattern: empty port: %q", pattern)
	}
	port := u.Port()
	if port != "" && !isDigits(port) {
		return nil, fmt.Errorf("redirect pattern: port must be numeric: %q", pattern)
	}
	segs, err := compilePatternSegments(u.EscapedPath())
	if err != nil {
		return nil, fmt.Errorf("redirect pattern: %w: %q", err, pattern)
	}
	return &redirectCompiled{
		scheme:   "https",
		host:     strings.ToLower(host),
		port:     normalizePort("https", port),
		segments: segs,
	}, nil
}

// compilePatternSegments enforces the wildcard grammar: exactly one "*" that
// is a COMPLETE segment, never partial, never the first or last segment, no
// empty segments, literals restricted to the pchar set. Dot segments are
// rejected outright — a pattern must be written in its canonical path form.
func compilePatternSegments(path string) ([]redirectSegment, error) {
	parts, err := splitPath(path)
	if err != nil {
		return nil, err
	}
	wildcards := 0
	for i, raw := range parts {
		if raw == "." || raw == ".." {
			return nil, fmt.Errorf("dot segments are not allowed in a pattern")
		}
		if raw == "*" {
			if i == 0 || i == len(parts)-1 {
				return nil, fmt.Errorf("the wildcard must be an interior path segment")
			}
			wildcards++
			if wildcards > 1 {
				return nil, fmt.Errorf("at most one wildcard segment per pattern")
			}
			continue
		}
		if strings.Contains(raw, "*") {
			return nil, fmt.Errorf("partial-segment wildcards are not allowed")
		}
		for _, r := range raw {
			if !strings.ContainsRune(literalChars, r) {
				return nil, fmt.Errorf("invalid character %q in path segment", r)
			}
		}
	}
	if wildcards != 1 {
		return nil, fmt.Errorf("a pattern must contain exactly one wildcard segment")
	}
	out := make([]redirectSegment, 0, len(parts))
	for _, raw := range parts {
		if raw == "*" {
			out = append(out, redirectSegment{wildcard: true})
			continue
		}
		out = append(out, redirectSegment{literal: raw})
	}
	return out, nil
}

// compileRedirectCandidate parses + validates a CANDIDATE redirect URI (the
// value from a browser login request) into the same normalized shape.
// Fail-closed: a candidate with a query, fragment, userinfo, undecodable
// segments, or any decoded separator is NOT matchable — the pattern surface
// stays strictly path-shaped, which is what closes the encoding-bypass
// attacks in the design doc's adversarial table.
func compileRedirectCandidate(raw string) (*redirectCompiled, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return nil, fmt.Errorf("redirect pattern: not an absolute URL: %q", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	if u.User != nil || hasURIQueryOrFragment(u, raw) {
		return nil, fmt.Errorf("redirect pattern: userinfo/fragment/query are not matchable: %q", raw)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.Contains(host, "*") {
		return nil, fmt.Errorf("redirect pattern: host must be concrete: %q", raw)
	}
	port := u.Port()
	if port != "" && !isDigits(port) {
		return nil, fmt.Errorf("redirect pattern: port must be numeric: %q", raw)
	}
	segs, err := compileCandidateSegments(u.EscapedPath(), raw)
	if err != nil {
		return nil, err
	}
	return &redirectCompiled{
		scheme:   scheme,
		host:     host,
		port:     normalizePort(scheme, port),
		segments: segs,
	}, nil
}

func hasURIQueryOrFragment(u *url.URL, raw string) bool {
	return u.ForceQuery || u.Fragment != "" || u.RawQuery != "" || strings.Contains(raw, "#")
}

// compileCandidateSegments percent-decodes + dot-collapses the candidate's
// path into the matchable segment list. Decoding happens BEFORE dot-collapse
// (the browser percent-decodes first), and a decoded separator (/ ? # \ NUL)
// rejects the whole candidate — the pattern surface stays strictly path-
// shaped, which closes the encoding-bypass attacks in the design doc.
func compileCandidateSegments(path, raw string) ([]redirectSegment, error) {
	parts, err := splitPath(path)
	if err != nil {
		return nil, err
	}
	decoded := make([]string, 0, len(parts))
	for _, rawSeg := range parts {
		d, err := url.PathUnescape(rawSeg)
		if err != nil {
			return nil, fmt.Errorf("redirect pattern: invalid percent-encoding: %q", raw)
		}
		if strings.ContainsAny(d, "/?#\\\x00") {
			return nil, fmt.Errorf("redirect pattern: decoded segment contains a separator: %q", raw)
		}
		decoded = append(decoded, d)
	}
	// Dot-collapse on the DECODED segments — browser equivalence, and an
	// encoded ".." can only shrink the count (potentially below the
	// pattern's), never widen it.
	decoded = collapseDots(decoded)
	if len(decoded) == 0 {
		return nil, fmt.Errorf("redirect pattern: empty path: %q", raw)
	}
	segs := make([]redirectSegment, 0, len(decoded))
	for _, d := range decoded {
		segs = append(segs, redirectSegment{literal: d})
	}
	return segs, nil
}

// splitPath splits a raw URL path into its non-empty raw segments, dropping
// the leading "/" and rejecting empty segments (double slashes, trailing
// slash). Percent-decoding and dot-segment collapse happen in the callers:
// patterns forbid both, candidates decode-then-collapse to mirror browser
// navigation.
func splitPath(path string) ([]string, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("path must be absolute")
	}
	raw := strings.Split(path, "/")
	// raw[0] is "" from the leading slash; drop it, then reject empties.
	raw = raw[1:]
	out := make([]string, 0, len(raw))
	for _, seg := range raw {
		if seg == "" {
			return nil, fmt.Errorf("empty path segment")
		}
		out = append(out, seg)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("path must contain at least one segment")
	}
	return out, nil
}

// collapseDots removes "." and applies ".." pop semantics (RFC 3986
// §5.2.4) to an already-decoded segment list.
func collapseDots(segs []string) []string {
	var stack []string
	for _, seg := range segs {
		switch seg {
		case ".":
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, seg)
		}
	}
	return stack
}

// normalizePort strips the https default port 443 so "host" and "host:443"
// compare equal; every other explicit port is preserved and must match
// exactly. An empty port means "the default", identical to no port.
func normalizePort(scheme, port string) string {
	if port == "443" && scheme == "https" {
		return ""
	}
	return port
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
