package admingovernance

import "strings"

// DestructiveRule classifies one (HTTP method, path-prefix) pair as
// destructive. PathPrefix matches by simple prefix rather than an exact
// route template because the grpc-gateway-proxied admin services (tenant /
// client / user / token / permission CRUD) resolve a path parameter into
// the REAL request path (e.g. "/api/v1/admin/tenants/acme-corp", not
// "/api/v1/admin/tenants/:id") before this check ever sees it — a prefix
// match ("/api/v1/admin/tenants/") catches every ID without the classifier
// needing to know the route's parameter shape. Action is an operator-chosen
// label surfaced only for logging/audit; it carries no behavior.
type DestructiveRule struct {
	Method     string
	PathPrefix string
	Action     string
}

// DestructiveSet is a configured, ordered list of DestructiveRule entries.
// An empty set classifies nothing as destructive — the guard is then a
// byte-identical no-op, matching every other opt-in mechanism in this
// package.
type DestructiveSet []DestructiveRule

// NewDestructiveSet builds a DestructiveSet from configured rules.
func NewDestructiveSet(rules []DestructiveRule) DestructiveSet { return DestructiveSet(rules) }

// Match reports whether (method, path) is classified destructive, and the
// matching rule's Action label. First match wins (declaration order).
func (s DestructiveSet) Match(method, path string) (action string, ok bool) {
	for _, r := range s {
		if r.Method == method && r.PathPrefix != "" && strings.HasPrefix(path, r.PathPrefix) {
			return r.Action, true
		}
	}
	return "", false
}
