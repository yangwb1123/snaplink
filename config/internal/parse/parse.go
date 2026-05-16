// Package parse holds the tiny pieces of value-coercion and nested-map
// path-writing that every Source implementation needs (env, flag, etcd,
// and future K8s ConfigMap / consul / vault sources). Living here rather
// than in the parent config package keeps the public API of config small
// without forcing every source to duplicate fifteen lines of utility.
package parse

import "github.com/goccy/go-yaml"

// Value runs the raw scalar string through yaml.Unmarshal so "true" /
// "42" / "3.14" / "null" / "[a, b]" become their native typed
// equivalents. Anything yaml can't parse falls back to the raw string
// (which is the safe default — string is the OS-native shape of an
// ENV / etcd-leaf value anyway).
//
// The empty string short-circuits to "" rather than yaml's nil — an
// operator who set SSO_LOGGING__LEVEL="" probably meant the empty
// string and not "remove this key", which is what nil would imply.
func Value(raw string) any {
	if raw == "" {
		return ""
	}
	var v any
	if err := yaml.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	return v
}

// SetPath walks the keys creating intermediate maps as needed and
// writes val at the leaf. If an intermediate key already holds a
// non-map value, it's overwritten with a fresh map — the trailing
// write wins (matches the Loader's deep-merge semantics).
func SetPath(root map[string]any, path []string, val any) {
	if len(path) == 0 {
		return
	}
	m := root
	for i, k := range path {
		if i == len(path)-1 {
			m[k] = val
			return
		}
		sub, ok := m[k].(map[string]any)
		if !ok {
			sub = map[string]any{}
			m[k] = sub
		}
		m = sub
	}
}
