package configaudit

import "strings"

// sensitiveSubstrings are matched case-insensitively against a leaf field
// name. Fixed by AGENTS.md's config-audit redaction rule: "any field whose
// lowercase name contains secret/password/dsn/token/key is recorded as
// '***'". This is a focused sibling of platform/audit's Redactor (which
// operates on audit.Event's fixed field set), not a reuse of it — a config
// snapshot/patch has no Event to redact, just arbitrary JSON keys.
var sensitiveSubstrings = []string{"secret", "password", "dsn", "token", "key"}

// IsSensitiveKey reports whether name (a JSON object key, matched
// case-insensitively) looks like it holds a credential. Authorization is an
// exact key match so fields such as AuthorizationServers remain visible.
func IsSensitiveKey(name string) bool {
	lower := strings.ToLower(name)
	if lower == "authorization" {
		return true
	}
	for _, s := range sensitiveSubstrings {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// RedactOps returns a copy of ops with every add/replace op whose PATH's
// final segment is sensitive (IsSensitiveKey) having its Value replaced by
// "***". Remove ops carry no Value already, so they pass through
// unchanged. Diff runs over the RAW (unredacted) snapshots so the patch
// still records THAT a secret changed (the path + op survive); RedactOps
// then scrubs WHAT it changed to before the patch reaches a Store or an
// HTTP response — never redact before diffing, or two different secrets
// would both diff to "no change".
func RedactOps(ops []Op) []Op {
	out := make([]Op, len(ops))
	for i, op := range ops {
		out[i] = op
		if op.Op == "remove" {
			continue
		}
		if IsSensitiveKey(lastPathSegment(op.Path)) {
			out[i].Value = "***"
		}
	}
	return out
}

// Redact returns a deep copy of snapshot with every sensitive leaf key
// (IsSensitiveKey) replaced by "***", recursing into nested objects and
// arrays. Used on the .../running and .../applied admin endpoints, which
// expose a whole snapshot rather than a patch (RedactOps covers .../diff
// and .../history).
func Redact(snapshot map[string]any) map[string]any {
	if snapshot == nil {
		return nil
	}
	out, _ := redactValue(snapshot).(map[string]any)
	return out
}

// redactValue is Redact's recursive worker, generic over the `any`-typed
// values a decoded JSON document is made of (map[string]any, []any, or a
// scalar leaf).
func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if IsSensitiveKey(k) {
				out[k] = "***"
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactValue(val)
		}
		return out
	default:
		return v
	}
}
