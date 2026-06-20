package oauth

import "slices"

// ACRMatchesAny reports whether the inbound ACR claim matches any of
// the demanded values. Empty inbound ACR never matches any non-empty
// demand — a subject token with no factor information can't satisfy
// a step-up gate (RFC 9470 §3 / OIDC Core §3.1.2.1 acr_values).
func ACRMatchesAny(inbound string, demanded []string) bool {
	if inbound == "" || len(demanded) == 0 {
		return false
	}
	return slices.Contains(demanded, inbound)
}

// MergeTargets deduplicates a slice of resource / audience URIs
// while preserving the first-occurrence order. Both RFC 8707
// `resource` and RFC 8693 `audience` express the same intent;
// merging lets callers use whichever vocabulary their tooling
// favors without changing the token contents.
func MergeTargets(primary, secondary []string) []string {
	if len(primary) == 0 && len(secondary) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(primary)+len(secondary))
	out := make([]string, 0, len(primary)+len(secondary))
	for _, s := range primary {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range secondary {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
