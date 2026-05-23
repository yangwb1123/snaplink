package oauth

// Response mode constants per OIDC Core §3.1.2.5 + Form Post 1.0 §2.
// Duplicated here (also present in oidc/discovery_options.go) so the
// oauth/ handlers can validate response_mode without importing oidc/
// — which would create a cycle through handle_end_session.
const (
	responseModeQuery    = "query"
	responseModeFragment = "fragment"
	responseModeFormPost = "form_post"
)

// isValidResponseMode reports whether the supplied response_mode
// value is one this server understands. Empty is always valid
// (means "use the response_type-defined default") so callers MUST
// short-circuit on empty before this check.
func isValidResponseMode(mode string) bool {
	switch mode {
	case responseModeQuery, responseModeFragment, responseModeFormPost:
		return true
	}
	return false
}
