package oauth

import (
	"github.com/snaplink/sso/shared/core"
)

// EchoStateConditionally writes the state parameter into a JSON response
// map when state is non-empty. Per RFC 6749 §4.1.2.1, the authorization
// server MUST echo state back to the client both on success AND on error
// responses when the initial request carried it.
//
// Call this right before ctx.JSON in every authorization-code, implicit,
// hybrid, and JARM response handler so no response mode drops state.
func EchoStateConditionally(resp map[string]any, state string) {
	if state != "" {
		resp[core.KeyState] = state
	}
}

// EchoStateError returns an error JSON body with the state parameter echoed
// back when non-empty. Use this for error responses in authorization flows
// where the client must receive its state back to detect CSRF.
func EchoStateError(state string) map[string]any {
	body := map[string]any{
		core.KeyError: core.ErrAccessDenied,
	}
	if state != "" {
		body[core.KeyState] = state
	}
	return body
}

// EchoStateRedirect appends the state parameter to a redirect URL's query
// string when non-empty. Use for redirect-based response modes (query,
// fragment) where the RP expects state in the URL.
func EchoStateRedirect(baseURL, state string) string {
	if state == "" {
		return baseURL
	}
	sep := "?"
	if containsQuery(baseURL) {
		sep = "&"
	}
	return baseURL + sep + core.KeyState + "=" + state
}

func containsQuery(url string) bool {
	for i := 0; i < len(url); i++ {
		if url[i] == '?' {
			return true
		}
	}
	return false
}

// compile-time validation: these functions compile only when core.KeyState
// is defined. No runtime cost.
var _ = EchoStateConditionally
var _ = EchoStateError
var _ = EchoStateRedirect
