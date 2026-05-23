package core

// ErrorBody returns the OAuth/OIDC standard error envelope:
//
//	{ "error": code }
//
// Wrap with ctx.JSON(status, ErrorBody(...)) at handler error
// branches. Keeping the shape in one place means callers don't have
// to remember the wire key (KeyError) and reviewers can grep one
// function to audit every error response.
func ErrorBody(code string) map[string]string {
	return map[string]string{KeyError: code}
}

// ErrorBodyDesc adds error_description to the envelope:
//
//	{ "error": code, "error_description": desc }
//
// Per RFC 6749 §5.2 error_description is optional human-readable
// detail. Don't put PII or token material in here — SIEM stores it
// in the clear.
func ErrorBodyDesc(code, desc string) map[string]string {
	return map[string]string{KeyError: code, KeyErrorDescription: desc}
}
