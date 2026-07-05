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

// ErrorBodyWithTrace returns the standard error envelope enriched with
// the request's trace ID for client-side debugging. When traceID is
// empty the trace_id field is omitted (backward compatible).
//
//	{ "error": code, "trace_id": "abc123" }
func ErrorBodyWithTrace(code, traceID string) map[string]string {
	body := map[string]string{KeyError: code}
	if traceID != "" {
		body["trace_id"] = traceID
	}
	return body
}

// ErrorBodyWithLocalizedDesc adds error_description_localized to an
// already-built error envelope (mutates body in place and returns it for
// chaining). This is a purely ADDITIVE, opt-in enrichment — same shape as
// ErrorBodyWithTrace's trace_id: the existing `error` / `error_description`
// fields are left exactly as the caller built them, so a response built
// without this call (no Localizer configured, or no translation found for
// this key/locale — see shared/i18n) is byte-identical to today. An empty
// desc is a no-op (nothing to add).
//
//	{ "error": code, "error_description_localized": desc }
func ErrorBodyWithLocalizedDesc(body map[string]string, desc string) map[string]string {
	if desc != "" {
		body[KeyErrorDescriptionLocalized] = desc
	}
	return body
}
