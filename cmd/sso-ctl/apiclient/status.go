package apiclient

import (
	"fmt"
	"net/http"
)

// RedirectHintAdmin is the operator remediation hint for the env-var
// surfaces: none of the affected sso-ctl subcommands has an --addr flag,
// so SSO_ADMIN_ADDR is the only knob to point at the canonical origin.
const RedirectHintAdmin = "set SSO_ADMIN_ADDR to the canonical admin origin"

// StatusMessage formats a non-200 admin API response for a stderr
// diagnostic. A 3xx response (observed, never followed — see
// RejectRedirect) gets the redirect wording with a userinfo-redacted
// Location, the operator hint, and a sanitized/truncated body echo so the
// operator can diagnose a redirecting gateway; every other status keeps
// the historical "<prog>: <verb> failed (HTTP <code>): <body>" bytes
// exactly (verb is the caller's existing action word, e.g. "list").
func StatusMessage(prog, verb, hint string, resp *http.Response, body []byte) string {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		msg := fmt.Sprintf("%s: %s failed (HTTP %d redirect", prog, verb, resp.StatusCode)
		if loc := resp.Header.Get("Location"); loc != "" {
			msg += " to " + redactURL(loc)
		}
		msg += "): " + hint
		if len(body) == 0 {
			return msg + "; body: (empty)"
		}
		return msg + "; body: " + string(sanitizeBody(body))
	}
	return fmt.Sprintf("%s: %s failed (HTTP %d): %s", prog, verb, resp.StatusCode, string(body))
}
