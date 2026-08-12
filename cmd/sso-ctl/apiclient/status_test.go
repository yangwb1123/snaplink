package apiclient

import (
	"net/http"
	"strings"
	"testing"
)

// TestStatusMessage_RedirectGolden pins the exact 3xx diagnostic template:
// "<prog>: <verb> failed (HTTP <code> redirect to <redactURL(Location)>):
// <hint>; body: <echo>". The Location must be userinfo-redacted, the body
// sanitized (sensitive fields) and truncated to bodyEchoLimit + "...".
func TestStatusMessage_RedirectGolden(t *testing.T) {
	cases := []struct {
		name   string
		status int
		loc    string
		body   string
		want   string
	}{
		{
			name:   "location userinfo redacted and body truncated",
			status: http.StatusTemporaryRedirect,
			loc:    "https://user:sekret@target.example/base",
			body:   strings.Repeat("<html>gateway moved</html>\n", 20), // > 200 bytes
			want:   "sso-ctl tenants: list failed (HTTP 307 redirect to https://target.example/base): set SSO_ADMIN_ADDR to the canonical admin origin; body: " + strings.Repeat("<html>gateway moved</html>\n", 20)[:200] + "...",
		},
		{
			name:   "no location header means no to-clause",
			status: http.StatusFound,
			body:   "moved",
			want:   "sso-ctl tenants: list failed (HTTP 302 redirect): set SSO_ADMIN_ADDR to the canonical admin origin; body: moved",
		},
		{
			name:   "sensitive field redacted",
			status: http.StatusTemporaryRedirect,
			loc:    "https://target.example/",
			body:   `{"client_secret":"TOPSECRET","error":"redirecting"}`,
			want:   "sso-ctl tenants: list failed (HTTP 307 redirect to https://target.example/): set SSO_ADMIN_ADDR to the canonical admin origin; body: {\"client_secret\":\"<redacted>\",\"error\":\"redirecting\"}",
		},
		{
			name:   "empty body",
			status: http.StatusTemporaryRedirect,
			loc:    "https://target.example/",
			body:   "",
			want:   "sso-ctl tenants: list failed (HTTP 307 redirect to https://target.example/): set SSO_ADMIN_ADDR to the canonical admin origin; body: (empty)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tc.status, Header: http.Header{}}
			if tc.loc != "" {
				resp.Header.Set("Location", tc.loc)
			}
			got := StatusMessage("sso-ctl tenants", "list", RedirectHintAdmin, resp, []byte(tc.body))
			if got != tc.want {
				t.Errorf("StatusMessage =\n  %q\nwant\n  %q", got, tc.want)
			}
			if strings.Contains(got, "sekret") {
				t.Errorf("userinfo leaked into diagnostic: %q", got)
			}
		})
	}
}

// TestStatusMessage_Non3xxByteIdentical pins that every non-3xx status keeps
// the historical "<prog>: <verb> failed (HTTP <code>): <body>" bytes — the
// fix must never alter non-redirect diagnostics.
func TestStatusMessage_Non3xxByteIdentical(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{http.StatusNotFound, `{"error":"tenant_not_found"}`, "sso-ctl tenants: get failed (HTTP 404): {\"error\":\"tenant_not_found\"}"},
		{http.StatusInternalServerError, "boom", "sso-ctl tokens: revoke failed (HTTP 500): boom"},
		{http.StatusBadRequest, "", "sso-ctl sessions: revoke failed (HTTP 400): "},
	}
	for _, tc := range cases {
		resp := &http.Response{StatusCode: tc.status, Header: http.Header{}}
		got := StatusMessage(progNameFor(tc.status), verbFor(tc.status), RedirectHintAdmin, resp, []byte(tc.body))
		if got != tc.want {
			t.Errorf("StatusMessage(%d) =\n  %q\nwant\n  %q", tc.status, got, tc.want)
		}
	}
}

func progNameFor(status int) string {
	switch status {
	case http.StatusNotFound:
		return "sso-ctl tenants"
	case http.StatusInternalServerError:
		return "sso-ctl tokens"
	default:
		return "sso-ctl sessions"
	}
}

func verbFor(status int) string {
	switch status {
	case http.StatusNotFound:
		return "get"
	case http.StatusInternalServerError:
		return "revoke"
	default:
		return "revoke"
	}
}
