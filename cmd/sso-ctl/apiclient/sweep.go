package apiclient

// T-2 discovery truthiness sweep: fetch the discovery document via the
// sweep apiclient and probe every advertised endpoint with its canonical
// wire method. Advertised-only semantics: an absent endpoint is never
// probed and never counts as skipped (it was never part of the contract).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// discoveryDoc is the subset of the OIDC discovery document the sweep reads.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func (d *discoveryDoc) endpoint(field string) string {
	switch field {
	case "token_endpoint":
		return d.TokenEndpoint
	case "authorization_endpoint":
		return d.AuthorizationEndpoint
	case "jwks_uri":
		return d.JWKSURI
	case "introspection_endpoint":
		return d.IntrospectionEndpoint
	case "revocation_endpoint":
		return d.RevocationEndpoint
	case "userinfo_endpoint":
		return d.UserInfoEndpoint
	case "end_session_endpoint":
		return d.EndSessionEndpoint
	}
	return ""
}

// checker carries the sweep state across the four probe groups.
type checker struct {
	base           string
	client         *Client // sweep client: discovery + on-base T-2 rows
	clientID       string
	clientSecret   string
	scope          string
	resources      []string
	expectTenantID string
	expectRoles    []string
	expectRolesSet bool
	expectNoRoles  bool

	doc     *discoveryDoc
	header  map[string]any
	payload map[string]any
	jwks    map[string]bool
}

// probeRow is one T-2 matrix row. want == 0 means truthiness: any status
// except 404 passes (including 3xx — never followed); a nonzero want is a
// content row that passes only on the exact status.
type probeRow struct {
	field  string
	method string
	want   int
}

// runT2 executes the T-2 group: discovery fetch, the endpoint matrix, and
// the token_endpoint suffix assertion. Prints the group line on stdout.
func (ck *checker) runT2() bool {
	doc, ok := ck.fetchDiscovery()
	if !ok {
		fmt.Fprintln(os.Stdout, "discovery: FAIL")
		return false
	}
	ck.doc = doc
	rows := []probeRow{
		{"token_endpoint", http.MethodPost, 0},
		{"authorization_endpoint", http.MethodGet, 0},
		{"jwks_uri", http.MethodGet, http.StatusOK},
		{"revocation_endpoint", http.MethodPost, 0},
		{"userinfo_endpoint", http.MethodGet, 0},
		{"end_session_endpoint", http.MethodGet, 0},
	}
	failed := false
	for _, row := range rows {
		if raw := doc.endpoint(row.field); raw != "" && !ck.probeEndpoint(row, raw) {
			failed = true
		}
	}
	if !ck.checkTokenSuffix() {
		failed = true
	}
	if failed {
		fmt.Fprintln(os.Stdout, "discovery: FAIL")
		return false
	}
	fmt.Fprintln(os.Stdout, "discovery: OK")
	return true
}

// fetchDiscovery fetches and decodes the discovery document through the
// sweep apiclient. Any non-200 (including 3xx — the no-redirect pin means
// the 3xx is observed, never followed), undecodable JSON, or empty body
// fails the T-2 group.
func (ck *checker) fetchDiscovery() (*discoveryDoc, bool) {
	resp, err := ck.client.Get(oidcDiscoveryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery: GET %s%s -> %s\n", redactURL(ck.base), oidcDiscoveryPath, redactURL(err.Error()))
		return nil, false
	}
	raw, rerr := ReadBody(resp)
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "discovery: GET %s%s -> %v\n", redactURL(ck.base), oidcDiscoveryPath, rerr)
		return nil, false
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "discovery: GET %s%s -> status %d; expected 200 + JSON object\n", redactURL(ck.base), oidcDiscoveryPath, resp.StatusCode)
		return nil, false
	}
	var doc discoveryDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "discovery: GET %s%s -> invalid JSON: %v\n", redactURL(ck.base), oidcDiscoveryPath, err)
		return nil, false
	}
	return &doc, true
}

// probeEndpoint validates an advertised endpoint URL and probes it with its
// canonical method. Truthiness rows pass on anything but 404; content rows
// pass only on the exact expected status (any 3xx fails a content row — no
// redirect is ever followed).
func (ck *checker) probeEndpoint(row probeRow, raw string) bool {
	if err := validateAdvertisedURL(raw); err != nil {
		fmt.Fprintf(os.Stderr, "endpoint %s %s: %s; row failed\n", row.field, redactURL(raw), err.Error())
		return false
	}
	client, path := ck.endpointClient(raw)
	resp, err := client.Do(row.method, path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "endpoint %s %s %s: %s\n", row.field, row.method, redactURL(raw), redactURL(err.Error()))
		return false
	}
	if _, rerr := ReadBody(resp); rerr != nil {
		fmt.Fprintf(os.Stderr, "endpoint %s %s %s: %v\n", row.field, row.method, redactURL(raw), rerr)
		return false
	}
	if row.want == 0 {
		if resp.StatusCode == http.StatusNotFound {
			fmt.Fprintf(os.Stderr, "endpoint %s %s %s: observed 404, expected non-404\n", row.field, row.method, redactURL(raw))
			return false
		}
		return true
	}
	if resp.StatusCode != row.want {
		fmt.Fprintf(os.Stderr, "endpoint %s %s %s: observed %d, expected %d\n", row.field, row.method, redactURL(raw), resp.StatusCode, row.want)
		return false
	}
	return true
}

// endpointClient routes an advertised absolute URL: on-base URLs ride the
// sweep client (the documented SSO_ADMIN_TOKEN residual applies there);
// off-base advertised URLs get a token-less client bound to the URL itself
// so the env can never override an advertised target.
func (ck *checker) endpointClient(raw string) (*Client, string) {
	if strings.HasPrefix(raw, ck.base) {
		return ck.client, strings.TrimPrefix(raw, ck.base)
	}
	return probeClient(raw), ""
}

// checkTokenSuffix asserts the A4 contract: the advertised token_endpoint
// path, minus the issuer's own path prefix (a reverse proxy may mount the
// deployment under a base path), is exactly "/token". A bare
// strings.HasSuffix would accept "/oauth2/token" — a different endpoint
// that happens to share the final segment.
func (ck *checker) checkTokenSuffix() bool {
	if ck.doc.TokenEndpoint == "" {
		return true // advertised-only: absence is never a failure here
	}
	u, err := url.Parse(ck.doc.TokenEndpoint)
	if err != nil {
		return true // row 2 preflight already failed this URL
	}
	base := ""
	if iu, ierr := url.Parse(ck.doc.Issuer); ierr == nil {
		base = strings.TrimSuffix(iu.Path, "/")
	}
	if path := strings.TrimPrefix(u.Path, base); path != "/token" {
		fmt.Fprintf(os.Stderr, "token_endpoint %s: path suffix %q != \"/token\"\n", redactURL(ck.doc.TokenEndpoint), u.Path)
		return false
	}
	return true
}

// bodyEcho renders a sanitized response body for stderr diagnostics; empty
// bodies produce no echo at all.
func bodyEcho(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return " body " + string(sanitizeBody(raw))
}

// urlPattern matches scheme://... tokens inside diagnostic text — url.Error
// messages embed the full request URL, including userinfo.
var urlPattern = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^ \t\n"<>)]*`)

// redactURL strips userinfo from every URL-shaped token in s. The single
// printer for URL-bearing diagnostics: no diagnostic ever echoes embedded
// credentials. Unparseable tokens pass through unchanged (a diagnostic must
// never crash on malformed input).
func redactURL(s string) string {
	return urlPattern.ReplaceAllStringFunc(s, func(m string) string {
		u, err := url.Parse(m)
		if err != nil {
			return m
		}
		u.User = nil
		return u.String()
	})
}

// sanitizeBody prepares a response body for stderr diagnostics: sensitive
// JSON fields (access_token/refresh_token/id_token/client_secret) are
// redacted first, then the result is truncated to 200 bytes. Every body
// echo in check.go goes through this helper; a minted token or client
// secret must never reach stderr.
func sanitizeBody(b []byte) []byte {
	b = redactSensitiveFields(b)
	if len(b) > bodyEchoLimit {
		b = append(append([]byte{}, b[:bodyEchoLimit]...), []byte("...")...)
	}
	return b
}

// redactSensitiveFields replaces the string values of the named JSON object
// keys while preserving every other byte (order, whitespace, other values).
func redactSensitiveFields(b []byte) []byte {
	for _, key := range []string{`"access_token"`, `"refresh_token"`, `"id_token"`, `"client_secret"`} {
		needle := []byte(key + ":")
		off := 0
		for {
			idx := bytes.Index(b[off:], needle)
			if idx < 0 {
				break
			}
			idx += off
			valStart := idx + len(needle)
			for valStart < len(b) && (b[valStart] == ' ' || b[valStart] == '\t') {
				valStart++
			}
			if valStart >= len(b) || b[valStart] != '"' {
				off = idx + len(needle)
				continue
			}
			valEnd := valStart + 1
			for valEnd < len(b) {
				if b[valEnd] == '\\' {
					valEnd += 2
					continue
				}
				if b[valEnd] == '"' {
					break
				}
				valEnd++
			}
			if valEnd >= len(b) {
				off = idx + len(needle)
				continue
			}
			valEnd++
			redacted := append([]byte{}, b[:valStart]...)
			redacted = append(redacted, `"<redacted>"`...)
			redacted = append(redacted, b[valEnd:]...)
			b = redacted
			off = valStart + len(`"<redacted>"`)
		}
	}
	return b
}
