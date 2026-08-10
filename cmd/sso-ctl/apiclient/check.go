package apiclient

// Command surface for `sso-ctl check` — the deploy-tree live sweep.
//
// Probe groups (exit code contract: 0 all executed and passed; 1 any
// failure or any skipped group, final line `check INCOMPLETE`; 2 CLI
// misuse):
//
//	T-2   discovery truthiness sweep: fetch /.well-known/openid-configuration
//	      via apiclient, probe every advertised endpoint with its canonical
//	      wire method (the router collapses method mismatch to 404, so a
//	      wrong-method probe proves nothing), assert the token_endpoint path
//	      suffix is "/token".
//	T-8a  client-credentials mint; claims matrix (kid in JWKS, typ at+jwt,
//	      iss == discovery issuer, sub/client_id == --client-id, jti, plus
//	      operator-declared scope/resource/tenant_id expectations and the
//	      conditional roles assertion: --expect-roles <set> (equal when
//	      present, absence tolerated) or --expect-no-roles (cc-path pin);
//	      revoke + post-revoke introspection.
//	T-8d  unregistered-scope probe: byte-identical 400 {"error":"invalid_scope"}.
//	T-9   credential-less introspection probe: byte-identical 401
//	      {"error":"invalid_client"} via a bare client (apiclient.New would
//	      inherit SSO_ADMIN_TOKEN).
//
// Security posture (see
// docs/architect-analysis/auto/cmd-sso-ctl-apiclient-design.md):
//   - every probe runs with the no-redirect pin (redirects would forward
//     307/308 POST bodies and same-host Authorization);
//   - the mint/T-8d/T-9 probes never carry a bearer (a non-Basic
//     Authorization header makes /token reject the request outright);
//   - credential-bearing probes go through apiclient with body credentials,
//     targeted at the *advertised* endpoints only;
//   - no diagnostic ever echoes a credential, the minted token, or the probe
//     scope; declared/observed claim values (tenant_id, scope, roles) may be
//     named, and redactURL/sanitizeBody are the only URL/body printers.

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	checkProg = "sso-ctl check"
	// oidcDiscoveryPath mirrors interfaces/sso PathOIDCDiscovery; apiclient
	// must not import interfaces/sso (the value is a wire contract).
	oidcDiscoveryPath = "/.well-known/openid-configuration"
	// probeScopePrefix + 12 random alphanumerics. The prefix guarantees the
	// scope is never openid/device_sso (those bypass scope allowlists).
	probeScopePrefix = "sweep-probe-"
	probeScopeLen    = 12
	// 62*4 = 248: rejection sampling keeps the charset mapping unbiased.
	probeScopeLimit = 62 * 4
	probeCharset    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	// bodyEchoLimit is the sanitizeBody truncation ceiling for stderr echoes.
	bodyEchoLimit = 200
)

// CheckRun implements the `sso-ctl check` subcommand. args has the leading
// program name stripped (the dispatcher's os.Args[2:]). It returns the
// process exit code: 0 all probe groups executed and passed; 1 any executed
// check failed or a group was skipped (`check OK` is never printed on a run
// that skipped a group); 2 CLI misuse.
func CheckRun(args []string) int {
	ck, code := parseCheckConfig(args)
	if ck == nil {
		return code // help (0) or misuse (2); diagnostics already printed
	}
	scope, err := probeScope()
	if err != nil {
		fmt.Fprintf(os.Stderr, checkProg+": %v\n", err)
		return 1
	}
	if os.Getenv(EnvToken) != "" {
		// The sweep client inherits SSO_ADMIN_TOKEN via New's env fallback;
		// under the no-redirect pin the bearer can ride only to the
		// advertised hosts on the discovery/T-2 GET rows.
		fmt.Fprintln(os.Stderr, checkProg+": SSO_ADMIN_TOKEN is set — the admin bearer rides only to the advertised hosts on the discovery/T-2 GET rows and is never forwarded past a redirect")
	}
	discoveryOK := ck.runT2()
	mintOK, mintSkipped := ck.runT8a()
	invalidScopeOK, invalidScopeSkipped := ck.runT8d(scope)
	introspectOK, introspectSkipped := ck.runT9()
	if mintSkipped || invalidScopeSkipped || introspectSkipped {
		fmt.Fprintln(os.Stdout, "check INCOMPLETE")
		return 1
	}
	if !discoveryOK || !mintOK || !invalidScopeOK || !introspectOK {
		fmt.Fprintln(os.Stdout, "check FAIL")
		return 1
	}
	fmt.Fprintln(os.Stdout, "check OK")
	return 0
}

// parseCheckConfig parses and validates the check invocation, returning the
// wired checker or a nonzero exit code on misuse (diagnostics and usage
// already printed; flag-package errors print their own diagnostic). The
// roles declarations are validated together: both flags are contradictory
// misuse — the two assertions cannot both be true of one mint — and the
// check precedes the credentials check so flag errors always win.
func parseCheckConfig(args []string) (*checker, int) {
	fs := flag.NewFlagSet(checkProg, flag.ContinueOnError)
	fs.Usage = usage
	addrFlag := fs.String("addr", DefaultAddr, "base URL (SSO_ADMIN_ADDR env wins)")
	clientID := fs.String("client-id", "", "OAuth client ID (required with --client-secret)")
	clientSecret := fs.String("client-secret", "", "OAuth client secret (required with --client-id)")
	scopeFlag := fs.String("scope", "", "space-separated scopes to request at mint")
	var resources stringList
	fs.Var(&resources, "resource", "RFC 8707 resource indicator (repeatable)")
	expectTenantID := fs.String("expect-tenant-id", "", "declare the minted token MUST carry this tenant_id")
	var expectRoles expectRolesFlag
	fs.Var(&expectRoles, "expect-roles", "declare the roles set a minted token's roles claim MUST equal when present; absence is tolerated (conditional assertion; repeatable or space-separated)")
	expectNoRoles := fs.Bool("expect-no-roles", false, "declare the minted token MUST NOT carry a non-empty roles claim (the attainable client-credentials pin: cc mints never resolve Subject.Roles)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, 0 // usage() already printed by the flag package; the
			// tree's ContinueOnError convention would exit 2 here, but A1
			// mandates exit 0 for help — check is the deliberate first case.
		}
		return nil, 2 // flag package printed the error + usage to stderr
	}
	if expectRoles.present && *expectNoRoles {
		fmt.Fprintln(os.Stderr, checkProg+": --expect-roles and --expect-no-roles are mutually exclusive")
		usage()
		return nil, 2
	}
	if *clientID == "" || *clientSecret == "" {
		fmt.Fprintln(os.Stderr, checkProg+": missing required --client-id and --client-secret (T-8a/T-8d groups cannot run)")
		usage()
		return nil, 2
	}
	base := effectiveAddr(*addrFlag)
	if err := validateBaseURL(base); err != nil {
		fmt.Fprintln(os.Stderr, checkProg+": invalid base URL: "+err.Error())
		usage()
		return nil, 2
	}
	return &checker{
		base:           strings.TrimSuffix(base, "/"),
		client:         New(WithAddr(base), WithNoRedirect()),
		clientID:       *clientID,
		clientSecret:   *clientSecret,
		scope:          *scopeFlag,
		resources:      []string(resources),
		expectTenantID: *expectTenantID,
		expectRoles:    []string(expectRoles.set),
		expectRolesSet: expectRoles.present,
		expectNoRoles:  *expectNoRoles,
	}, 0
}

// usage prints the check subcommand banner to stderr (the tree convention:
// help and diagnostics go to stderr, never stdout).
func usage() {
	fmt.Fprint(os.Stderr, `sso-ctl check — deploy-tree live sweep (T-2 truthiness + T-8a/T-8d/T-9 probes).

Usage:
  sso-ctl check [flags]

Probe groups:
  T-2   Discovery sweep: fetch /.well-known/openid-configuration via
        apiclient, probe every advertised endpoint with its canonical method
        (404 = unmounted = fail), assert the token_endpoint path suffix is
        "/token". Advertised-only: absent endpoints are never probed.
  T-8a  Client-credentials mint; access-token claims matrix (kid in JWKS,
        typ at+jwt, iss == discovery issuer, sub/client_id == --client-id,
        jti, declared --scope/--resource/--expect-* claims); revoke +
        post-revoke introspection.
  T-8d  Unregistered-scope probe: 400 {"error":"invalid_scope"} byte-identical.
        Valid only when the client's AllowedScopes is non-empty or a global
        scope registry is wired.
  T-9   Credential-less introspection probe: 401 {"error":"invalid_client"}.

Exit codes:
  0  all probe groups executed and passed
  1  any executed check failed, or a group was skipped (check INCOMPLETE)
  2  CLI misuse (missing credentials, invalid --addr, unknown flag)

Flags:
  --addr string              base URL (default "http://127.0.0.1:8443"; SSO_ADMIN_ADDR env wins)
  --client-id string         OAuth client ID (required with --client-secret)
  --client-secret string     OAuth client secret (required with --client-id)
  --scope string             space-separated scopes to request at mint (optional)
  --resource string          RFC 8707 resource indicator (repeatable; optional)
  --expect-tenant-id string  declare the minted token MUST carry this tenant_id (optional)
  --expect-roles roles...    declare the roles set a minted token's roles claim MUST equal when
                             present; absence is tolerated — a conditional assertion, because
                             cc-path mints never resolve Subject.Roles (repeatable or
                             space-separated; --expect-roles "" declares the empty set)
  --expect-no-roles          declare the minted token MUST NOT carry a non-empty roles claim —
                             the attainable client-credentials pin: roles arrive only on
                             authcode/device/refresh paths the sweep cannot drive (optional)
  -h, --help                 print this usage and exit 0

Roles notes:
  Server-side roles emission stays pinned by the infrastructure/defaultimpl
  issue_payload tests (TestTenantRoles_ClaimsPerIssuer). Because absence is
  tolerated, --expect-roles cannot detect a total loss of roles emission on a
  user path — the defaultimpl pin is the regression guard for that.
`)
}

// expectRolesFlag is the --expect-roles flag value: the declared roles set
// plus a presence bit. The bit separates `--expect-roles ""` (an active
// declaration of the empty set: any non-empty roles claim fails) from the
// flag being absent (roles are never asserted).
type expectRolesFlag struct {
	set     stringList
	present bool
}

func (f *expectRolesFlag) String() string { return f.set.String() }

func (f *expectRolesFlag) Set(v string) error {
	f.present = true
	return f.set.Set(v)
}

// stringList is a repeatable and space-separated string flag value
// (the tree's flag.Var precedent, e.g. entitiescmd's attrFlag).
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, strings.Fields(v)...)
	return nil
}

// effectiveAddr resolves the base URL exactly as apiclient.New does: the
// SSO_ADMIN_ADDR env value wins over the --addr flag; the flag defaults to
// DefaultAddr. Preflight validates the EFFECTIVE value so a bad env cannot
// bypass the fail-fast and a bad flag cannot exit 2 when a valid env value
// would have overridden it.
func effectiveAddr(flagAddr string) string {
	if v := os.Getenv(EnvAddr); v != "" {
		return v
	}
	return flagAddr
}

// validateBaseURL applies the fail-fast addr rules: absolute http(s) URL
// with a non-empty host, no userinfo (Go's transport would send embedded
// credentials as Basic auth), and no query/fragment (apiclient.Do
// concatenates base + path, so a query-bearing base fetches a different
// resource than intended). The returned error never echoes the input.
func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("not a valid absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("host is empty")
	}
	if u.User != nil {
		return errors.New("must not embed credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must not carry a query or fragment")
	}
	return nil
}

// validateAdvertisedURL applies the same URL rules to an advertised endpoint
// value (row-2 preflight). The returned error never echoes the raw value.
func validateAdvertisedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("not a valid absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("host is empty")
	}
	if u.User != nil {
		return errors.New("must not embed credentials")
	}
	return nil
}

// probeScope returns the T-8d probe scope: "sweep-probe-" + 12 crypto/rand
// alphanumerics. crypto/rand only — math/rand is runtime-seeded and seedable,
// and the scope's whole point is that no deployment can pre-register it. The
// value is never printed (stdout or stderr). io.ReadFull (not rand.Read:
// crypto/rand.Read never returns an error — it crashes) so a failure maps to
// a returnable error and exit 1, never a fallback.
func probeScope() (string, error) {
	buf := make([]byte, probeScopeLen)
	one := make([]byte, 1)
	for i := range buf {
		for {
			if _, err := io.ReadFull(rand.Reader, one); err != nil {
				return "", fmt.Errorf("generate probe scope: %w", err)
			}
			if one[0] < probeScopeLimit {
				break
			}
		}
		buf[i] = probeCharset[int(one[0])%len(probeCharset)]
	}
	return probeScopePrefix + string(buf), nil
}

// probeClient builds a token-less apiclient bound to an exact advertised
// URL. Credential-bearing probes use body credentials only; New's env
// fallbacks must never apply (SSO_ADMIN_TOKEN would make /token reject the
// request outright — a non-Basic Authorization header fails client auth —
// and SSO_ADMIN_ADDR would override the target).
func probeClient(target string) *Client {
	return &Client{
		baseURL: target,
		http: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: RejectRedirect,
		},
	}
}
