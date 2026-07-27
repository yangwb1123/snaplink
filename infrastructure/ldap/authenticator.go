// Package ldapauth implements an LDAP / Active Directory authenticator for
// snaplink/sso as a SEPARATE nested Go module: this server authenticates a
// user DIRECTLY against an enterprise LDAP/AD directory (the most common
// remaining enterprise federation method after SAML), via the secure
// SEARCH-THEN-BIND flow over TLS.
//
// # Why a separate module
//
// The LDAP dependency (github.com/go-ldap/ldap/v3 and its asn1-ber transitive
// dep) lives ONLY in this module's go.mod. The core sso module stays byte-free
// of it — the same firm zero-external-SDK invariant that isolates kms/awskms
// (aws-sdk-go-v2), redis (go-redis), and saml (crewjam/saml). An operator opts
// in by importing this module from their own forked cmd and wiring it via
// sso.WithAuthenticator / srv.RegisterAuthenticator; nothing in the core module
// imports it.
//
// # Architecture: importable root-typed authenticator (no package-main import)
//
// A separate module's package CANNOT import cmd's package main. So this module
// references no cmd type: it exposes its OWN importable constructor (New) that
// returns an *Authenticator implementing the root sso.Authenticator interface.
// The operator's fork registers it on the server through the SAME seam the
// built-in authenticators use (sso.WithAuthenticator at construction, or
// srv.RegisterAuthenticator after). See doc.go for copy-pasteable wiring.
//
// # Security posture
//
// LDAP authentication is a credential gate; the classic pitfalls are LDAP
// INJECTION and USER ENUMERATION.
//
//   - Injection: EVERY user-supplied value placed into a search filter (the
//     username, and the user DN in the group filter) is escaped with
//     ldap.EscapeFilter. The raw username is NEVER formatted into a filter. A
//     username like "*)(uid=*))(|(uid=*" is rendered inert by escaping, so it
//     cannot widen the query or match extra entries.
//   - Enumeration: an unknown user (search miss) is indistinguishable from a
//     wrong password — BOTH return the single generic ErrAuthFailed, and BOTH
//     pay a comparable timing cost (on a search miss the authenticator still
//     performs a DUMMY user bind so the bind-round-trip time an attacker would
//     measure is present whether or not the user exists). This mirrors the
//     password authenticator's cost-matched dummy bcrypt hash (§2: "unknown
//     password users hit a cost-matched dummy bcrypt hash").
//   - TLS: credentials travel only over TLS (ldaps:// or StartTLS); plaintext /
//     InsecureSkipVerify requires an explicit AllowInsecure dev opt-out.
//   - Credentials are never logged and never placed on the AuthResult.
package ldapauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// AuthMethodLDAP is the AMR value stamped on AuthResult.AuthMethods for a user
// authenticated against the directory. Relying parties read it for step-up /
// ACR/AMR decisions (RFC 8176 has no registered "ldap" value; this is the
// project's directory-auth tag, analogous to the built-in authenticators'
// AuthMethod* tags).
const AuthMethodLDAP = "ldap"

// ErrAuthFailed is the SINGLE generic authentication failure returned for
// EVERY user-facing failure mode: unknown user (search miss), wrong password,
// ambiguous match (>1 entry), or a malformed credential. Collapsing them into
// one error is the anti-enumeration contract (§2) — no probe can distinguish
// "no such user" from "wrong password" by the error. Operational failures that
// are NOT a credential verdict (TLS handshake failure, directory unreachable,
// service-account bind rejected) return a DISTINCT wrapped error so the
// operator can tell a misconfiguration from a bad login; those never leak the
// existence of a user.
var ErrAuthFailed = errors.New("ldap: authentication failed")

// ErrDirectoryUnavailable wraps a non-verdict operational failure: the
// directory could not be reached, the TLS upgrade failed, or the
// service-account (search) bind was rejected. It is returned for conditions
// that are the OPERATOR's problem, not the END-USER's, and that do not depend
// on whether the supplied username exists — so it leaks no enumeration signal.
var ErrDirectoryUnavailable = errors.New("ldap: directory unavailable")

// ErrCallbackNotApplicable is returned by Callback: LDAP is DIRECT credential
// auth (like password), not a redirect flow, so the generic /auth/callback
// code-exchange probe never applies. Mirrors password.go's "callback not
// supported".
var ErrCallbackNotApplicable = errors.New("ldap: callback not applicable (direct credential auth, not a redirect flow)")

// Authenticator authenticates a username + password against one upstream LDAP /
// Active Directory directory via search-then-bind over TLS. It implements
// sso.Authenticator. Construct it with New; it is safe for concurrent use (it
// holds no per-request state — each Authenticate dials its own connection).
type Authenticator struct {
	cfg    Config
	dialer dialer
	logger logger
}

// logger is the minimal optional logging seam (mirrors spi.Logger's shape
// without importing it across the module boundary for one method). nil ⇒
// silent. It is used ONLY to surface operational failures (unreachable
// directory, TLS failure) for observability — NEVER to log credentials or the
// outcome of a credential check (which would itself be an enumeration oracle in
// the logs).
type logger interface {
	Error(msg string, keysAndValues ...any)
}

// Option configures an Authenticator at construction.
type Option func(*Authenticator)

// WithLogger attaches an optional logger used ONLY to record operational
// failures (directory unreachable, TLS upgrade failed) for observability. It
// never logs credentials, usernames at failure, or the verdict of a credential
// check. nil — or not passing this option — keeps the authenticator silent.
func WithLogger(l logger) Option {
	return func(a *Authenticator) {
		if l != nil {
			a.logger = l
		}
	}
}

// withDialer overrides the production go-ldap dialer with a test fake. It is
// unexported: only tests in this package (which can construct the in-process
// fake directory) use it. Production code always gets the real ldapDialer.
func withDialer(d dialer) Option {
	return func(a *Authenticator) { a.dialer = d }
}

// New validates cfg and returns the authenticator. A construction error fails
// the operator's boot CLOSED — a directory-auth gate with an invalid TLS
// posture or a filter missing its placeholder must not start (see
// Config.Validate). It performs NO network I/O (the directory is contacted
// lazily, per Authenticate), so a directory that is down at boot does not block
// startup.
func New(cfg Config, opts ...Option) (*Authenticator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	a := &Authenticator{
		cfg:    cfg,
		dialer: &ldapDialer{requestTimeout: cfg.requestTimeout()},
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Name returns the configured authenticator name (the provider=<name> selector
// at /auth/login and the AuthResult.Provider value).
func (a *Authenticator) Name() string { return a.cfg.Name }

// LoginURL returns "" — LDAP is direct credential auth, there is no IdP to
// redirect to (mirrors authenticators/password.go). The login orchestrator
// treats the empty string as "no redirect" and drives the direct Authenticate
// path.
func (a *Authenticator) LoginURL(_ string) string { return "" }

// Callback is not applicable: LDAP has no redirect/callback leg. Returns a
// typed error so callers distinguish "wrong authenticator for this flow" from a
// credential failure (mirrors the SAML SP authenticator's not-applicable
// callback).
func (a *Authenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, ErrCallbackNotApplicable
}

// Authenticate validates the supplied username + password against the directory
// via search-then-bind:
//
//  1. Dial a directory URL (failover across cfg.URLs) and, for ldap:// +
//     StartTLS, upgrade to TLS BEFORE any bind.
//  2. Bind as the service account (or anonymous) — the SEARCH leg.
//  3. Search for the user with the configured filter, the username escaped via
//     ldap.EscapeFilter. Require EXACTLY ONE entry (0 or >1 ⇒ reject).
//  4. Bind as the found entry's DN with the supplied password — the VERIFY leg.
//     This is the actual credential check.
//  5. Read the configured attributes + group memberships and map them onto an
//     sso.AuthResult (ExternalID = the IDAttribute, Provider = Name(),
//     AuthMethods = ["ldap"]).
//
// ANTI-ENUMERATION: a search miss (unknown user) returns the SAME ErrAuthFailed
// as a wrong password AND still performs a dummy bind so the timing matches a
// real wrong-password attempt — an attacker cannot tell whether the username
// exists from either the error or the latency. See dummyBind.
func (a *Authenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	username := req.Credential["username"]
	password := req.Credential["password"]
	if username == "" || password == "" {
		// An empty password is rejected up front and NEVER sent as a bind: many
		// directories treat a bind with an empty password as an anonymous /
		// unauthenticated bind that SUCCEEDS (RFC 4513 §5.1.2), which would turn
		// "no password" into a false-positive login. This guard mirrors
		// password.go's identical up-front check.
		return nil, ErrAuthFailed
	}

	c, err := a.dial(ctx)
	if err != nil {
		// Dial / TLS failure is an operational condition independent of whether
		// the user exists — distinct error, no enumeration signal.
		a.logError("ldap dial failed", err)
		return nil, err // already wrapped as ErrDirectoryUnavailable by dial
	}
	defer func() { _ = c.Close() }()

	// (2) Service-account (or anonymous) bind for the search leg.
	if a.cfg.BindDN != "" {
		if err := c.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			// A rejected SERVICE bind is a misconfiguration (wrong service creds),
			// not an end-user verdict — distinct error. It is independent of the
			// supplied username, so it reveals nothing about user existence.
			a.logError("ldap service-account bind failed", err)
			return nil, fmt.Errorf("%w: service-account bind rejected", ErrDirectoryUnavailable)
		}
	}

	// (3) Locate the user entry. EscapeFilter neutralizes injection.
	entryDN, idValue, attrs, memberOf, err := a.searchUser(c, username)
	if err != nil {
		// Either a genuine search transport error, OR a "no such user" / ">1
		// match" that searchUser collapses to ErrAuthFailed. On the
		// ErrAuthFailed path we ALSO run a dummy bind so the timing matches a
		// real failed user bind — closing the enumeration timing side-channel.
		// We deliberately do NOT log on this path: it is the ordinary
		// per-request outcome of an unknown user or ambiguous match, and
		// logging it would just flood the operator's error log on every
		// wrong-password/unknown-user attempt.
		if errors.Is(err, ErrAuthFailed) {
			a.dummyBind(c, password)
		} else {
			// A genuine operational failure (search transport error/timeout),
			// independent of whether the user exists. Log it for observability
			// — mirroring the dial + service-account-bind logging above —
			// so a degraded/failing search path doesn't vanish silently while
			// dial/bind failures against the same directory are visible.
			a.logError("ldap search failed", err)
		}
		return nil, err
	}

	// (4) Verify leg: bind as the user's DN with the supplied password. THIS is
	// the credential check. A reused connection is fine — go-ldap rebinds it; we
	// have no further need for the service-account identity on this conn.
	if err := c.Bind(entryDN, password); err != nil {
		// Wrong password (or a disabled/locked account the directory rejects at
		// bind) collapses to the SAME generic error as an unknown user. We do
		// NOT inspect the LDAP result code to distinguish e.g.
		// "invalid credentials" from "account locked": surfacing that would be an
		// oracle. Detail is available to operators via directory-side logs, not
		// our wire error.
		return nil, ErrAuthFailed
	}

	// (5) Build the result. ExternalID falls back to the entry DN if the
	// configured ID attribute was absent, so it is never empty.
	externalID := idValue
	if externalID == "" {
		externalID = entryDN
	}
	result := &sso.AuthResult{
		ExternalID:  externalID,
		Provider:    a.cfg.Name,
		Attributes:  attrs,
		AuthMethods: []string{AuthMethodLDAP},
	}

	// Group resolution is best-effort: a group lookup failure must not deny an
	// otherwise-valid login (the credential already verified). It is logged but
	// not fatal — groups are authorization context, not the authentication
	// verdict.
	groups, gErr := a.resolveGroups(c, entryDN, username, memberOf)
	if gErr != nil {
		a.logError("ldap group resolution failed", gErr)
	} else if len(groups) > 0 {
		if result.Attributes == nil {
			result.Attributes = map[string]string{}
		}
		result.Attributes[groupsAttributeKey] = joinGroups(groups)
	}

	return result, nil
}

// dial connects to the first directory URL that dials successfully (failover),
// applying StartTLS on ldap:// connections before returning. Every failure
// path returns ErrDirectoryUnavailable (an operational, non-enumerating error).
func (a *Authenticator) dial(ctx context.Context) (conn, error) {
	timeout := a.cfg.dialTimeout()
	var lastErr error
	for _, rawURL := range a.cfg.URLs {
		// Honor a cancelled/expired request context between failover attempts so
		// a client that gave up doesn't drive a long walk through every URL.
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDirectoryUnavailable, err)
		}

		host, tlsCfg, err := a.dialTLSConfig(rawURL)
		if err != nil {
			lastErr = err
			continue
		}
		c, err := a.dialer.Dial(rawURL, timeout, tlsCfg)
		if err != nil {
			lastErr = err
			continue
		}

		// ldap:// + StartTLS: upgrade BEFORE any bind so no credential ever
		// crosses the wire in plaintext. A StartTLS failure aborts THIS URL (we
		// must never fall through to a plaintext bind). Bounded by the SAME
		// dial timeout as the connect itself: go-ldap's own per-operation
		// SetTimeout does not cover the raw TLS handshake StartTLS performs
		// (see startTLSWithTimeout), so without this an unresponsive peer past
		// the StartTLS extended-op response could hang the login indefinitely.
		if a.cfg.StartTLS {
			if err := startTLSWithTimeout(c, tlsCfg, timeout); err != nil {
				_ = c.Close()
				lastErr = fmt.Errorf("StartTLS: %w", err)
				continue
			}
			_ = host // host already folded into tlsCfg.ServerName
		}
		return c, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no URLs configured")
	}
	return nil, fmt.Errorf("%w: %v", ErrDirectoryUnavailable, lastErr)
}

// dialTLSConfig resolves the per-URL TLS config (and the host used for SNI /
// verification). For ldap:// without StartTLS and without AllowInsecure this
// would have been rejected at Validate, so here a plaintext path implies the
// operator opted in.
func (a *Authenticator) dialTLSConfig(rawURL string) (host string, tlsCfg *tls.Config, err error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", nil, fmt.Errorf("ldap: parse URL %q: %w", rawURL, err)
	}
	host = u.Hostname()
	// TLS config is needed for ldaps:// (dial-time handshake) and for StartTLS
	// (post-dial upgrade). For a plain ldap:// without StartTLS it is unused.
	needTLS := strings.EqualFold(u.Scheme, "ldaps") || a.cfg.StartTLS
	if !needTLS {
		return host, nil, nil
	}
	tlsCfg, err = a.cfg.tlsConfig(host)
	if err != nil {
		return "", nil, err
	}
	return host, tlsCfg, nil
}

func (a *Authenticator) logError(msg string, err error) {
	if a.logger != nil {
		a.logger.Error(msg, "error", err)
	}
}

// Interface guard: *Authenticator is a root sso.Authenticator — the exact seam
// sso.WithAuthenticator / srv.RegisterAuthenticator accept.
var _ sso.Authenticator = (*Authenticator)(nil)
