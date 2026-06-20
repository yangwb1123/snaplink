// Package radiusauth implements a RADIUS authenticator for snaplink/sso as a
// SEPARATE nested Go module: this server authenticates a user against an
// external RADIUS server (the SSO acting as a RADIUS CLIENT), the integration
// for enterprises with RADIUS / Microsoft NPS-backed identity.
//
// # Why a separate module
//
// The RADIUS dependency (layeh.com/radius, the standard pure-Go RADIUS library)
// lives ONLY in this module's go.mod. The core sso module stays byte-free of it
// — the same firm zero-external-SDK invariant that isolates kms/awskms
// (aws-sdk-go-v2), redis (go-redis), saml (crewjam/saml), ldap
// (go-ldap/ldap/v3), and kerberos (gokrb5). An operator opts in by importing
// this module from their own forked cmd and wiring it via
// sso.WithAuthenticator / srv.RegisterAuthenticator; nothing in the core module
// imports it.
//
// # Architecture: importable root-typed authenticator (no package-main import)
//
// A separate module's package CANNOT import cmd's package main. So this module
// references no cmd type: it exposes its OWN importable constructor (New) that
// returns an *Authenticator implementing the root sso.Authenticator interface.
// The operator's fork registers it through the SAME seam the built-in
// authenticators use (sso.WithAuthenticator at construction, or
// srv.RegisterAuthenticator after). See doc.go for copy-pasteable wiring.
//
// # Security posture
//
// RADIUS authentication is a credential gate; the relevant pitfalls are USER
// ENUMERATION and a forged / unauthenticated server reply.
//
//   - Enumeration: a RADIUS server returns Access-Reject for BOTH an unknown
//     user AND a wrong password — it never distinguishes the two. The
//     authenticator preserves that by collapsing EVERY Access-Reject into the
//     single generic ErrAuthFailed, so no probe can tell "no such user" from
//     "wrong password" by the error. An operational failure that is NOT a
//     credential verdict (timeout, server unreachable, a non-authentic reply)
//     returns the DISTINCT ErrServerUnavailable — which is independent of
//     whether the user exists, so it leaks no enumeration signal either.
//   - Empty password: rejected BEFORE any exchange (no anonymous bypass) —
//     mirrors the password / LDAP authenticators' identical up-front guard.
//   - Shared secret: the trust anchor. layeh encrypts the PAP User-Password
//     with it and VALIDATES the server's Response Authenticator with it on every
//     reply, so a forged Access-Accept produced without the secret is rejected
//     (it surfaces as ErrServerUnavailable, never a false-positive login). The
//     secret is never logged and never placed on the AuthResult.
//   - Bounded: a per-request timeout + bounded retransmits cap a slow/dead
//     server so it cannot hang a login.
package radiusauth

import (
	"context"
	"errors"

	"github.com/snaplink/sso/interfaces/sso"
)

// AuthMethodRADIUS is the AMR value stamped on AuthResult.AuthMethods for a user
// authenticated against the RADIUS server. Relying parties read it for step-up
// / ACR/AMR decisions (RFC 8176 has no registered "radius" value; this is the
// project's RADIUS-auth tag, analogous to the built-in authenticators'
// AuthMethod* tags and the ldap authenticator's "ldap").
const AuthMethodRADIUS = "radius"

// ErrAuthFailed is the SINGLE generic authentication failure returned for EVERY
// user-facing failure mode: an Access-Reject (whether the cause was an unknown
// user OR a wrong password — the RADIUS server returns Reject for both), or an
// empty/missing credential. Collapsing them into one error is the
// anti-enumeration contract (AGENTS.md §2) — no probe can distinguish "no such
// user" from "wrong password" by the error.
var ErrAuthFailed = errors.New("radius: authentication failed")

// ErrServerUnavailable wraps a non-verdict operational failure: the RADIUS
// server could not be reached, the request timed out, the RadSec/TLS handshake
// failed, or the server's reply was NOT authentic (failed the
// Response-Authenticator check — a forged or wrong-secret response). It is
// returned for conditions that are the OPERATOR's problem, not the END-USER's,
// and that do NOT depend on whether the supplied username exists — so it leaks
// no enumeration signal. Mirrors the ldap authenticator's
// ErrDirectoryUnavailable.
var ErrServerUnavailable = errors.New("radius: server unavailable")

// ErrCallbackNotApplicable is returned by Callback: RADIUS is DIRECT credential
// auth (like password / LDAP), not a redirect flow, so the generic
// /auth/callback code-exchange probe never applies.
var ErrCallbackNotApplicable = errors.New("radius: callback not applicable (direct credential auth, not a redirect flow)")

// Authenticator authenticates a username + password against one upstream RADIUS
// server (or failover set) by sending an RFC 2865 Access-Request and mapping
// the reply. It implements sso.Authenticator. Construct it with New; it is safe
// for concurrent use (it holds no per-request state — each Authenticate builds
// its own packet).
type Authenticator struct {
	cfg    Config
	exch   Exchanger
	logger logger
}

// logger is the minimal optional logging seam (mirrors spi.Logger's shape
// without importing it across the module boundary for one method). nil => silent.
// It is used ONLY to surface operational failures (unreachable server, RadSec
// handshake failure) for observability — NEVER to log credentials, the username
// at failure, or the outcome of a credential check (which would itself be an
// enumeration oracle in the logs).
type logger interface {
	Error(msg string, keysAndValues ...any)
}

// Option configures an Authenticator at construction.
type Option func(*Authenticator)

// WithLogger attaches an optional logger used ONLY to record operational
// failures (server unreachable, RadSec handshake failed) for observability. It
// never logs credentials, the username at failure, or the verdict of a
// credential check. nil — or not passing this option — keeps the authenticator
// silent.
func WithLogger(l logger) Option {
	return func(a *Authenticator) {
		if l != nil {
			a.logger = l
		}
	}
}

// WithExchanger overrides the stock layeh.com/radius exchanger with an
// operator-supplied one. This is the PUBLIC seam config.go's CHAP rejection
// points at: the stock radiusExchanger implements only PAP, so an operator who
// needs CHAP (or any other Access-Request construction) implements the narrow
// Exchanger interface and injects it here — Authenticate then routes every
// verdict through it instead of the built-in PAP path. A nil Exchanger is
// ignored (the stock one is kept), so passing it cannot accidentally disarm the
// authenticator. The tests in this package also use it to drive the in-process
// fake, keeping the seam exercised without a real RADIUS server.
func WithExchanger(e Exchanger) Option {
	return func(a *Authenticator) {
		if e != nil {
			a.exch = e
		}
	}
}

// New validates cfg and returns the authenticator. A construction error fails
// the operator's boot CLOSED — a credential-auth gate with no server, no shared
// secret, or an invalid RadSec posture must not start (see Config.Validate). It
// performs NO network I/O (the RADIUS server is contacted lazily, per
// Authenticate), so a server that is down at boot does not block startup; only
// the optional RadSec client certificate / CA (local material) is read.
func New(cfg Config, opts ...Option) (*Authenticator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	exch, err := newRadiusExchanger(cfg)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{cfg: cfg, exch: exch}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Name returns the configured authenticator name (the provider=<name> selector
// at /auth/login and the AuthResult.Provider value).
func (a *Authenticator) Name() string { return a.cfg.Name }

// LoginURL returns "" — RADIUS is direct credential auth, there is no IdP to
// redirect to (mirrors authenticators/password.go and the ldap authenticator).
// The login orchestrator treats the empty string as "no redirect" and drives
// the direct Authenticate path.
func (a *Authenticator) LoginURL(_ string) string { return "" }

// Callback is not applicable: RADIUS has no redirect/callback leg. Returns a
// typed error so callers distinguish "wrong authenticator for this flow" from a
// credential failure.
func (a *Authenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, ErrCallbackNotApplicable
}

// Authenticate validates the supplied username + password against the RADIUS
// server:
//
//  1. Reject an empty username/password up front (no anonymous bypass).
//  2. Send an RFC 2865 Access-Request (User-Name + PAP-encrypted User-Password +
//     NAS-Identifier) via the Exchanger, with failover across the configured
//     servers and a bounded per-request deadline.
//  3. Access-Accept => mint an AuthResult (ExternalID = username, Provider =
//     Name(), AuthMethods = ["radius"], Attributes = the configured reply
//     mapping).
//
// ANTI-ENUMERATION: an Access-Reject (unknown user OR wrong password — the
// server returns Reject for both) collapses to the SAME generic ErrAuthFailed;
// a transport/server failure (timeout, unreachable, non-authentic reply)
// returns the DISTINCT ErrServerUnavailable. Neither error reveals whether the
// username exists.
func (a *Authenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	username := req.Credential["username"]
	password := req.Credential["password"]
	if username == "" || password == "" {
		// An empty password is rejected up front and NEVER sent in an
		// Access-Request: it must not reach the server, where a permissive policy
		// could conceivably treat it as a bypass. This guard mirrors password.go's
		// and the ldap authenticator's identical up-front check. It returns the
		// SAME generic ErrAuthFailed as a real Reject, so "no password supplied" is
		// not distinguishable from "wrong password" either.
		return nil, ErrAuthFailed
	}

	accepted, attrs, err := a.exch.Exchange(ctx, username, password)
	if err != nil {
		// A TRANSPORT/operational failure (timeout, unreachable, forged/
		// non-authentic reply, RadSec handshake failure) is independent of whether
		// the user exists — a DISTINCT error, no enumeration signal. The underlying
		// cause is logged for operators (never the credentials), but the wire error
		// is the generic ErrServerUnavailable.
		a.logError("radius exchange failed", err)
		return nil, ErrServerUnavailable
	}
	if !accepted {
		// Access-Reject: the credential verdict. Unknown user and wrong password
		// are INDISTINGUISHABLE here (the server returned Reject for both), and we
		// deliberately do NOT inspect any Reply-Message to explain why — surfacing
		// that would be an oracle. One generic failure.
		return nil, ErrAuthFailed
	}

	// Access-Accept: build the result. ExternalID is the supplied username (the
	// stable RADIUS identity); a RADIUS Access-Accept carries no canonical user
	// id attribute, so the login name is the durable external id, exactly as an
	// operator expects to correlate against the RADIUS/NPS account.
	return &sso.AuthResult{
		ExternalID:  username,
		Provider:    a.cfg.Name,
		Attributes:  attrs,
		AuthMethods: []string{AuthMethodRADIUS},
	}, nil
}

func (a *Authenticator) logError(msg string, err error) {
	if a.logger != nil {
		a.logger.Error(msg, "error", err)
	}
}

// Interface guard: *Authenticator is a root sso.Authenticator — the exact seam
// sso.WithAuthenticator / srv.RegisterAuthenticator accept.
var _ sso.Authenticator = (*Authenticator)(nil)
