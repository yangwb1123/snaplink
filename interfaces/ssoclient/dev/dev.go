// Package dev provides in-process stub implementations of the
// ssoclient.{AuthClient, AuthzClient, AuditClient} interfaces for
// LOCAL DEVELOPMENT ONLY.
//
// The stubs do not talk to a real sso-server. ValidateToken always
// succeeds (returning a configurable fake Subject), Check always
// returns true by default, and audit Record is a no-op. Business
// code that depends on the ssoclient interfaces can run end-to-end
// without standing up the SSO backend — useful for iterating on
// UI, running integration tests against in-process domain logic,
// and onboarding new developers.
//
// # Safety
//
// Every constructor in this package emits a single stderr warning
// on first call per process so accidental production use is loud.
// The warning includes the constructor name so grepping the logs
// makes it obvious which surface area is bypassed.
//
// To silence the warning (for tests of the dev package itself, or
// CI runs that intentionally use it), pass [WithSilent] to any
// constructor.
//
// # Wiring example
//
//	var (
//	    auth ssoclient.AuthClient
//	    az   ssoclient.AuthzClient
//	)
//	if devMode {
//	    auth = dev.NewAuthClient(dev.WithUserID("dev-001"))
//	    az   = dev.NewAuthzClient(dev.WithPermissions("billing:*"))
//	} else {
//	    auth, _ = remote.NewAuthClient(ctx, serverURL)
//	    az,   _ = remote.NewAuthzClient(ctx, serverURL)
//	}
//	// rest of business code uses auth / az without knowing which.
package dev

import (
	"fmt"
	"os"
	"sync"
)

// commonOption is shared by the per-client Option types. The dev
// package's options are tiny enough that one common shape covers
// them without inflating the API.
type commonOption struct {
	silent bool
}

// Option mutates the AuthClient at construction.
type Option func(*authConfig)

// AuthzOption mutates the AuthzClient at construction.
type AuthzOption func(*authzConfig)

// AuditOption mutates the AuditClient at construction.
type AuditOption func(*auditConfig)

// WithSilent suppresses the one-time stderr "dev mode active"
// warning. Intended for tests of this package + CI runs that
// intentionally use dev clients. Production wiring should leave
// the warning on so accidental dev-in-prod is noisy.
func WithSilent() Option           { return func(c *authConfig) { c.silent = true } }
func WithSilentAuthz() AuthzOption { return func(c *authzConfig) { c.silent = true } }
func WithSilentAudit() AuditOption { return func(c *auditConfig) { c.silent = true } }

// warned tracks whether the per-process startup banner has fired.
// Each constructor calls warnOnce.Do once on first non-silent build,
// so a process using multiple dev clients still prints exactly one
// banner.
var (
	warnOnce sync.Once
)

// warn emits the startup banner. Idempotent; silent constructors
// can suppress by not calling it.
func warn(ctor string) {
	warnOnce.Do(func() {
		fmt.Fprintf(os.Stderr,
			"⚠️  ssoclient/dev: AUTH BYPASS ACTIVE — %s constructed. DO NOT USE IN PRODUCTION.\n",
			ctor,
		)
	})
}
