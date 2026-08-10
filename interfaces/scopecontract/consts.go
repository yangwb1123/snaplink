// Package scopecontract is the single source of the scope-matrix-v2 table
// (campaign B4-2): the nine tenant resource scopes the global scope registry
// (protocols/oauth/scoperegistry) registers by default. Composition packages
// (cmd/sso-server, test/) and interfaces/sso import this package to wire and
// pin the matrix; the registry itself receives the matrix as a constructor
// argument because protocols must not import interfaces.
//
// Eight of the nine constants alias their original owner packages, so the
// pin is structural (compile-time), not a test. The ninth,
// ScopeAuditEventWrite, is a documented literal: it lives in
// cmd/snaplink-billing/config.go (defaultAuditScope, exact-enforced at boot)
// which this package must not import (composition would be an upward edge);
// the test/ pin test asserts equality with the billing default.
package scopecontract

import (
	"github.com/yangwb1123/snaplink/interfaces/admin"
	commercehttp "github.com/yangwb1123/snaplink/interfaces/commerce"
	meteringhttp "github.com/yangwb1123/snaplink/interfaces/metering"
)

// Matrix returns the nine scope-matrix-v2 scopes, deduplicated. The same
// value the registry seeds; kept as a function so construction call sites
// cannot accidentally mutate a shared slice.
func Matrix() []string {
	return []string{
		ScopeAdminRead,
		ScopeAdminWrite,
		ScopePaymentOrderRead,
		ScopePaymentWrite,
		ScopeCheckoutCreate,
		ScopeMeteringWrite,
		ScopeEntitlementRead,
		ScopeAuditEventWrite,
		ScopeAdminWildcard,
	}
}

// Commerce matrix rows (interfaces/commerce/consts.go).
const (
	ScopeAdminRead        = commercehttp.ScopeAdminRead
	ScopeAdminWrite       = commercehttp.ScopeAdminWrite
	ScopePaymentOrderRead = commercehttp.ScopePaymentOrderRead
	ScopePaymentWrite     = commercehttp.ScopePaymentWrite
	ScopeCheckoutCreate   = commercehttp.ScopeCheckoutCreate
)

// Metering matrix rows (interfaces/metering/consts.go).
const (
	ScopeMeteringWrite   = meteringhttp.ScopeMeteringWrite
	ScopeEntitlementRead = meteringhttp.ScopeEntitlementRead
)

// ScopeAuditEventWrite is the audit-governance relay scope, pinned literal of
// cmd/snaplink-billing/config.go defaultAuditScope (composition-owned; see
// package doc).
const ScopeAuditEventWrite = "audit:event:write"

// ScopeAdminWildcard is the admin API wildcard permission
// (interfaces/admin/middleware.go). Registry semantics match
// permissions.Matches: "admin:*" registers every concrete "admin:..." scope.
const ScopeAdminWildcard = admin.Scope
