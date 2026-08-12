package scopecontract

import (
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/admin"
	commercehttp "github.com/yangwb1123/snaplink/interfaces/commerce"
	meteringhttp "github.com/yangwb1123/snaplink/interfaces/metering"
)

// Matrix pin (design acceptance row 6): the nine scope-matrix-v2 constants
// equal their four source files. Eight rows alias the source constants
// directly (structural pin at compile time); the audit relay row is a pinned
// literal (cmd/snaplink-billing owns it and must not be imported upward from
// interfaces) and is asserted here + against the billing default in test/.
func TestMatrixPinnedToSourceConstants(t *testing.T) {
	if ScopeAdminRead != commercehttp.ScopeAdminRead {
		t.Errorf("ScopeAdminRead = %q, want commerce.ScopeAdminRead %q", ScopeAdminRead, commercehttp.ScopeAdminRead)
	}
	if ScopeAdminWrite != commercehttp.ScopeAdminWrite {
		t.Errorf("ScopeAdminWrite = %q, want commerce.ScopeAdminWrite %q", ScopeAdminWrite, commercehttp.ScopeAdminWrite)
	}
	if ScopePaymentOrderRead != commercehttp.ScopePaymentOrderRead {
		t.Errorf("ScopePaymentOrderRead = %q, want commerce.ScopePaymentOrderRead %q", ScopePaymentOrderRead, commercehttp.ScopePaymentOrderRead)
	}
	if ScopePaymentWrite != commercehttp.ScopePaymentWrite {
		t.Errorf("ScopePaymentWrite = %q, want commerce.ScopePaymentWrite %q", ScopePaymentWrite, commercehttp.ScopePaymentWrite)
	}
	if ScopeCheckoutCreate != commercehttp.ScopeCheckoutCreate {
		t.Errorf("ScopeCheckoutCreate = %q, want commerce.ScopeCheckoutCreate %q", ScopeCheckoutCreate, commercehttp.ScopeCheckoutCreate)
	}
	if ScopeMeteringWrite != meteringhttp.ScopeMeteringWrite {
		t.Errorf("ScopeMeteringWrite = %q, want metering.ScopeMeteringWrite %q", ScopeMeteringWrite, meteringhttp.ScopeMeteringWrite)
	}
	if ScopeEntitlementRead != meteringhttp.ScopeEntitlementRead {
		t.Errorf("ScopeEntitlementRead = %q, want metering.ScopeEntitlementRead %q", ScopeEntitlementRead, meteringhttp.ScopeEntitlementRead)
	}
	if ScopeAdminWildcard != admin.Scope {
		t.Errorf("ScopeAdminWildcard = %q, want admin.Scope %q", ScopeAdminWildcard, admin.Scope)
	}
	if ScopeAuditEventWrite != "audit:event:write" {
		t.Errorf("ScopeAuditEventWrite = %q, want the pinned billing default literal", ScopeAuditEventWrite)
	}
}

// Matrix() returns exactly the nine scopes, deduplicated, in stable order.
func TestMatrixShape(t *testing.T) {
	got := Matrix()
	want := []string{
		"admin:read",
		"admin:write",
		"billing:payment:order:read",
		"billing:payment:write",
		"billing:checkout:create",
		"metering:write",
		"billing:entitlement:read",
		"audit:event:write",
		"admin:*",
	}
	if len(got) != len(want) {
		t.Fatalf("Matrix() = %v, want %v", got, want)
	}
	seen := map[string]bool{}
	for i, s := range got {
		if s != want[i] {
			t.Errorf("Matrix()[%d] = %q, want %q", i, s, want[i])
		}
		if seen[s] {
			t.Errorf("Matrix() duplicate %q", s)
		}
		seen[s] = true
	}
}
