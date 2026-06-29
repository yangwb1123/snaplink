package admin

import (
	"testing"
)

// TestIsGatedGRPCMethod_DiscoveryMutations verifies that the discovery write
// mutations (Register, Deregister) require admin auth, while the discovery
// read operations (Discover, Watch) remain open for service-discovery clients
// that do not hold admin tokens. The existing admin/audit/netpolicy prefix
// gates must not regress.
func TestIsGatedGRPCMethod_DiscoveryMutations(t *testing.T) {
	gated := []string{
		// Discovery write mutations — the security fix.
		"/snaplink.discovery.v1.Discovery/Register",
		"/snaplink.discovery.v1.Discovery/Deregister",
		// Admin CRUD services — must remain gated.
		"/snaplink.admin.v1.UserAdminService/Delete",
		"/snaplink.admin.v1.ClientAdminService/Create",
		// Audit service — must remain gated.
		"/snaplink.audit.v1.AuditWriter/StreamEvents",
		// Netpolicy management — must remain gated.
		"/snaplink.netpolicy.v1.PolicyService/Apply",
	}
	for _, m := range gated {
		if !isGatedGRPCMethod(m) {
			t.Errorf("isGatedGRPCMethod(%q) = false, want true", m)
		}
	}

	open := []string{
		// Discovery read operations must remain open for service-mesh clients.
		"/snaplink.discovery.v1.Discovery/Discover",
		"/snaplink.discovery.v1.Discovery/Watch",
	}
	for _, m := range open {
		if isGatedGRPCMethod(m) {
			t.Errorf("isGatedGRPCMethod(%q) = true, want false", m)
		}
	}
}
