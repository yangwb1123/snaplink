package security

import "testing"

// TestAWSAzureWorkloadIdentityValidatorsExposedViaSecurityPackage guards the
// aliases.go promise ("these aliases preserve the historical security.*
// import surface unchanged for every consumer") and the exact wiring recipe
// options_grants.go's own doc comment gives operators
// ("security.NewGCPWorkloadIdentityValidator and
// security.NewAWSWorkloadIdentityValidator ship today"): every cloud preset
// securityverify implements MUST be reachable through the security package
// alias surface, not only by reaching into shared/security/securityverify
// directly. GCP already worked (interfaces/sso wires it via
// security.NewGCPWorkloadIdentityValidator); AWS/Azure must too.
func TestAWSAzureWorkloadIdentityValidatorsExposedViaSecurityPackage(t *testing.T) {
	t.Parallel()

	if _, err := NewAWSWorkloadIdentityValidator("https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE", nil); err != nil {
		t.Fatalf("security.NewAWSWorkloadIdentityValidator: %v", err)
	}
	if _, err := NewAzureWorkloadIdentityValidator("11111111-1111-1111-1111-111111111111", nil); err != nil {
		t.Fatalf("security.NewAzureWorkloadIdentityValidator: %v", err)
	}

	// The claims-mapper attribute keys an operator reads back off a verified
	// WorkloadIdentity for audit/logging must also be reachable without an
	// import of securityverify (GCP's equivalents already are: AttrGCPProjectID
	// et al. in aliases.go).
	if AttrAWSNamespace == "" || AttrAWSServiceAccountName == "" || AttrAWSServiceAccountUID == "" {
		t.Error("AWS workload-identity attribute keys not aliased into the security package")
	}
	if AttrAzureTenantID == "" || AttrAzureAppID == "" {
		t.Error("Azure workload-identity attribute keys not aliased into the security package")
	}
}
