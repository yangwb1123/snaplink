package securityverify

import "errors"

// GCP workload-identity preset (metadata-server-issued OIDC ID tokens for
// GCE/GKE workloads).
//
// A workload running on a GCE instance (or in GKE, whether via the node's
// default service account or GKE Workload Identity) can call
//
//	GET /computeMetadata/v1/instance/service-accounts/<sa>/identity?audience=<aud>
//	Metadata-Flavor: Google
//
// against its own instance metadata server and receive back an OIDC ID
// token: an ordinary JWT, signed by GOOGLE (not the workload, not this
// server), whose `iss` is always "https://accounts.google.com" and whose
// signing keys are published at a single stable, globally-routable JWKS URL
// that never changes (only the keys inside it rotate). That stability is
// exactly what makes GCP a clean fit for NewWorkloadIdentityValidator: no
// per-deployment discovery step is needed, unlike Azure (per-tenant issuer)
// or AWS (no stable global endpoint at all — see workload_identity.go's
// package doc).

// GCPIssuer is Google's fixed OIDC issuer for metadata-server ID tokens.
// Every token this preset accepts MUST carry this exact `iss`.
const GCPIssuer = "https://accounts.google.com"

// GCPJWKSURL is Google's stable, well-known JWKS endpoint. It has held this
// exact URL for the lifetime of Google's OIDC support; only the keys served
// from it rotate.
const GCPJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

// GCP-specific attribute keys, projected onto WorkloadIdentity.Attributes
// for audit/logging visibility. Not used in the /token security decision —
// only WorkloadIdentity.Subject is (see workload_identity.go).
const (
	AttrGCPProjectID      = "gcp_project_id"
	AttrGCPServiceAccount = "gcp_service_account"
	AttrGCPInstanceName   = "gcp_instance_name"
	AttrGCPZone           = "gcp_zone"
)

// NewGCPWorkloadIdentityValidator builds a WorkloadIdentityValidator preset
// for GCP metadata-server-issued OIDC ID tokens. source supplies the
// verification JWKS; pass nil to use the real Google endpoint
// (NewHTTPJWKSSource(GCPJWKSURL)) — tests substitute an httptest-backed
// source pointed at a fake JWKS document instead of reaching the network.
func NewGCPWorkloadIdentityValidator(source JWKSSource, opts ...WorkloadIdentityValidatorOption) (*WorkloadIdentityValidator, error) {
	if source == nil {
		source = NewHTTPJWKSSource(GCPJWKSURL)
	}
	return NewWorkloadIdentityValidator(string(CloudProviderGCP), GCPIssuer, source, gcpClaimsMapper, opts...)
}

// gcpClaimsMapper projects a verified GCP ID token's claims onto a
// WorkloadIdentity. `email` (the calling service account) is the Subject an
// operator registers in Client.Attributes[AttrWorkloadIdentitySubject] —
// it's the stable identity GCP guarantees for a service-account-bound
// token, unlike `sub` (a numeric unique-id that's opaque to operators) or
// the GCE instance metadata (which describes the VM, not the credential).
// The GCE-specific nested claims (google.compute_engine.*) are optional:
// present for GCE/GKE-node-issued tokens, absent for some other metadata-
// identity callers, so their absence is not a validation failure.
func gcpClaimsMapper(claims map[string]any) (*WorkloadIdentity, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("workload_identity: gcp token missing sub")
	}
	email, _ := claims["email"].(string)
	subject := email
	if subject == "" {
		// Not every metadata-identity caller is service-account-bound; fall
		// back to the numeric sub so the token still maps to SOME stable
		// subject rather than being silently dropped.
		subject = sub
	}

	id := &WorkloadIdentity{
		Subject:    subject,
		Attributes: map[string]string{},
	}
	if email != "" {
		id.Attributes[AttrGCPServiceAccount] = email
	}
	gcpComputeEngineAttributes(claims, id)
	return id, nil
}

// gcpComputeEngineAttributes extracts the optional nested
// `google.compute_engine.*` claim block GCE/GKE-node tokens carry, split out
// of gcpClaimsMapper for the per-function line budget.
func gcpComputeEngineAttributes(claims map[string]any, id *WorkloadIdentity) {
	google, ok := claims["google"].(map[string]any)
	if !ok {
		return
	}
	ce, ok := google["compute_engine"].(map[string]any)
	if !ok {
		return
	}
	if v, ok := ce["project_id"].(string); ok && v != "" {
		id.AccountID = v
		id.Attributes[AttrGCPProjectID] = v
	}
	if v, ok := ce["instance_name"].(string); ok && v != "" {
		id.Attributes[AttrGCPInstanceName] = v
	}
	if v, ok := ce["zone"].(string); ok && v != "" {
		id.Attributes[AttrGCPZone] = v
	}
}
