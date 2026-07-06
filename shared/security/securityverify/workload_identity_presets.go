package securityverify

import (
	"errors"
	"fmt"
	"strings"
)

// Cloud workload-identity presets: GCP (metadata-server-issued OIDC ID
// tokens), AWS (operator-configured OIDC issuer — typically a per-EKS-
// cluster issuer, see below), and Azure (Azure AD Workload Identity
// Federation, tenant-scoped issuer/JWKS). All three share this ONE file
// (rather than one file per cloud) because shared/security/securityverify
// sits at its 10-non-test-file directory-fanout ceiling
// (directory_fanout_test.go); a future fourth cloud preset should follow the
// SAME pattern — extend this file rather than opening an 11th one.
//
// --- GCP ---
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
// per-deployment discovery step is needed, unlike AWS (below) or Azure
// (per-tenant issuer — still a documented follow-up, see workload_identity.go).
//
// --- AWS ---
//
// AWS has no single stable, globally-published JWKS the way GCP does. What
// an operator actually presents here is typically a Kubernetes bound
// service-account token from an EKS cluster — the SAME token IRSA /
// AssumeRoleWithWebIdentity consumes — but that token's issuer is the
// PER-CLUSTER EKS OIDC provider URL
// (`https://oidc.eks.<region>.amazonaws.com/id/<cluster-id>`), which the AWS
// account administrator registers as an IAM OIDC identity provider. There is
// no fixed, hardcoded issuer this package can bake in the way GCPIssuer is;
// instead the operator supplies THEIR cluster's (or any other AWS-trusted
// OIDC provider's) issuer URL, and NewAWSWorkloadIdentityValidator derives
// the JWKS URL from it via the standard OIDC discovery convention every EKS
// (and generic Kubernetes OIDC-federated) issuer publishes at:
// `<issuer>/.well-known/jwks.json`.
//
// --- Azure ---
//
// Azure AD Workload Identity Federation lets a workload (typically a
// Kubernetes pod using AKS Workload Identity, or any client presenting a
// federated-credential-exchanged token) authenticate as an Azure AD app
// registration / managed identity WITHOUT a client secret. The resulting
// token is an ordinary Azure AD v2.0-issued JWT: PER-TENANT issuer
// (`https://login.microsoftonline.com/<tenant>/v2.0`), with signing keys
// published at Azure AD's stable, tenant-scoped discovery convention
// (`https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys` — no
// separate discovery-DOCUMENT fetch needed, unlike a fully generic OIDC
// issuer; this is closer to GCP's fixed-URL simplicity than to AWS's
// per-cluster derivation). Because the issuer AND the JWKS URL are both
// templated on the SAME operator-supplied tenant id,
// NewAzureWorkloadIdentityValidator only needs that one input.

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

// awsWellKnownJWKSPathSuffix is the standard OIDC discovery convention every
// EKS (and generic Kubernetes OIDC-federated) issuer publishes its JWKS at —
// there is no separate discovery-document fetch, just this fixed suffix.
const awsWellKnownJWKSPathSuffix = "/.well-known/jwks.json"

// AWS-specific attribute keys, projected onto WorkloadIdentity.Attributes
// for audit/logging visibility. Not used in the /token security decision —
// only WorkloadIdentity.Subject is (see workload_identity.go). Named for the
// underlying Kubernetes bound-service-account-token claims (the
// `kubernetes.io` claim block) EKS and IRSA-consuming tokens carry, not an
// AWS-only wire shape.
const (
	AttrAWSNamespace          = "aws_eks_namespace"
	AttrAWSServiceAccountName = "aws_eks_service_account"
	AttrAWSServiceAccountUID  = "aws_eks_service_account_uid"
)

// NewAWSWorkloadIdentityValidator builds a WorkloadIdentityValidator preset
// for an operator-configured AWS-trusted OIDC issuer — typically a
// per-cluster EKS OIDC provider URL
// (`https://oidc.eks.<region>.amazonaws.com/id/<cluster-id>`), but any
// AWS-compatible OIDC provider URL works identically. Unlike GCP, AWS has no
// single stable global issuer to bake in, so issuer is REQUIRED and caller-
// supplied (see the package doc above).
//
// source supplies the verification JWKS; pass nil to derive it from issuer
// via the standard `<issuer>/.well-known/jwks.json` convention
// (NewHTTPJWKSSource(issuer+awsWellKnownJWKSPathSuffix)) — tests substitute
// an httptest-backed source pointed at a fake JWKS document instead of
// reaching the network.
func NewAWSWorkloadIdentityValidator(issuer string, source JWKSSource, opts ...WorkloadIdentityValidatorOption) (*WorkloadIdentityValidator, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	if issuer == "" {
		return nil, errors.New("workload_identity: aws issuer required")
	}
	if source == nil {
		source = NewHTTPJWKSSource(issuer + awsWellKnownJWKSPathSuffix)
	}
	return NewWorkloadIdentityValidator(string(CloudProviderAWS), issuer, source, awsClaimsMapper, opts...)
}

// awsClaimsMapper projects a verified EKS/IRSA-shaped bound service-account
// token's claims onto a WorkloadIdentity. `sub` — always
// "system:serviceaccount:<namespace>:<name>" for a Kubernetes bound
// service-account token — is the Subject an operator registers in
// Client.Attributes[AttrWorkloadIdentitySubject]: it is the stable identity
// the issuing cluster guarantees for that credential, unlike the nested
// `kubernetes.io.serviceaccount.uid` (rotates if the ServiceAccount object is
// recreated) or any AWS-side field (the raw token predates
// AssumeRoleWithWebIdentity and carries no AWS account information at all —
// see the package doc). The nested `kubernetes.io` claim block is optional:
// present for EKS/Kubernetes-issued bound tokens, but its absence alone
// isn't grounds to reject a `sub` that already parses as a valid
// service-account identity.
func awsClaimsMapper(claims map[string]any) (*WorkloadIdentity, error) {
	sub, _ := claims["sub"].(string)
	if !strings.HasPrefix(sub, "system:serviceaccount:") {
		return nil, errors.New("workload_identity: aws token missing/malformed system:serviceaccount sub")
	}

	id := &WorkloadIdentity{
		Subject:    sub,
		Attributes: map[string]string{},
	}
	awsKubernetesAttributes(claims, id)
	return id, nil
}

// awsKubernetesAttributes extracts the optional nested `kubernetes.io.*`
// claim block EKS/Kubernetes-issued bound service-account tokens carry,
// split out of awsClaimsMapper for the per-function line budget.
func awsKubernetesAttributes(claims map[string]any, id *WorkloadIdentity) {
	k8s, ok := claims["kubernetes.io"].(map[string]any)
	if !ok {
		return
	}
	if v, ok := k8s["namespace"].(string); ok && v != "" {
		id.Attributes[AttrAWSNamespace] = v
	}
	sa, ok := k8s["serviceaccount"].(map[string]any)
	if !ok {
		return
	}
	if v, ok := sa["name"].(string); ok && v != "" {
		id.Attributes[AttrAWSServiceAccountName] = v
	}
	if v, ok := sa["uid"].(string); ok && v != "" {
		id.Attributes[AttrAWSServiceAccountUID] = v
	}
}

// azureIssuerTemplate is the Azure AD v2.0 issuer shape; %s is the tenant id
// (a GUID, or a verified domain like "contoso.onmicrosoft.com").
const azureIssuerTemplate = "https://login.microsoftonline.com/%s/v2.0"

// azureJWKSURLTemplate is Azure AD's stable, tenant-scoped JWKS discovery
// endpoint convention for v2.0 tokens — a fixed URL shape, not something
// that needs a separate discovery-document fetch the way a fully generic
// OIDC issuer would.
const azureJWKSURLTemplate = "https://login.microsoftonline.com/%s/discovery/v2.0/keys"

// Azure-specific attribute keys, projected onto WorkloadIdentity.Attributes
// for audit/logging visibility. Not used in the /token security decision —
// only WorkloadIdentity.Subject is (see workload_identity.go).
const (
	AttrAzureTenantID = "azure_tenant_id"
	AttrAzureAppID    = "azure_app_id"
)

// NewAzureWorkloadIdentityValidator builds a WorkloadIdentityValidator preset
// for Azure AD Workload Identity Federation tokens. tenantID is the Azure AD
// tenant (a GUID, or a verified domain) the token MUST be issued from — it
// fixes BOTH the required `iss` and the JWKS fetch URL, since Azure AD v2.0
// publishes tenant-scoped signing keys at a stable, well-known URL (see the
// package doc above).
//
// source supplies the verification JWKS; pass nil to derive it from tenantID
// via azureJWKSURLTemplate (NewHTTPJWKSSource(...)) — tests substitute an
// httptest-backed source pointed at a fake JWKS document instead of reaching
// the network.
func NewAzureWorkloadIdentityValidator(tenantID string, source JWKSSource, opts ...WorkloadIdentityValidatorOption) (*WorkloadIdentityValidator, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("workload_identity: azure tenant id required")
	}
	issuer := fmt.Sprintf(azureIssuerTemplate, tenantID)
	if source == nil {
		source = NewHTTPJWKSSource(fmt.Sprintf(azureJWKSURLTemplate, tenantID))
	}
	return NewWorkloadIdentityValidator(string(CloudProviderAzure), issuer, source, azureClaimsMapper, opts...)
}

// azureClaimsMapper projects a verified Azure AD v2.0 token's claims onto a
// WorkloadIdentity. `oid` (the object id of the underlying service principal
// / managed identity) is the Subject an operator registers in
// Client.Attributes[AttrWorkloadIdentitySubject] — it is STABLE across
// app-registration renames, unlike `appid`/`azp` (the client id, which an
// operator could reassign to a different app) or `sub` (pairwise under Azure
// AD v2.0's default configuration, so it can differ per resource for the
// same identity).
func azureClaimsMapper(claims map[string]any) (*WorkloadIdentity, error) {
	oid, _ := claims["oid"].(string)
	if oid == "" {
		return nil, errors.New("workload_identity: azure token missing oid")
	}
	id := &WorkloadIdentity{
		Subject:    oid,
		Attributes: map[string]string{},
	}
	if tid, ok := claims["tid"].(string); ok && tid != "" {
		id.AccountID = tid
		id.Attributes[AttrAzureTenantID] = tid
	}
	if appid, ok := claims["appid"].(string); ok && appid != "" {
		id.Attributes[AttrAzureAppID] = appid
	}
	return id, nil
}
