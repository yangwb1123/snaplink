// Command sso-operator is a Kubernetes controller for the SSOConfigDrift
// custom resource — a K8s-native wrapper around this SDK's existing
// cross-cluster config-diff HTTP primitive
// (platform/configaudit.HandleClusterDiff, exposed as
// POST /api/v1/admin/config/cluster-diff), so a fleet operator can express
// "compare cluster A's running config against cluster B" declaratively
// (`kubectl apply -f my-drift-check.yaml`) instead of scripting the two
// HTTP calls by hand.
//
// # What it does
//
// For each SSOConfigDrift object, on the configured PollInterval (default
// 5m):
//
//  1. Resolve both clusters' admin:read bearer tokens from the Secrets
//     referenced by Spec.ClusterA/ClusterB.BearerSecretRef (same namespace
//     as the CR).
//  2. GET ClusterA.BaseURL + "/api/v1/admin/config/running", extract the
//     "running" field.
//  3. POST that snapshot as {"snapshot": ...} to
//     ClusterB.BaseURL + "/api/v1/admin/config/cluster-diff".
//  4. Write the result into Status: DriftDetected (patch non-empty),
//     PatchOpCount (len(patch)), LastCheckedAt, and a human-readable
//     Message — either a drift/no-drift summary or the last error's text.
//
// An operator reads the result with:
//
//	kubectl get ssoconfigdrift <name> -o yaml
//	kubectl describe ssoconfigdrift <name>
//
// # What it deliberately does NOT do
//
//   - NO config apply. Nothing in this binary ever issues a write request
//     against either cluster's admin API. The two HTTP calls it makes are
//     both read-only from ClusterA's perspective and diff-only (not
//     apply) from ClusterB's — cluster-diff computes and returns a patch,
//     it does not apply one.
//   - NO canary rollout. There is no concept here of gradually shifting
//     traffic or config between replicas/clusters.
//   - NO auto-remediation. A detected drift is reported, never acted on.
//     There is no "reconcile ClusterB to match ClusterA" behavior, on a
//     timer or otherwise.
//   - NO GitOps reconciler. This does not read desired state from a Git
//     repo and push it to a cluster; it only compares two ALREADY-RUNNING
//     clusters against each other.
//
// This is a bounded, read-only slice of the broader "declarative
// multi-cluster config governance" backlog item — see
// docs/deferred-backlog.md in the parent repo for the full picture of what
// remains out of scope and why.
//
// # Fail-open philosophy
//
// Every HTTP or Secret-lookup failure sets Status.Message to a
// (token-free) error summary and requeues quickly (see
// controller.shortRequeueInterval) rather than failing the
// reconcile permanently or blocking anything — this mirrors
// platform/configaudit/drift.go's own report-only, never-blocks
// observability design in the parent SSO module. Status.DriftDetected and
// Status.PatchOpCount are left UNCHANGED on a failed attempt: a transient
// HTTP error is evidence of nothing, so the last known-good comparison
// result is preserved rather than reset to a false "no drift".
//
// Bearer tokens are read from Secrets and used only in the Authorization
// header of the two outbound requests — they are NEVER written into
// Status, logged, or otherwise persisted anywhere this controller
// touches.
//
// # Trust model — RBAC precondition (read before deploying)
//
// A SSOConfigDrift's Spec directly names a Secret (BearerSecretRef) and a
// destination (BaseURL) for that Secret's value. This controller enforces
// two things itself: BaseURL MUST be https:// (validateBaseURL rejects
// plain http, so a token can never reach the wire unencrypted regardless
// of what a CR names), and BearerSecretRef can only ever resolve a Secret
// in the CR's OWN namespace (corev1.SecretKeySelector has no cross-
// namespace field). It does NOT enforce, and cannot enforce from inside a
// single reconcile, that the Secret named is "meant for" this feature —
// this is the same trust model every core Kubernetes resource that
// references a same-namespace Secret by name uses (a Pod's
// envFrom.secretKeyRef, an Ingress's TLS secretName, ...): whoever can
// create/update a SSOConfigDrift can cause the controller's own
// ServiceAccount (which needs `get` on Secrets in-namespace to serve ANY
// legitimate CR) to read and forward ANY Secret in that namespace to
// whatever https:// host BaseURL names.
//
// Operators MUST therefore scope RBAC so that write access to
// SSOConfigDrift (create/update/patch) is granted to NO WIDER a set of
// principals than read access to Secrets in the same namespace — do not
// assume "can write CRs" is a lesser privilege than "can read Secrets".
// If your cluster's RBAC already treats these as separate privilege
// tiers, deploy this controller (and grant Secret-read to its
// ServiceAccount) only in namespaces where the two tiers coincide, or
// place the drift-check Secrets in a DEDICATED namespace this
// ServiceAccount is scoped to rather than the namespace where broader
// application Secrets live.
//
// # A natural next step (not built here)
//
// A future "apply" mode would need: (a) an explicit opt-in field on the
// spec (e.g. Spec.AutoApply bool, defaulting false, so existing CRs never
// silently start writing), (b) a call to a NEW write-capable endpoint on
// ClusterB (cluster-diff itself stays read-only by design — see its own
// doc comment in platform/configaudit/handlers.go), (c) a canary/rollout
// strategy (percentage of config keys, or a staged multi-cluster order)
// living in its own CRD or Spec sub-struct, and (d) an audit trail
// distinguishing "detected" from "applied" events. None of that is
// present in this package; SSOConfigDrift's Status has no field that
// could even represent "applied" today, which is intentional — it keeps
// this slice honestly read-only rather than half-wiring a write path
// nobody asked to review yet.
package main
