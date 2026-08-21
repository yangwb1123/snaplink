// Command sso-operator is a Kubernetes controller for the SSOConfigDrift
// custom resource — a K8s-native wrapper around this SDK's existing
// cross-cluster config-diff HTTP primitive
// (platform/configaudit.HandleClusterDiff, exposed as
// POST /api/v1/admin/config/cluster-diff), so a fleet operator can express
// "compare cluster A's running config against cluster B" declaratively
// (`kubectl apply -f my-drift-check.yaml`) instead of scripting the two
// HTTP calls by hand. For CRs that explicitly opt in AND carry a one-shot
// approval annotation, it can additionally drive the declared-baseline
// write endpoint (platform/configaudit.HandleApply, POST
// /api/v1/admin/config/apply) — see "Apply mode" below.
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
//  5. ONLY IF the CR opted in (Spec.Apply.Enabled) AND carries the
//     one-shot approval annotation (sso.snaplink.io/apply-approve: "true")
//     AND the diff was non-empty: POST the fetched snapshot to
//     ClusterB.BaseURL + "/api/v1/admin/config/apply?approve=true" with
//     its canonical sha256 digest and Spec.Apply.Reason, and record the
//     outcome in Status.Apply (state/versionID/digest/lastAttemptAt/
//     message). A successful apply consumes the annotation; a failed one
//     keeps it and requeues short, so a transient blip self-heals.
//
// An operator reads the result with:
//
//	kubectl get ssoconfigdrift <name> -o yaml
//	kubectl describe ssoconfigdrift <name>
//
// # What it deliberately does NOT do
//
//   - NO canary rollout. There is no concept here of gradually shifting
//     traffic or config between replicas/clusters.
//   - NO auto-remediation. Apply is one-shot and explicitly approved: it
//     records cluster B's declared applied-config baseline (the server
//     endpoint never mutates B's RUNNING config), and it never runs again
//     for the same approval — so this is not a "reconcile ClusterB to
//     match ClusterA" loop, on a timer or otherwise.
//   - NO GitOps reconciler. This does not read desired state from a Git
//     repo and push it to a cluster; it only compares two ALREADY-RUNNING
//     clusters against each other (and, when opted in and approved, writes
//     one declared baseline).
//   - NO automatic rollback. Explicit rollback is supported only through the
//     separately approved Spec.Rollback contract and an expected-version CAS
//     guard; the operator never infers rollback from drift or health.
//
// # Apply mode (opt-in, one-shot approval)
//
// The default — and the behavior for every CR that does not opt in — is
// byte-identical to the original report-only loop: nothing here issues a
// write against either cluster unless ALL of Spec.Apply.Enabled, the
// approval annotation, and a non-empty diff are present in the same
// reconcile. See docs/design/operator-config-apply.md for the full
// authority model:
//
//   - Opt-in is Spec.Apply.Enabled (declarative, default false). Changing
//     it bumps Generation, so it takes effect immediately.
//   - Approval is the annotation sso.snaplink.io/apply-approve: "true" —
//     transient, per-action state, never part of GitOps-desired-state. It
//     authorizes exactly ONE apply: the controller deletes it after a
//     successful apply, so no standing approval can ever cause repeated
//     applies. Because annotations do not bump Generation, an approval
//     takes effect on the next scheduled poll — apply rate ≤ 1 per
//     approval, latency ≤ PollInterval, by construction.
//   - Spec.Apply.Reason is the mandatory operator justification forwarded
//     to the server (a blank reason is refused both at CRD admission and
//     by the controller before any HTTP call).
//   - The snapshot the operator forwards is cluster A's running config AS
//     SERVED — already redacted by A's GET .../config/running — so the
//     apply body carries no secret-shaped values, and the operator never
//     persists it (Status.Apply.Digest is a hash, Status.Apply.Message is
//     the server's own error text or a version id).
//
// # Rollback mode (opt-in, one-shot approval, expected-version CAS)
//
// When Spec.Rollback.Enabled is true and the CR carries a non-empty reason,
// an expected current version, and the one-shot annotation
// sso.snaplink.io/rollback-approve: "true", the controller POSTs
// /api/v1/admin/config/rollback with the expected-version CAS guard. A
// successful rollback consumes that annotation and records the restored
// version in Status.Rollback; conflicts and other failures retain the
// approval for the short retry. Apply and rollback approvals cannot coexist
// in one reconcile.
//
// Honesty note: apply records B's applied-config baseline; it does not
// change B's running config, so the operator's drift report persists after
// an apply. Apply mode is for operators who have already converged B and
// want B's config-audit history to record A's config as the declared
// baseline — not a mechanism to clear the drift report.
//
// This is a bounded promotion of the broader "declarative multi-cluster
// config governance" backlog item — see docs/deferred-backlog.md in the
// parent repo for the full picture of what remains out of scope and why.
//
// # Fail-open philosophy
//
// Every HTTP or Secret-lookup failure sets Status.Message to a
// (token-free) error summary and requeues quickly (see
// controller.shortRequeueInterval) rather than failing the reconcile
// permanently or blocking anything — this mirrors
// platform/configaudit/drift.go's own report-only, never-blocks
// observability design in the parent SSO module. Status.DriftDetected and
// Status.PatchOpCount are left UNCHANGED on a failed attempt: a transient
// HTTP error is evidence of nothing, so the last known-good comparison
// result is preserved rather than reset to a false "no drift". An apply
// failure follows the same doctrine: it is recorded in Status.Apply
// (state/message) and never suppresses the drift report — a CR whose apply
// keeps failing is still a fully-functional drift reporter, and the
// approval stays pending so the next short requeue retries it.
//
// Bearer tokens are read from Secrets and used only in the Authorization
// header of the outbound requests — they are NEVER written into Status,
// logged, or otherwise persisted anywhere this controller touches.
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
// Apply mode adds one more consequence of that same boundary: whoever can
// set the approval annotation (or Spec.Apply.Enabled) can cause the
// controller to WRITE a declared baseline to B using B's token. Kubernetes
// RBAC has no per-annotation granularity, so the approval cannot be
// narrowed below CR-write — but it changes nothing about what the
// controller can DO (it already holds both tokens): it only gates whether
// a write is issued, and the server still independently requires
// admin:write + ?approve=true + a digest-verified snapshot + a reason.
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
// # Remaining next steps (not built here)
//
// Canary/rollout strategy (percentage of config keys, or a staged
// multi-cluster order) living in its own CRD or Spec sub-struct, and GitOps
// reconciliation of the declared baseline remain out of scope. Explicit
// rollback is implemented, but it is never automatic and still requires the
// expected-version CAS plus one-shot approval described above.
package main
