# Design: explicit Operator config-baseline rollback

Status: implemented in the current tree.

This is the bounded follow-up to
`docs/design/operator-config-apply.md`. It lets `SSOConfigDrift` drive the
existing declared-baseline rollback endpoint without turning the controller
into an automatic runtime-config remediation loop.

## Authority and trigger

Rollback occurs only when all of these are true in one successful reconcile:

1. `spec.rollback.enabled` is `true`;
2. `spec.rollback.reason` is non-empty;
3. `spec.rollback.expected_version_id` is non-empty;
4. annotation `sso.snaplink.io/rollback-approve: "true"` is present; and
5. the rollback target is Cluster B and the HTTP check completed successfully.

The expected version is a compare-and-swap guard. The server refuses the
request if Cluster B's current applied version is no longer that ID, so a
stale CR cannot roll back a newer human or controller change. The check and
rollback are separate operations; the check does not infer that a rollback is
needed. An operator or GitOps workflow must explicitly update the spec and
add the one-shot approval.

Apply and rollback approvals are mutually exclusive in one reconcile. The
controller refuses to issue either write when both are present. A successful
rollback consumes only the rollback annotation. Transport, 4xx, 5xx and
malformed responses keep the annotation and use the existing short retry;
status records the token-free outcome.

## Wire and storage contract

`ConfigRollbackRequest` adds optional `expected_version_id`. Omitting it keeps
the existing manual endpoint behavior. Supplying it requires the built-in
Memory/SQLite stores' atomic `RollbackIfCurrent` extension; a mismatch is
`409 config_apply_conflict` and changes nothing. The extension is optional so
custom `configaudit.Store` implementations remain source-compatible; the
conditional operator path returns `501 config_rollback_not_available` when a
backend cannot provide the atomic guard.

The CRD adds:

- `spec.rollback.enabled` and `spec.rollback.reason`;
- `spec.rollback.expected_version_id`; and
- `status.rollback.{state,lastAttemptAt,versionID,expectedVersionID,message}`.

The status is evidence only. The controller never stores a snapshot or bearer
token, and the rollback response remains the existing redacted baseline
response. The server audit event remains metadata-only.

## Explicit non-goals

- No automatic rollback based on drift, health, or a status field.
- No runtime configuration mutation; rollback changes the declared applied
  baseline only, exactly like the existing manual endpoint.
- No Git repository polling or source-of-truth resolution.
- No rollback while a config canary is observing.
