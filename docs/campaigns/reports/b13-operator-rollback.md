# Operator config-baseline rollback

Status: implemented.

Delivered:

- `SSOConfigDrift` accepts an explicit rollback spec and one-shot approval
  annotation; apply and rollback approvals are mutually exclusive.
- The controller sends `POST /api/v1/admin/config/rollback?approve=true` with
  `reason` and `expected_version_id`, consumes approval only after success,
  and records token-free `status.rollback` outcomes.
- Memory and SQLite stores expose atomic `RollbackIfCurrent`; stale versions
  return `409 config_apply_conflict` without changing the baseline.
- Custom stores that do not implement the conditional extension return
  `501 config_rollback_not_available` for the guarded path; the existing
  unguarded manual endpoint remains source-compatible.
- CRD schema, OpenAPI, error-code, config-reference, feature-matrix,
  changelog, roadmap, and design documents are synchronized.

Verification:

- `go build ./... && go vet ./...` — passed.
- `go test -run 'TestMaintainability_|TestArchitecture_' .` — passed.
- `go test ./platform/configaudit/... -count=1` — passed.
- `go test ./... -race` — passed.
- `go test ./cmd/sso-operator/...` in the nested module — passed.
- `python3 cli.py modules check` — passed.
- `python3 cli.py check-routes` and `python3 cli.py sdk-surface check` — passed.

The repository-wide `make ci` remains blocked at the pre-existing formatting
gate for the unrelated dirty `shared/core/invitation.go`; it was not changed.
