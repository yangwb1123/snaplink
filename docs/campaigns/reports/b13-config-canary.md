# B13-R2-C config canary

Status: implemented.

Delivered:

- `POST /api/v1/admin/config/apply?approve=true&canary=true&window=60s`
  with a bounded `1s`–`24h` window and unchanged non-canary behavior.
- Atomic `observing → confirmed|rolled_back` state for Memory and SQLite;
  SQLite migration v3 persists the state beside the applied-version chain.
- Existing `StorageHealthSource` ports are adapted in the composition root;
  definitive unhealthy results roll back, unknown/deadline results fail open,
  and a process restart rolls back an interrupted observation before resuming.
- Concurrent apply/rollback is rejected while observing; rollback refuses to
  touch a newer applied version.
- `config_canary_started`, `config_canary_confirmed`, and
  `config_canary_rolled_back` audit events use metadata-only evidence.
- OpenAPI, error codes, configuration reference, feature matrix, changelog,
  deferred backlog, and the design decision are synchronized.

Verification:

- `go build ./... && go vet ./...` — passed.
- `go test ./platform/configaudit/... -count=1` — passed.
- `go test ./interfaces/sso/... -run 'Config' -count=1` — passed.
- `go test ./...` — passed.
- `go test ./... -race` — passed.
- `python3 cli.py check-routes` — passed (243 runtime routes / 350 documented
  operations).
- `python3 cli.py sdk-surface check` — passed.
- `go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .`
  — passed.

The repository-wide `make ci` remains blocked at its pre-existing format gate:
`shared/core/invitation.go` is dirty and unformatted. It was not changed by
this task because it is unrelated user work.
