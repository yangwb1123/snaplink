Done. Committed as `f085bc13` and pushed. Summary of the work:

## 1. Design document (`docs/design/lifecycle-caep-events.md`)

Adjudicated all five required decisions:
- **Event types**: standard OpenID CAEP/RISC URIs only (no custom snaplink URI) — `risc/account-disabled` + `caep/session-revoked` for non-active targets (INVITED/SUSPENDED/INACTIVE/ARCHIVED/PURGED), `risc/account-enabled` for reactivation into ACTIVE, split via the domain's own `AllowsAuthentication` predicate. `sub_id` = `target_user` metadata; affected clients derive from the **tenant dimension** (`TenantUserStore.ListByUser` → `TenantScopedClientStore.ListByTenant`, never cross-tenant).
- **Wiring**: extended `mapAuditEvent` (the existing audit→SET broadcaster), not a bus reaction — evidence: `applyAuditSinkTaps` already taps the transmitter, `RecordTransition` already emits `admin_user_lifecycle_changed` for every admin/sweep transition, and the revoke reaction's store ops emit no mapped events (no double emission, proven by test).
- **Failure modes**: fail-open via the existing `caep_broadcast_failed` path; resolution failures → no receivers; async delivery never blocks the transition.
- **Boundaries**: CAEP receive side untouched, `lifecyclereactions` untouched, no wire config keys (only the SDK option `caep.WithTenantUserStore`), zero exemptions, no new upward dependency (`protocols/caep → domains/userlifecycle` is downward).
- **Acceptance assertions** all testable.

## 2. Implementation
- `event_mapper.go`: `scopeUser` + `mapLifecycleChanged` (reads `MetaTargetUser`/`MetaToState` from the domain's own constants)
- `broadcaster.go`/`broadcaster_retry.go`: `tenants` field + `WithTenantUserStore` + `resolveLifecycleClients` (per-tenant fail-open, dedup); `resolveClients` relocated to stay within the 500-line budget
- `security_event_token.go`: `EventURIRISCAccountEnabled`; `receiver.go`: advertised in `DefaultSSFSupportedEvents`

## 3. Tests (none skipped)
- `protocols/caep/transmitter_lifecycle_test.go` — 6 unit tests: signed-SET delivery, tenant isolation, account-enabled on reactivation, fail-open + failure audit, unscoped-silent cases, and bus→transmitter single-emission
- `test/lifecycle_caep_e2e_test.go` — 3 full-composition integration tests: affected client receives exactly one JWKS-verifiable SET, sweep-driven transition emits, delivery-failure fail-open

## 4. Verification (all run, all pass)
```
go build ./... && go vet ./...                                PASS
go test ./protocols/caep/... ./domains/userlifecycle/...      ok (4 packages)
  ./protocols/lifecyclereactions/... -count=1
go test ./test/ -run 'Lifecycle|CAEP|SSF' -count=1            ok (14 tests)
go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .   ok
```
Plus `-race` on the changed packages and the full `interfaces/sso` package.

## 5. Docs sync
`feature-matrix.md` lifecycle row, `CHANGELOG.md` Added, `deferred-backlog.md` boundary updated (future-work statement closed, stock-binary conservative-silence boundary documented).

Pre-existing campaign/batch-runner worktree changes were left uncommitted as required.
