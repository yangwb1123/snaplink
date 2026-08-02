Spec complete: `docs/auto/interfaces-sso-direction2-postgres-hotstore-spec.md`

## Summary

I verified the 方向二 claim against the code, then produced a 3-decision requirements spec, each with name, problem, evidence (file/symbol), proposed behavior, and acceptance check. Key verification findings:

**Gap confirmed**: `oauth.backend` dispatch (`serverbuildstore/build_oauth_stores.go`) only handles `memory|sqlite|redis`; `infrastructure/postgres/` has zero OAuth hot stores; `docs/config-reference.md:100` is asymmetric with `identity.session_backend` (line 99, already postgres-capable). The postgres hot-store template already exists — `infrastructure/postgres/session.go` (`NewSessionManagerWithDB` + per-namespace `Run`).

## The 3 decisions

1. **Postgres implementations of the four OAuth hot-store SPIs** — new `auth_code.go` / `refresh_token.go` / `device_code.go` / `par.go` in `infrastructure/postgres`, translating the SQLite `DELETE ... RETURNING` atomic-consume semantics (verified at `sqlite/auth_codes.go:303-320` etc.), family ledger, and reuse detection; shared-pool constructors per the session-store precedent. `interfaces/sso` stays frozen (60-file ceiling) — `WithAuthCodeStore(store oauth.AuthCodeStore, ...)` accepts any implementation.

2. **Optional-SPI and opaque-lookup parity** — the postgres refresh store must implement `RefreshTokenSubjectIndex`/`ClientPurger`/`FamilyTracker`/`RotationLimiter`/`ExpiryLister` + `SetLookupHMACKeys`, because `interfaces/sso` consumes them via type assertion (`server_tenant.go:169` tenant-suspension purge, `sso.go:375` governance, `build_app_oauth.go:245-247` GDPR erasure) — omitting them silently degrades shipped features, the worst failure mode for a "first-class" backend.

3. **Stock-binary surface closure** — `case "postgres"` in all four builders (loud `errPostgresNotConfigured`-style failure), schema boot-gate branching (`CheckSQLiteSchema` would falsely fail on a postgres pool; precedent `checkIdentityLinkSchema` at `build_stores.go:403-410`), `rotation_grace_backend=postgres` (currently rejected at `build_app_oauth.go:257-300`), docs enum updates, and HA-coherence test locking.

Dependency order 1→2→3, each gated by `go build/vet`, maintainability/architecture tests, `-race`, E2E, and `make ci`.
