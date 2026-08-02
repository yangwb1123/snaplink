Design doc complete: `docs/auto/interfaces-sso-direction2-postgres-hotstore-design.md` (sibling of the spec). All claims were grounded in code before writing — I verified the SQLite consume/ledger/rotation statements, the oauthspi optional surface, the `runTx`/`serializable` retry helper, the session-store shared-pool precedent, the boot-gate branching precedent, and the exact consumer line numbers.

Structure — `##` per decision, each with the four requested sections:

**## Decision 1 — Postgres OAuth hot-store implementations**
- **API surface**: 4 new files in `package postgres` (fan-out capped at exactly 4 non-test files), `New*StoreWithDB(db, dialect)` constructors running per-namespace migrations, `DB()`/`Ping()`/`Close()` readiness trio, `*MaxVersion()` helpers. Constraint flagged: `session.go`'s `interfaces/sso` import is a frozen exemption — new files must import `oauthspi` only.
- **Storage model**: 4 namespaces, full-column baseline DDL (no sqlite backfill ladder), `DELETE ... RETURNING` atomic consume, ledger mirror wrapped in `runTx` (fail-closed — the one place a naive translation silently kills reuse detection), CRDB serializable retry for rotation.
- **Failure modes** + **what could break**: `?`→`$N` drift, pgx multi-statement rejection, orphaned ledger rows, CI test-DB availability.

**## Decision 2 — Optional-SPI parity**
- Full optional assertion set (`Inspector`/`SubjectIndex`/`Counter`/`ClientPurger`/`FamilyTracker`/`RotationLimiter`/`ExpiryLister`) + `SetLookupHMACKeys`, `oauth.postgres` config, guard test.
- Key finding captured: sqlite's `ListExpiring` thumbprints the *stored HMAC value*, not the raw token — parity means reproducing that exactly, and a "fix" would break the opaque-lookup invariant.

**## Decision 3 — Stock-binary surface closure**
- Builder signatures thread `pgDB`/`pgDialect`; schema gate branches per backend (the `CheckSQLiteSchema`-on-postgres false boot failure); backend-accurate ready-check names; `wireRefreshRotationGrace` postgres case with a `refresh_grace` namespace (BYTEA successor blob); HA-coherence lock test.

Plus a per-decision verification table and strict dependency order 1→2→3. One citation corrected post-write (`RefreshGraceStore` interface path/line).
