# AGENTS.md

Operational guide for AI agents. Follows [agents.md](https://agents.md). User instructions override conflicts. **§3 invariants are gates — violations are regressions.**

**Agent OS:** [BOOTSTRAP.md](docs/agent-os/BOOTSTRAP.md) (context) → [ARCHITECTURE.md](docs/agent-os/ARCHITECTURE.md) (package map) → [HARNESS.md](docs/agent-os/HARNESS.md) (gate spec) → [EVALUATION.md](docs/agent-os/EVALUATION.md) (acceptance criteria) → [CHECKS_REGISTRY.md](docs/agent-os/CHECKS_REGISTRY.md) (all checks) → [Skills](docs/skills/) (refactor patterns)

**Reference:** [Config](docs/config-reference.md) | [Features](docs/feature-matrix.md) | [Observability](docs/observability.md) | [Errors](docs/error-codes.md) | [OpenAPI](docs/openapi.yaml) | [ADRs](docs/adr/) | [Arch rules](.arch/rules.yaml) | [Prompts](.prompts/)

---

## 0. Engineering Principles (HARD GATES)

### 0.1 Code Budgets

| Metric | Limit | Violation Action |
|---|---|---|
| File lines (`.go`) | ≤ 500 | STOP feature. Run `skills/split-large-file.md` |
| Function lines | ≤ 50 | Extract sub-functions |
| Cyclomatic complexity | ≤ 15 | Run `skills/refactor-high-complexity.md` |
| If-nesting depth | ≤ 3 | Guard clauses / early return |
| Directory depth | ≤ 3 | Flatten (merge leaf dir into parent name); `gen/`, `ops/deploy/`, `testdata` exempt |
| Go files per dir | ≤ 10 | Split flat package into cohesive sub-packages (`package main` dirs first; library splits change import paths) |
| Subdirs per dir | ≤ 15 | Regroup leaf packages; see `directory_fanout_test.go` |

All budgets are committed gates (`maintainability_*_test.go`, `directory_fanout_test.go`, `maxdepth_test.go`); the per-file and per-function backlogs are now **zero** (extract/split, never re-exempt).

**Cardinal rule:** If your edit pushes a file OVER 500 lines, you MUST split first, then continue. Refactoring always outranks feature work (480+ line file you'll exceed → refactor pre-existing violation first).

### 0.2 Dependency Direction

Packages live under their architectural layer directory (the first path segment
IS the layer); imports point one-way toward the shared kernel — see
[DIRECTORY_MAP](docs/architecture/DIRECTORY_MAP.md), enforced by
`architecture_layer_test.go`.

```
interfaces/sso → protocols/oauth → shared/security → shared/core
interfaces/sso → protocols/oidc  → shared/security → shared/core
```

**Prohibits:** `protocols/oauth → protocols/oidc`, `protocols/oidc → protocols/oauth`, `cmd/ ← any`, and any upward (toward-interfaces) layer import.

### 0.3 Post-Edit Verification

After every `.go` change: `go build ./...` + `go vet ./...`, then the committed maintainability gates `go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...` — file ≤ 500 lines (`maintainability_budget_test.go`), function cyclomatic ≤ 15 and length ≤ 50 (`maintainability_complexity_test.go`), and dependency direction (`TestArchitecture_ImportBoundaries`). These run inside `make ci` (the `race` target), independent of the generative `make harness`. Fail-fast: fix before next task.

### 0.4 Root Directory Policy

Root only allows server composition files. No `*_handler.go`, `*_service.go`, `*_store.go`, `*_grant.go` in root.

**Allowed:** `sso.go`, `handler.go`, `handlers.go`, `server_*.go`, `mesh_authz.go`, `signing_key_aggregation.go`, `storage_health.go`, `accessors.go`, `aliases.go`, `options*.go`.

**Migration pattern:** Extract logic to pure functions in domain package → keep thin wrapper `(s *Server)` methods in root → update `Deps` interface if needed → `python cli.py check-root` passes.

**Target packages:** `oauth/`, `oidc/`, `security/`, `cluster/`, `tenant/`, `selfservice/`, `internal/auth/consent/`, `internal/auth/login/`, `internal/handler/`.

### 0.5 Prohibited Patterns

| Pattern | Do instead |
|---|---|
| `TODO: refactor later` | Refactor immediately |
| Appending to 490+ line file | Run `skills/refactor-large-file.md` first |
| `oidc/` importing `oauth/` | Route via `handlers.go` |
| `e.Metadata = map{...}` | Use `SetMeta(e, k, v)` only |
| Root file count > 15 non-exempt | Run `skills/hexagonal-extraction.md` |
| Business code in root | Run `skills/hexagonal-extraction.md` |
| Mocks where Memory* exists | Use real `MemoryProvider`/`MemorySink`/`memory.Registry` |

### 0.6 Adding New Feature Code (every new package/file MUST satisfy these)

Same layer/budget/import rules as existing code apply — GATES, not guidelines
(committed in `package archgate`: `architecture_layer_test`, `architecture_gate`,
`maxdepth_test`, `maintainability_*`). This is the pre-flight checklist; the
rules themselves are §0.1/§0.2, not restated here.

1. Place by responsibility under its layer dir (§0.2, ARCHITECTURE.md) — extend an existing package, don't proliferate a new one for a one-off.
2. Imports point DOWN only, toward `shared/core` — never add a `layerExemptions` entry.
3. Directory depth ≤ 3 (§0.1) — flatten a new backend/variant into the parent name (`webauthnsqlite`, `encryptionaesgcm`), don't nest a 4th level.
4. File ≤ 500 / function ≤ 50 / cyclo ≤ 15 (§0.1) — SPLIT FIRST if your edit would breach; the near-budget files (e.g. `protocols/oauth/handle_register.go` at 500) must be split before adding to them.
5. NEVER add a new maintainability exemption to grandfather your own violation — `maxCycloExemptions`/`maxFuncLenExemptions`/`maxFileSizeExemptions` are count-capped and shrink-only; adding one fails the build.
6. Classify any new top-level (or `internal/`) package in `layerName()` (`architecture_layer_test.go`) — unclassified fails the gate by design.
7. Before done: `go build ./... && go vet ./...` then `go test -run 'TestMaintainability_|TestArchitecture_' .` — all pass with no new exemptions.

---

## 1. System Overview

OAuth 2.0 + OIDC SSO server SDK + runnable binary. All concerns are interfaces; defaults in `defaultimpl/` (memory) + `defaultimpl/sqlite/` (pure-Go, no CGO). No external SaaS deps.

```bash
go build ./...
go test ./... -race
go test ./test/ -run TestE2E -v    # cross-wire HTTP + JWKS + bufconn
make ci                             # gofmt + vet + race + build + proto-lint + ci-modules
```

**Middleware stack** (probes registered OUTSIDE):
```
/metrics, /livez, /readyz                         ← outside ratelimit
tracing → ratelimit → bodyLimit → metrics → CORS → router
```

---

## 2. Module Map

Full, current package list — including the newer `domains/` additions
(`conditionalaccess`, `connections`, `identitylink`, `metering`,
`tokenanomaly`, `tokenexchange`, `tokenpolicy`, `tokenusage`,
`userlifecycle`), `protocols/` additions (`lifecyclereactions`,
`scimprovision`), `shared/` additions (`i18n`, `trust`), and infra additions
(`kafka`, `mqtt`, `postgres`) — lives in
[ARCHITECTURE.md](docs/agent-os/ARCHITECTURE.md) (agent-lookup) /
[DIRECTORY_MAP](docs/architecture/DIRECTORY_MAP.md) (canonical; wins on
conflict). Don't duplicate that list here — it drifts. This section only
keeps package-level invariants that aren't already stated in full in §3 or §4.

| Package | Invariant not covered elsewhere |
|---|---|
| `core/` | SPIs: User/Client/Session/Token/Subject/AuthRequest/AuthResult + Authenticator/UserProvider/ClientStore/SessionManager/TokenIssuer/JWK; wire consts + sentinels |
| `oauth/` | AuthCode/Device/Refresh/PAR stores, hexagonal grant handlers; single-use `DELETE RETURNING` (no read-then-delete race); refresh family rotation |
| `oidc/` | `at_hash` required when access_token is in the response; discovery derived from server state |
| `security/` | `AsymmetricJWSAlgs`: EdDSA/ES256-512/RS256/PS256 ONLY; `alg=none` banned; algorithm checked BEFORE signature verify |
| `anomaly/` | Async behavioral detection, OFF the request path; NEVER feeds an auth decision |
| `cluster/` | Cross-replica Bus kinds: `KindTokenRevoked`, `KindSigningKeyRotation`, `KindClientChange`, `KindAuthzPolicyChange` |
| `admin/` | Scoped `admin:read`/`admin:write`; 401 sets `Bearer realm="admin"` |
| `permissions/` | `user:*` ⊇ `user:read` wildcard semantics; new backend MUST pass `permissionstest.ConformanceSuite` |
| `defaultimpl/` | Each issuer (Ed25519/ECDSA/RSA) accepts ONLY its own alg |
| `signingkeys/` | Leaderless peer-key adoption alg-matched BEFORE install; degraded → 503 |
| `audit/` | `SetMeta` only, never `e.Metadata = map{...}` (also §0.5); W3C TraceID/SpanID; bounded cardinality |

Packages with a full dedicated invariant section already in §3 (not repeated
here): `tenant/` + `geo/` and `region/` → Tenant & Residency · `caep/` → CAEP/SSF
· `federation/` → Federation · `authenticators/` → Anti-Enumeration.

Everything else (`spi/`, `fapi/`, `scim/`, `compliance/`, `selfservice/`,
`middleware/`, `adapters/`, `config/`, `proto/`+`gen/proto/`+`grpcserver/`,
`ssoclient/`, `migrate/`, `netpolicy/`+`registry/`, `bootstrap/`+`snapshot/`+
`releases/`, `internal/*`, `cmd/`, `deploy/`, `test/`, and every `domains/`
package listed above) is pure package-map, not a gate — see ARCHITECTURE.md.

**Nested modules** (no `go.work`; `make ci` → `ci-modules`): `kms/{awskms,gcpkms,azurekeyvault,pkcs11}/`, `saml/`, `ldap/`, `kerberos/`, `radius/`, `extauthz/`, `redis/`, `kafka/`, `mqtt/`.

---

## 3. Global Constraints (GATES)

### Oracle-Leak Hardening

| Scenario | Required response |
|---|---|
| AuthCode/Refresh/Device/PAR: unknown/expired/consumed/mismatch on `/token` | `400 invalid_grant` |
| Stale/missing PAR `request_uri` | `invalid_request_uri` |
| DPoP/mTLS failure | `invalid_token` |
| `private_key_jwt` failure | `invalid_client` |

### Anti-Enumeration

| Endpoint | Required behavior |
|---|---|
| `/register/:client_id` | Missing/wrong/unknown bearer → identical 401 `invalid_token` |
| `/token/revoke` | 200 on valid client creds regardless of token existence |
| `/token/introspect` inactive | `{"active":false}` |
| bcrypt (unknown user) | Cost-matched dummy hash |
| WebAuthn (unknown user/session) | `404 session_invalid` |
| MFA `/auth/mfa` | All failures → `400 mfa_invalid`; detail ONLY in `mfa_failure` audit |

### Fail Modes

- **Fail-Open** (log + continue): refresh issuance, ID Token issuance, geo, risk-scorer, audit Sink error, tenant-suspension outage, JTI-replay store error (default), anomaly runner.
- **Fail-Closed**: refresh rotation grant (500), signature/validation failure, scope expansion, family reuse → `DeleteFamily` → `invalid_grant`, trust-chain validation, CAEP receiver.

### Wire Contracts

- **SPI + Storage:** Every concern = interface + `memory` impl ± `sqlite`/`etcd`/`file`. No mocks in tests.
- **Form + JSON:** All endpoints via `bindOAuthParams` (`oauth/bind.go`). HTTP Basic > body creds on `/token`, `/introspect`, `/revoke`, `/par`.
- **PKCE:** Captured at `/auth/login`; verified at `/token` `grant=authorization_code` only. Refresh carries no verifier.
- **Refresh family:** `FamilyID` through every rotation; reuse → `DeleteFamily` → `invalid_grant`. Grace window: concurrent double-submit idempotent; post-window replay still kills family.
- **Session refresh:** Refuses expired/revoked BEFORE extending. Forward/monotonic wall clock — ops MUST slew, never step.
- **`aud` claim:** Unmarshals string or array; marshals single-aud as compact string per OIDC.
- **Discovery:** Derived from server state. New opt-in → branch the doc. New bearer endpoint → `tokenNoStoreHeaders` + `setBearerChallenge`.

### Credential Endpoints

- **Cache headers:** `/token`, `/introspect`, `/revoke[-all]`, `/par`, `/auth/login`, `/userinfo`, `/register*` → `Cache-Control: no-store` + `Pragma: no-cache`. Including errors.
- **401 WWW-Authenticate:** `setBearerChallenge`: missing token omits `error=`; validation failure → `error="invalid_token"`. Descriptions via `security.QuoteAuthParam`.
- **RFC 9207 `iss`:** Every `/auth/login` response uses `s.resolveIssuer(ctx)`. New authz handlers MUST use `s.authzErrorBody(ctx, code)`, not `errorBody`.

### RFC 9068 Claims (every Issue)

- MUST set `Subject.ClientID`. `jti` always auto-generated.
- Login: `AuthTime`+`AMR` from live event; `acr` from `AuthResult.AchievedACR` (empty → omitted). MFA second leg folds factor + `mfa`.
- `auth_code`: stamps `auth_time` from `AuthCode.AuthTime` (real `/auth/login` moment, NOT exchange time).
- Refresh: propagates original AMR without resetting `AuthTime`.
- Token-exchange: propagates `AuthTime`+`ACR`+`AMR`+`SID` from inbound; multi-hop `act` chain prepended.
- `client_credentials`: `ClientID` only.

### X-Forwarded-* Trust

`requestBaseURL` + geo + host honor first-hop XFF — ONLY safe behind a trusted edge that strips + re-sets them. Same model governs `security.mtls.backend: header`, ratelimit IP keying, and mesh `X-Auth-*` headers.

### Tenant & Residency

- Mismatch → 403 `tenant_mismatch`; suspended → `ErrTenantSuspended`; fail-OPEN on outage.
- Admin mutation MUST call `InvalidateTenantSuspensionCache` / `InvalidateTenantResidencyCache`.
- Residency: `region_not_allowed`/`residency_violation` are governance codes (NOT credential oracles).

### Signing Keys

- `RotateKey`/`RetireKey`: overlap-window; demoted key stays verify-only through TTL.
- Leaderless: peer-key adoption alg-matched BEFORE install; decode failure OPEN; adopted keys in separate verify set.
- Coordinated cutover: FAIL-SAFE — deferred retire only widens verify window, never retires early.

### CAEP / SSF

- Transmitter: push ONLY to affected client's receiver; tenant events → `ListByTenant` of THAT tenant only (no cross-tenant leak).
- Receiver: FAIL-CLOSED; jti-replay verified; endpoint from `Client.Attributes["caep_receiver_endpoint"]` (HTTPS, validated at create/update — NEVER request input).

### Federation

- Trust-chain FAIL-CLOSED; all failures → `ErrTrustChainInvalid` (oracle-safe); anchor keys NEVER fetched.
- Auto-registration: pre-registered client WINS; chain failure → byte-identical `invalid_client`; `Secret=""` NEVER.

---

## 4. Coding Conventions

- **No literal leaks** — paths/headers/error codes in `consts.go`.
- **No emojis** in code, comments, or commits.
- **Comments explain WHY** — hidden constraints, invariants, workarounds only. Never "what".
- **Interface guards** in implementation packages, never in interface package (cycle).
- **Tests:** Unit tests beside code. Cross-server integration → `test/` (`package ssotest`). Race fixes prove with `-count=10+`.
- **Hexagonal extraction:** `HandleX(deps Deps, ctx)` free functions in domain packages. `*sso.Server` satisfies `Deps` via `accessors.go`.
- **Error codes:** New `Err*` → update `docs/error-codes.md` in same commit.
- **API specs:** Documented endpoint change → update `docs/openapi.yaml` in same commit.
- **Maintainability gates:** Committed tests enforce 500-line budget + import boundaries (ratcheting). When one fails, SPLIT/fix — do NOT grow exemption list.

### Don'ts

- No `git reset --hard`, `push --force`, `branch -D` without authorization.
- No git-config changes; no hook bypass (`--no-verify`/`--no-gpg-sign`).
- No "while I'm here" cleanup/refactors; no Markdown files unless asked.
- Never violate oracle-leak / anti-enumeration patterns.

### Common Tasks

| Task | Pattern |
|---|---|
| New authenticator | `authenticators/<name>.go` → YAML in `config/config.go` → wire in `buildAuthenticators` |
| New audit Sink | Implement `audit.Sink` (+ `audit.Closer`); wire via `audit.New(...)` / `MultiSink` |
| New permissions backend | `permissions.Provider` in `permissions/<name>/`; run `permissionstest.ConformanceSuite` |
| New gRPC service | `proto/<name>/v1/<name>.proto` → regen → `grpcserver/<name>.go` → `bufconn` test |
| New OAuth/OIDC grant | `bindOAuthParams`; HTTP Basic > body creds; oracle-leak; `DELETE RETURNING`; wire in `sso.go`; discovery |
| New credential endpoint | `tokenNoStoreHeaders(ctx)` at entry; `setBearerChallenge(ctx, ...)` on 401 |
| Extract to domain pkg | Pure functions in `internal/<module>/` → thin `(s *Server)` wrapper → update `Deps` iface → `check-root` |

### Commits

Conventional (`feat(area):`, `fix(area):`, `chore:`, `docs:`). Imperative subject. Body explains why. Co-author trailer when AI-assisted. Don't commit binaries.
