# AGENTS.md

Operational guide for AI agents. Follows [agents.md](https://agents.md). User instructions override conflicts. **§3 invariants are gates — violations are regressions.**

**Agent OS:** [BOOTSTRAP.md](docs/agent-os/BOOTSTRAP.md) (context) → [ARCHITECTURE.md](docs/agent-os/ARCHITECTURE.md) (package map) → [HARNESS.md](docs/agent-os/HARNESS.md) (gate spec) → [EVALUATION.md](docs/agent-os/EVALUATION.md) (acceptance criteria) → [CHECKS_REGISTRY.md](docs/agent-os/CHECKS_REGISTRY.md) (agent engineering checks) → [Skills](docs/skills/) (refactor patterns)

**Reference:** [Config](docs/config-reference.md) | [Features](docs/feature-matrix.md) | [Observability](docs/observability.md) | [Errors](docs/error-codes.md) | [OpenAPI](docs/openapi.yaml) | [ADRs](docs/adr/) | [Arch rules](.arch/rules.yaml) | [Prompts](.prompts/)

---

## 0. Engineering Principles (HARD GATES)

The repository currently has two enforcement paths: declarative Python checks
loaded from `engineering.yaml`, and committed root Go gate tests
(`package archgate`) that run inside `make ci`. When they disagree, satisfy the
stricter rule and report the drift; never edit a threshold as part of unrelated
feature work. `python cli.py <command>` runs an individual or composite check;
[CHECKS_REGISTRY.md](docs/agent-os/CHECKS_REGISTRY.md) catalogs both agent
engineering enforcement paths and their known gaps.

### 0.1 Code Budgets

| Metric | Limit | Violation Action |
|---|---|---|
| File lines (`.go`) | ≤ 500 | STOP feature. Split first ([skill](docs/skills/split-large-file/)) |
| Function lines | ≤ 50 | Extract sub-functions |
| Cyclomatic complexity | ≤ 15 | [refactor-high-complexity](docs/skills/refactor-high-complexity/SKILL.md) |
| If-nesting depth | ≤ 3 | Guard clauses / early return |
| Directory depth | ≤ 3 | Flatten (merge leaf dir into parent name); `gen/`, `ops/deploy/`, `testdata` exempt |
| Non-test Go files per dir | ≤ 10 | Split flat package into cohesive sub-packages |
| Subdirs per dir | ≤ 15 contributor target | Python config rejects >15; the committed Go gate currently rejects >16 — do not use the one-directory gap |

The file/function exemption maps are mechanically capped at zero; fan-out maps
have count latches and frozen per-directory ceilings. `layerExemptions` is also
SHRINK-ONLY by policy, but has no automatic count latch, so review must reject
every addition. `interfaces/sso` is AT its 60 non-test-file ceiling — extend an
existing file or extract to a domain package (`_test.go` files never count
against a ceiling).

**Cardinal rule:** if your edit would breach a budget, SPLIT FIRST, then
continue. Refactoring always outranks feature work (480+ line file you'll
exceed → refactor the pre-existing violation first).

### 0.2 Dependency Direction

The first path segment IS the architectural layer; imports point one-way
toward the shared kernel — see [DIRECTORY_MAP](docs/architecture/DIRECTORY_MAP.md)
(canonical), enforced by `architecture_layer_test.go`:

```
composition → interfaces → infrastructure → protocols → domains → platform → shared
```

**Prohibits:** `protocols/oauth ↔ protocols/oidc` (either direction — route
via `interfaces/sso/handlers.go`), `cmd/ ← any`, and any upward
(toward-interfaces) layer import. Never add a `layerExemptions` entry. A new
top-level (or `internal/`) package MUST be classified in `layerName()`
(`architecture_layer_test.go`) — unclassified fails the gate by design.

### 0.3 Post-Edit Verification

After every `.go` change, fail-fast — fix before the next task:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```

### 0.4 Root Directory Policy

The repo root carries NO production Go — only the archgate gate tests plus the
composition/config files whitelisted in `engineering.yaml` `root_policy:`
(enforced by `python cli.py check-root`; banned patterns include
`*_handler.go`, `*_service.go`, `*_store.go`, `*_grant.go`). The SDK's
composition root is `interfaces/sso/`; business logic extracts OUT of it into
domain packages via the hexagonal pattern (§4 Common Tasks).

### 0.5 Prohibited Patterns

| Pattern | Do instead |
|---|---|
| `TODO: refactor later` | Refactor immediately |
| Appending to a 490+ line file | Split first ([split-large-file](docs/skills/split-large-file/SKILL.md)) |
| `protocols/oidc` ↔ `protocols/oauth` import | Route via `interfaces/sso/handlers.go` |
| `e.Metadata = map{...}` | `audit.SetMeta(e, k, v)` only |
| Mocks where a Memory* impl exists | Real `MemoryProvider`/`MemorySink`/`memory.Registry`/… |
| Growing any exemption map | Split / flatten / extract (§0.1) |

### 0.6 Adding New Feature Code (pre-flight checklist — the rules are §0.1/§0.2)

1. Place by responsibility under its layer dir (ARCHITECTURE.md) — extend an existing package, don't proliferate a new one for a one-off.
2. Imports point DOWN only, toward `shared/` (§0.2).
3. Directory depth ≤ 3 (§0.1) — flatten a new backend/variant into the parent name (`webauthnsqlite`), don't nest a 4th level.
4. Budgets (§0.1) — SPLIT FIRST if your edit would breach.
5. NEVER add a maintainability exemption to grandfather your own violation (§0.1).
6. Classify any new top-level (or `internal/`) package in `layerName()` (`architecture_layer_test.go`).
7. Before done: §0.3 verification passes with no new exemptions.

### 0.7 Module Builds and Runtime Plugins

- Cold-module selection goes through `python cli.py configure`; its default
  output stays under ignored `dist/modules/`. A custom `--out` inside the
  repository MUST stay under `dist/`; root `go.mod`/`go.sum` are immutable.
- Manifests are strict `snaplink.module.json` data. No shell/template fields,
  arbitrary Go expressions, blank imports, or registration through `init`.
- Kernel security invariants are non-removable. A route/config gate is not
  evidence that code or dependencies were compiled out.
- In-process hot activation is allowed only for precompiled modules behind a
  generation lease + drain lifecycle. The current `FeatureGates`,
  `Server.Handle`, `AddReadyCheck`, and `audit.Recorder.AddSink` are not
  hot-plugin registries.
- Installable third-party hot plugins run out of process through a typed,
  authenticated protocol. Never use Go `plugin.Open` for server extensions.
- Follow [ADR-0009](docs/adr/ADR-0009-static-and-runtime-modules.md) and
  [plugin-system.md](docs/plugin-system.md); `python cli.py modules check` must
  pass with every manifest/profile change.

---

## 1. System Overview

OAuth 2.0 + OIDC SSO server SDK + runnable API-only binary. All concerns are
interfaces; defaults in `infrastructure/defaultimpl/` (memory) +
`infrastructure/defaultimpl/sqlite/` (pure-Go, no CGO). No required external
SaaS dependency.
Hosted login, admin, self-service, developer, and setup UIs are separate
frontend projects; neither the SDK nor `sso-server` serves static frontend
bundles.

```bash
go build ./...
go test ./... -race
go test ./test/ -run TestE2E -v    # cross-wire HTTP + JWKS + bufconn
make ci                             # fmt + vet + race + build + examples + proto-lint + ci-modules + config validation
```

**Middleware stack** (outermost → router; probes registered OUTSIDE):
```
/metrics, /livez, /readyz                         ← outside ratelimit
panic recovery → tracing → metrics → trusted proxy → ratelimit → degradation
→ API version → body limit → compression → CORS → security headers
→ request logging → router
```

---

## 2. Module Map

The full package list lives in [ARCHITECTURE.md](docs/agent-os/ARCHITECTURE.md)
(agent lookup) / [DIRECTORY_MAP](docs/architecture/DIRECTORY_MAP.md)
(canonical; wins on conflict) — don't duplicate it here, it drifts. This table
keeps only package-level invariants not already stated in full in §3:

| Package | Invariant not covered elsewhere |
|---|---|
| `shared/core` | SPIs: User/Client/Session/Token/Subject/AuthRequest/AuthResult + Authenticator/UserProvider/ClientStore/SessionManager/TokenIssuer/JWK; wire consts + sentinels; imports NO snaplink package |
| `protocols/oauth` | AuthCode/Device/Refresh/PAR stores, hexagonal grant handlers; single-use `DELETE RETURNING` (no read-then-delete race); refresh family rotation |
| `protocols/oidc` | `at_hash` required when access_token is in the response; discovery derived from server state; `claims` parameter rides `AuthCode.RequestedClaims` through every store into the ID-token/access-token projection |
| `shared/security` | `AsymmetricJWSAlgs`: EdDSA/ES256-512/RS256/PS256 ONLY; `alg=none` banned; algorithm checked BEFORE signature verify; outbound metadata/JAR fetches ride `securityverify.SSRFGuardedDialer` (dial-time DNS-rebind block, oracle-stable errors) |
| `shared/trust` | Trust scoring is FAIL-OPEN advisory input to conditional access — a trust signal must NEVER become a lockout lever; live at request time only when `access_policies.enforce` wires the CAP engine |
| `domains/anomaly` | Async behavioral detection, OFF the request path; NEVER feeds an auth decision |
| `domains/connections` | `/auth/login` `provider=<connection id>` dispatches via `AuthenticatorFactory` (production impl in `cmd/sso-server/serverbuildauthn`); a statically-registered provider name WINS; cross-tenant guard (tenant-A host never dispatches tenant-B's connection); unknown/disabled/cross-tenant/build-failure ALL collapse to the same `unsupported_provider` — failure detail ONLY in the `connection_authenticator_build_failed` audit event |
| `platform/cluster` | Cross-replica Bus kinds: `KindTokenRevoked`, `KindSigningKeyRotation`, `KindClientChange`, `KindAuthzPolicyChange`, `KindTenantSuspension` |
| `interfaces/admin` | Scoped `admin:read`/`admin:write`; 401 sets `Bearer realm="admin"` |
| `domains/permissions` | `user:*` ⊇ `user:read` wildcard semantics; new backend MUST pass `permissionstest.ConformanceSuite` |
| `infrastructure/defaultimpl` | Each issuer (Ed25519/ECDSA/RSA) accepts ONLY its own alg |
| `platform/signingkeys` | Leaderless peer-key adoption alg-matched BEFORE install; degraded → 503 (the aggregation loop AND the etcd registry's publish-lease check are both in `/readyz`) |
| `platform/audit` | `SetMeta` only, never `e.Metadata = map{...}` (also §0.5); W3C TraceID/SpanID; bounded cardinality; a new EventType must be filed in `auditreport` (control area or the uncategorized allowlist — the drift test names strays) |
| `cmd/sso-server/servermodules` | Explicit cold-module composition hook only; generated builds replace its configured file through the single allow-listed overlay path; no `init` or blank imports |

Packages with a full dedicated invariant section already in §3 (not repeated
here): `domains/tenant` + `platform/geo`/`domains/region` → Tenant & Residency
· `protocols/caep` → CAEP/SSF · `domains/federation` → Federation ·
`domains/authenticators` → Anti-Enumeration. Everything else is pure
package-map, not a gate — see ARCHITECTURE.md.

**Nested modules** (own `go.mod`; no `go.work`; `make ci` → `ci-modules`):
`infrastructure/{kms/{awskms,gcpkms,azurekeyvault,pkcs11},saml,ldap,kerberos,radius,extauthz,kafka,mqtt}`,
`cmd/sso-mcp`, `cmd/sso-operator`. `infrastructure/redis` and
`infrastructure/postgres` are ROOT-module packages (their deps are tracked
under `/`).

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
| `/auth/login` provider dispatch | Unknown provider / unknown / disabled / cross-tenant / misconfigured connection → byte-identical 400 `unsupported_provider` |
| bcrypt (unknown user) | Cost-matched dummy hash |
| WebAuthn (unknown user/session) | `404 session_invalid` |
| MFA `/auth/mfa` | All failures → `400 mfa_invalid`; detail ONLY in `mfa_failure` audit |

### Fail Modes

- **Fail-Open** (log + continue): refresh issuance, ID Token issuance, geo, risk-scorer, trust-scorer, audit Sink error, tenant-suspension outage, JTI-replay store error (default), anomaly runner.
- **Fail-Closed**: refresh rotation grant (500), signature/validation failure, scope expansion, family reuse → `DeleteFamily` → `invalid_grant`, trust-chain validation, CAEP receiver, invalidation-bus recovery (resubscribe FIRST, then flush caches + re-seed revocation deny-sets, ONLY THEN clear degraded — a failed re-seed keeps the replica degraded and `/readyz` red).

### Wire Contracts

- **SPI + Storage:** Every concern = interface + `memory` impl ± `sqlite`/`etcd`/`file`. No mocks in tests.
- **Form + JSON:** All endpoints via `oauth.BindParams` (`bindOAuthParams` wrapper in `interfaces/sso`). HTTP Basic > body creds on `/token`, `/introspect`, `/revoke`, `/par`.
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

### Proxy-Supplied Input Trust

`security.trusted_proxies` (CIDR list → `shared/security/peertrust.Checker`,
compiled once at boot) gates EVERY proxy-supplied input: the XFF chain walk
(ratelimit IP keying, geo/risk client IP), `X-Forwarded-Proto/Host` (base
URL/issuer, DPoP `htu`, discovery URIs), `security.mtls.backend: header` cert
extraction, region `HeaderResolver`, and mesh `X-Auth-*` (ext_authz denies an
untrusted direct peer with the standard `invalid_token` challenge — not
probeable). UNSET = legacy first-hop trust, ONLY safe behind a trusted edge
that strips + re-sets these headers. Known still-ungated readers (don't grow
the list): audit IP enrichment, `domains/tenant/middleware.go` XFH tenant
resolution, `interfaces/ssoclient/rs`, push-callback client IP.

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

- Trust-chain FAIL-CLOSED; all failures → `ErrTrustChainInvalid` (oracle-safe); anchor keys NEVER fetched; metadata fetches ride the shared SSRF-guarded dialer.
- Auto-registration: pre-registered client WINS; chain failure → byte-identical `invalid_client`; `Secret=""` NEVER.

---

## 4. Coding Conventions

- **No literal leaks** — paths/headers/error codes in `consts.go`.
- **No emojis** in code, comments, or commits.
- **Comments explain WHY** — hidden constraints, invariants, workarounds only. Never "what".
- **Interface guards** in implementation packages, never in interface package (cycle).
- **Tests:** Unit tests beside code. Cross-server integration → `test/` (`package ssotest`). Race fixes prove with `-count=10+`.
- **Hexagonal extraction:** `HandleX(deps Deps, ctx)` free functions in domain packages. `*sso.Server` satisfies `Deps` via `accessors.go`.
- **Docs in the same commit:** new `Err*` → `docs/error-codes.md`; documented endpoint change → `docs/openapi.yaml`; new config knob → `docs/config-reference.md`.

### Don'ts

- No `git reset --hard`, `push --force`, `branch -D` without authorization.
- No git-config changes; no hook bypass (`--no-verify`/`--no-gpg-sign`).
- No "while I'm here" cleanup/refactors; no Markdown files unless asked.
- Never violate oracle-leak / anti-enumeration patterns.

### Common Tasks

| Task | Pattern |
|---|---|
| New authenticator | `domains/authenticators/<name>.go` → YAML in `config/` → wire in `cmd/sso-server/serverbuildauthn` |
| New audit Sink | Implement `audit.Sink` (+ `audit.Closer`); wire via `audit.New(...)` / `MultiSink` |
| New permissions backend | `permissions.Provider` in `domains/permissions/<name>/`; run `permissionstest.ConformanceSuite` |
| New gRPC service | `proto/<name>/v1/<name>.proto` → regen → `interfaces/grpcserver/<name>.go` → `bufconn` test |
| New OAuth/OIDC grant | `oauth.BindParams`; HTTP Basic > body creds; oracle-leak; `DELETE RETURNING`; wire in `interfaces/sso/server_routes*.go`; discovery |
| New credential endpoint | `tokenNoStoreHeaders(ctx)` at entry; `setBearerChallenge(ctx, ...)` on 401 |
| Extract to domain pkg | Pure functions in `internal/<module>/` → thin `(s *Server)` wrapper → update `Deps` iface → `python cli.py check-root` |
| New cold module/profile | Typed registration seam → strict `snaplink.module.json` → catalog/profile → `python cli.py modules check` → prove final `go version -m` inventory |
| New hot module | Static surface + generation leases + readiness/drain/Stop; third-party installable code stays out of process; see ADR-0009 |

### Commits

Conventional (`feat(area):`, `fix(area):`, `chore:`, `docs:`). Imperative subject. Body explains why. Co-author trailer when AI-assisted. Don't commit binaries.
