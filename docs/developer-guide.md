# Developer Guide

## First-Time Setup

```bash
# 1. Install Go 1.24+
go version

# 2. Clone and build
git clone https://github.com/snaplink/sso
cd sso
go build ./...

# 3. Verify engineering gates
make harness          # filesize + complexity + architecture checks
# or: python cli.py harness

# 4. Run tests
make test
```

**Note:** There is no `scripts/setup.sh` — the CLI (`python cli.py`) is the engineering entry point. Run `make harness` to initialize all gates.

---

## Daily Development Workflow

```
1. git pull              → sync
2. make harness          → verify current state
3. make help             → see available targets
4. develop               → make changes (see Post-Edit Verification below)
5. make harness          → gates must pass
6. make test             → unit tests
7. git commit            → pre-commit checks run
8. git push              → pre-push checks run
```

### Post-Edit Verification (every `.go` change)

After any code change, run the committed gates before moving to the next task:

```bash
go build ./...
go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' ./...
```

These check: file ≤ 500 lines, function cyclo ≤ 15, function length ≤ 50, dependency direction, and no unlawful root directory business code. **Fail-fast** — fix before continuing.

---

## Engineering System Overview

The project uses a formal engineering system (see `docs/agent-os/HARNESS.md`) with committed gates:

| Gate | What | Check |
|---|---|---|
| G1: File Size | `.go` files ≤ 500 lines | `TestMaintainability_Budget` |
| G2: Complexity | cyclo ≤ 15, function length ≤ 50 | `TestMaintainability_Complexity` |
| G3: Build & Test | `go build` + `go test -race` | pre-push |
| G4: Architecture | dependency direction (layers point DOWN) | `TestArchitecture_ImportBoundaries` |
| G5: No Mocks | use Memory* impls, never mocks | review |
| G6: Security | no-store headers, oracle-leak safe, anti-enumeration | `make check-invariants` |
| G7: Root Policy | no business code in project root | `python cli.py check-root` |

### Code Budgets

| Metric | Limit | Violation Action |
|---|---|---|
| File lines (`.go`) | ≤ 500 | Run `skills/refactor-large-file.md` |
| Function lines | ≤ 50 | Extract sub-functions |
| Cyclomatic complexity | ≤ 15 | Run `skills/refactor-high-complexity.md` |
| If-nesting depth | ≤ 3 | Guard clauses / early return |
| Directory depth | ≤ 3 | Flatten (merge leaf dir); `gen/`, `ops/deploy/`, `testdata` exempt |
| Go files per dir | ≤ 10 | Split into cohesive sub-packages |
| Subdirs per dir | ≤ 15 | Regroup leaf packages |

**Cardinal rule:** If your edit pushes a file over 500 lines, split first, then continue. Refactoring always outranks feature work.

---

## Available Make Targets

Run `make help` for the full list. Key targets:

| Target | Purpose |
|---|---|
| `make harness` | All engineering gates (filesize + complexity + architecture) |
| `make check-quick` | Fast post-edit check (filesize + vet) |
| `make test` | Unit tests |
| `make race` | Race detector tests (`-race -count=1`) |
| `make ci` | Full CI: fmt + vet + race + build + examples + proto-lint + ci-modules |
| `make lint` | golangci-lint |
| `make check-invariants` | Security invariant check |
| `make security-scan` | SAST/SCA (govulncheck + gosec) |
| `make coverage` | Test coverage report |
| `make diagnose` | Codebase health diagnosis |
| `make health-report` | Architecture health report |
| `make trend` | Engineering metrics snapshot |
| `make review` | Code review checklist |
| `make acceptance` | Full acceptance suite (EVALUATION.md) |
| `make build` | Compile to `bin/` |
| `make test-e2e` | Integration tests in `test/` (package `ssotest`) |
| `make config-validate` | Validate all deploy config.yaml files |
| `make proto-lint` / `make proto-gen` | Protobuf linting / code generation |
| `make docker` | Build container image |
| `make licenses` | Generate dependency license report |
| `make check-exemptions` | Verify exemption lists are in sync |

### Quick Reference

```bash
make check-quick         # fast: filesize + vet (after every edit)
make harness             # full: filesize + complexity + architecture
make ci                  # everything: fmt + vet + race + build + proto + modules
```

---

## Writing Code

### Architecture: Physically Layered Tree

Packages live under **layer directories**. The first path segment IS the layer. Imports point **DOWN only** (toward `shared/core`).

```
interfaces/     → delivery edge (HTTP, gRPC, public Server API — no business logic)
protocols/      → OAuth, OIDC, SCIM, FAPI, CAEP, selfservice, compliance
domains/        → business: tenant, federation, authenticators...
platform/       → cross-cutting: cluster, metrics, audit, geo...
shared/         → kernel: core (import-free), security, spi
infrastructure/ → default impls: memory, sqlite, vault, kms/*, saml, ldap, redis...
```

**Prohibited:**
- `protocols/oauth → protocols/oidc` or `protocols/oidc → protocols/oauth`
- `cmd/ ← any` (no package imports `cmd/`)
- Any upward (toward-interfaces) layer import

### Package Ownership

| Package | Owns | Key Invariants |
|---|---|---|
| `shared/core/` | SPIs: User/Client/Session/Token/Subject/AuthRequest/AuthResult | Wire consts + sentinels; import-free |
| `shared/security/` | Lockout, JTI-replay, JAR-fetch, JWE, step-up, mTLS, pairwise, SPIFFE | No `alg=none`; checked BEFORE sig verify |
| `shared/spi/` | Logger, CodeSender, RiskScorer, MFAProvider | — |
| `protocols/oauth/` | AuthCode/Device/Refresh/PAR stores, DCR/RAR, grant handlers | Oracle-leak collapse; `DELETE RETURNING`; refresh family rotation |
| `protocols/oidc/` | IDTokenIssuer, UserinfoSigner, JWKS, EndSession, FormPost, JARM | MUST NOT import `oauth/` |
| `protocols/scim/` | SCIM 2.0 provisioning (RFC 7643/7644) | — |
| `protocols/fapi/` | FAPI 2.0 Validator (Inspection\|Enforce) | — |
| `protocols/caep/` | OpenID SSF v1 SET transmitter + receiver | Push ONLY to affected client; receiver FAIL-CLOSED |
| `protocols/federation/` | OpenID Federation 1.0 (entity config + trust-chain) | Trust-chain FAIL-CLOSED; pre-registered client WINS |
| `protocols/selfservice/` | Signup, email change, password reset, data export, account erase | Hexagonal `Handle*(d Deps, ctx)` |
| `protocols/compliance/` | GDPR/CCPA/PIPL erasure + export | — |
| `domains/tenant/` | Tenant resolution | Mismatch → 403 |
| `domains/authenticators/` | 9 pluggable authenticators + `webauthn/` | Unknown password → cost-matched dummy bcrypt |
| `platform/cluster/` | Cross-replica Bus (Publish/Subscribe) | `KindTokenRevoked`, `KindSigningKeyRotation`, `KindClientChange` |
| `platform/audit/` | Recorder + Sinks + hash chain | `SetMeta` only; W3C TraceID/SpanID |
| `platform/permissions/` | Roles + menus + wildcard matcher | `user:*` ⊇ `user:read` |
| `infrastructure/defaultimpl/` | Ed25519/ECDSA/RSA issuers + Memory* stores + JWE + KMS bridge | Each issuer accepts ONLY its own alg |
| `interfaces/sso/` | Public Server API (`*sso.Server`), route wiring, middleware stack | No business logic; thin wrappers only |
| `config/` | YAML + env + etcd + flag loader | — |
| `admin/` | Admin HTTP middleware + gRPC interceptor + scope rules | `admin:read`/`admin:write` |
| `internal/handler/` | Shared handler utilities | AMR, health, logging, DPoP nonce |
| `internal/auth/consent/` | Consent utilities + challenge store | `ScopesMatch`, `ScopesSubsumed` |
| `internal/auth/login/` | Login request types | `Request` struct |
| `signingkeys/` | Leaderless JWKS key aggregation | Alg-matched BEFORE install |
| `test/` | Server-level integration suite (package `ssotest`) | — |

### Adding New Code (every new package/file MUST satisfy these)

1. **Place by responsibility, under its layer dir** — see tree above.
2. **Imports point DOWN only** — toward `shared/core`. No upward import.
3. **Directory depth ≤ 3** — flatten a new backend/variant into the parent name (`webauthnsqlite`, not `sqlite/webauthn/`).
4. **File ≤ 500 lines, function ≤ 50 lines & cyclo ≤ 15** — if your edit would breach, SPLIT FIRST.
5. **Classify any new top-level (or `internal/`) package** in `layerName()` (`architecture_layer_test.go`) — an unclassified package fails the gate.
6. **NEVER add a new maintainability exemption** — the exemption lists are count-capped and only shrink.
7. **Before done:** `go build ./... && go vet ./...` then `go test -run 'TestMaintainability_|TestArchitecture_' ./....` — all pass with no new exemptions.

### Adding an Endpoint

1. Determine ownership: OAuth → `protocols/oauth/`, OIDC → `protocols/oidc/`, admin → `admin/`
2. Use `bindOAuthParams` for form/JSON binding (`protocols/oauth/bind.go`)
3. Apply `tokenNoStoreHeaders(ctx)` at entry (credential endpoints)
4. Use `setBearerChallenge(ctx, ...)` on 401
5. Wire in `interfaces/sso/` route registration
6. Document in `docs/error-codes.md` and `docs/openapi.yaml`
7. Add oracle-leak tests (unknown/expired/consumed → unified error)
8. See `docs/skills/add-new-handler/` for detailed walkthrough

### Conventions

- **No emoji** in code, comments, or commits
- **Comments explain WHY** — hidden constraints, invariants, workarounds only. Never "what"
- **Interface guards** in implementation packages, never in interface package (avoids cycle)
- **Use `SetMeta(e, k, v)`** for audit — never `e.Metadata = map{...}`
- **Oracle-leak:** unknown/expired/consumed → unified `400 invalid_grant` (or `invalid_request_uri` for PAR)
- **Anti-enumeration:** bcrypt cost-matched dummy hash for unknown users; `/token/revoke` always 200; `/token/introspect` inactive → `{"active":false}`
- **Cache headers:** credential endpoints → `Cache-Control: no-store` + `Pragma: no-cache`
- **RFC 9207 `iss`:** every `/auth/login` response uses the resolved issuer
- **Refresh family:** `FamilyID` through every rotation; reuse → `DeleteFamily` → `invalid_grant`
- **No `TODO: refactor later`** — refactor immediately
- **Hexagonal extraction:** `HandleX(deps Deps, ctx)` free functions in domain packages; `*sso.Server` satisfies `Deps` via `accessors.go`
- **Root directory:** only server composition files allowed (`sso.go`, `handlers.go`, `server_*.go`, `accessors.go`). No `*_handler.go`, `*_service.go`, `*_store.go`, `*_grant.go` in root.

### Fail Modes

| Mode | Behavior |
|---|---|
| **Fail-Open** (log + continue) | Refresh issuance, ID Token issuance, geo, risk-scorer, audit Sink error, tenant-suspension outage, JTI-replay store error, anomaly runner |
| **Fail-Closed** | Refresh rotation grant (500), signature/validation failure, scope expansion, family reuse → `invalid_grant`, trust-chain validation, CAEP receiver |

---

## Common Tasks

### Running a specific test
```bash
go test ./protocols/oauth/ -run TestAuthCode -v
go test ./test/ -run TestE2E -v   # integration tests
```

### Checking file size
```bash
python cli.py check-filesize
# or: make filesize
```

### Measuring complexity
```bash
python cli.py complexity
# or: make complexity
```

### Checking architecture / dependency direction
```bash
python cli.py architecture
# or: make architecture
# committed: go test -run TestArchitecture_ImportBoundaries ./...
```

### Quick post-edit check
```bash
make check-quick
# runs: filesize check + go vet
```

### Full engineering gates
```bash
make harness
# runs: filesize + complexity + architecture
```

### Security invariant check
```bash
make check-invariants
```

### Code review checklist
```bash
make review
# or: python cli.py review
```

### Viewing trend data
```bash
cat .trends/2026-06.md
```

### License compliance
```bash
make licenses       # generate CSV report
make licenses-check # CI gate: reject GPL/AGPL/SSPL
```

### Checking root directory compliance
```bash
python cli.py check-root
```

### Using skills (refactoring patterns)
Skills are in `docs/skills/`. Run one via:
```bash
python cli.py skill <name> [args...]
# or read the .md directly: cat docs/skills/<name>/SKILL.md
```

Common skills:
| Skill | When |
|---|---|
| `skills/split-large-file.md` | File > 480 lines and you need to add more |
| `skills/refactor-large-file.md` | File > 500 lines (violation) |
| `skills/refactor-high-complexity.md` | Cyclo > 14 and you need to add logic |
| `skills/hexagonal-extraction.md` | Business code found in root directory |
| `skills/add-new-handler/` | Adding a new HTTP endpoint |

---

## Common Implementation Patterns

| Task | Pattern |
|---|---|
| New authenticator | `domains/authenticators/<name>.go` → YAML in `config/config.go` → wire in `buildAuthenticators` |
| New audit Sink | Implement `audit.Sink` (+ `audit.Closer`); wire via `audit.New(...)` / `MultiSink` |
| New permissions backend | Implement `permissions.Provider` in `permissions/<name>/`; run `permissionstest.ConformanceSuite` |
| New gRPC service | `proto/<name>/v1/<name>.proto` → `buf generate` → `grpcserver/<name>.go` → `bufconn` test |
| New OAuth/OIDC grant | `bindOAuthParams`; HTTP Basic > body creds; oracle-leak; `DELETE RETURNING`; wire in `sso.go`; update discovery |
| New credential endpoint | `tokenNoStoreHeaders(ctx)` at entry; `setBearerChallenge(ctx, ...)` on 401 |
| Extract to domain pkg | Pure functions in `internal/<module>/` → thin `(s *Server)` wrapper → update `Deps` iface → `check-root` |

---

## Commits

- **Format:** Conventional (`feat(area):`, `fix(area):`, `chore:`, `docs:`)
- **Imperative subject.** Body explains WHY, not what.
- **Co-author trailer** when AI-assisted.
- **No binaries** in commits.
- **Pre-commit checklist:**
  - [ ] `go build ./...` passes
  - [ ] `go vet ./...` passes
  - [ ] `go test -run 'TestMaintainability_|TestArchitecture_' ./...` passes
  - [ ] `python cli.py check-root` passes
  - [ ] No new file > 500 lines (unless exempted — and exemption lists only shrink)
  - [ ] No new function cyclo > 15 or function > 50 lines
  - [ ] No new dependency direction violations
  - [ ] No `TODO: refactor later`

---

## Don'ts

- No `git reset --hard`, `push --force`, `branch -D` without authorization
- No git-config changes; no hook bypass (`--no-verify`/`--no-gpg-sign`)
- No "while I'm here" cleanup/refactors
- Never violate oracle-leak / anti-enumeration patterns
- No `e.Metadata = map{...}` — use `SetMeta(e, k, v)` only
- No mocks where Memory* implementations exist (`MemoryProvider`, `MemorySink`, `memory.Registry`)
- `protocols/oidc/` must NOT import `protocols/oauth/`

---

## Key Reference Documents

| Document | Purpose |
|---|---|
| `AGENTS.md` | Agent behavior rules + hard constraints |
| `docs/agent-os/HARNESS.md` | Automated checks + rejection policy |
| `docs/agent-os/EVALUATION.md` | Quality gates + acceptance criteria |
| `docs/agent-os/BOOTSTRAP.md` | Project context overview |
| `docs/skills/` | Reusable engineering skills (refactor patterns) |
| `docs/config-reference.md` | YAML configuration reference |
| `docs/feature-matrix.md` | RFC/OIDC compliance matrix |
| `docs/observability.md` | Metrics + audit + tracing |
| `docs/error-codes.md` | Error code definitions |
| `docs/openapi.yaml` | API specification |
| `docs/architecture/DIRECTORY_MAP.md` | Layer directory map |
| `docs/adr/` | Architecture Decision Records |
