# AGENTS.md

Agent execution contract. User instructions override this file; security,
wire compatibility and engineering gates remain regression boundaries.

## 1. Product and Evidence

Snaplink: embeddable OAuth 2.0/OIDC SDK + API-only `sso-server`, with optional
modules. Browser UIs are external; Go never hosts static frontends.
Billing/Stripe adapter/audit provisioner deploy separately.

- Authority: code + committed gates; ownership: [DIRECTORY_MAP](docs/architecture/DIRECTORY_MAP.md).
- Contracts: [OpenAPI](docs/openapi.yaml), [Config](docs/config-reference.md),
  [Features](docs/feature-matrix.md), [Errors](docs/error-codes.md), [Observability](docs/observability.md).
- Execution: [HARNESS](docs/agent-os/HARNESS.md), [EVALUATION](docs/agent-os/EVALUATION.md),
  [CHECKS_REGISTRY](docs/agent-os/CHECKS_REGISTRY.md).

Plans are not evidence. Distinguish SDK/stock support and compiled/configured/
exposed/licensed/hot-active states; `full` is not HA. Report drift; enforce the
stricter contract without relaxing unrelated thresholds.

## 2. Engineering Boundaries

| Budget | Ceiling |
|---|---:|
| Production Go file / function | 500 / 50 lines |
| Cyclomatic complexity / `if` nesting | 15 / 3 |
| Directory depth | 3; `gen/`, `ops/deploy/`, `testdata` exempt |
| Non-test Go files / subdirectories per directory | 10 / 15 |

Split/simplify first ([refactor skill](docs/skills/refactor-high-complexity/SKILL.md)).
Exemptions never grow: file/function caps zero, fan-out ceilings frozen,
`layerExemptions` shrink-only. `interfaces/sso`: 60 production files maximum;
extend or extract downward (`_test.go` excluded).

```text
composition → interfaces → infrastructure → protocols → domains → platform → shared
```

- Imports stay in-layer/downward; no package imports `cmd/`;
  no `protocols/oauth ↔ protocols/oidc`. Coordinate in `interfaces/sso/handlers.go`.
- Classify new top-level/internal packages in `architecture_layer_test.go`'s `layerName()`;
  `shared/core` imports no Snaplink package; guards live with implementations.
- Root: no production Go; gates + `engineering.yaml` `root_policy` allow-list only.
- Extend owners; domain `HandleX(deps Deps, ctx)` + thin `*sso.Server` adapters/accessors.
  Preserve middleware order; probes outside rate limiting.

## 3. Security and Wire Contracts

### Oracle safety

Within each row, hidden causes are indistinguishable; details only in audit.

| Surface / hidden causes | Contract |
|---|---|
| `/token`: unknown/expired/consumed/mismatched AuthCode, Refresh, Device or PAR | `400 invalid_grant` |
| Missing/stale PAR `request_uri` | `invalid_request_uri` |
| Bearer DPoP/mTLS binding failure | `invalid_token` |
| `private_key_jwt` failure | `invalid_client` |
| `/register/:client_id`: missing/wrong/unknown bearer | identical `401 invalid_token` |
| `/token/revoke`: valid client credentials, any token existence | `200` |
| Inactive introspection | `{"active":false}` |
| Unknown/disabled/cross-tenant/broken login provider or connection | byte-identical `400 unsupported_provider` |
| Unknown bcrypt user | cost-matched dummy hash |
| Unknown WebAuthn user/session | `404 session_invalid` |
| Any MFA failure | `400 mfa_invalid`; detail only in `mfa_failure` audit |

At `/token`, DPoP proof/nonce failures instead use `400 invalid_dpop_proof` /
`400 use_dpop_nonce`.

### OAuth/OIDC

- Form/JSON: `oauth.BindParams` via `bindOAuthParams`; Basic beats body
  credentials on `/token`, `/introspect`, `/revoke`, `/par`.
- PKCE: capture at login, verify only at code exchange; no refresh verifier.
- Atomic single-use consume (`DELETE RETURNING`, not read/delete). Carry refresh
  `FamilyID`; reuse deletes family → `invalid_grant`; retries idempotent only within grace.
- Refresh refuses expired/revoked sessions; production clocks slew, never step backward.
- Discovery reflects server state; `aud` accepts string/array, emits string for one audience.
- All credential responses/errors: `Cache-Control: no-store`, `Pragma: no-cache`.
  New bearer endpoints: `tokenNoStoreHeaders`, 401 `setBearerChallenge`, descriptions
  via `security.QuoteAuthParam`.
- Authorization: `s.resolveIssuer(ctx)`; new errors: `s.authzErrorBody`, not `errorBody`.
- RFC 9068: set `Subject.ClientID`, generate `jti`; preserve login/code/refresh
  `AuthTime`/`AMR`/`ACR`, exchange `AuthTime`/`ACR`/`AMR`/`SID` + `act` chain.
  Client credentials set client identity only.
- ID-token response with access token: mandatory `at_hash`; requested OIDC claims
  survive AuthCode storage and token projection.

### Trust and failure modes

- JWS: EdDSA, ES256/384/512, RS256, PS256 only. Reject `none`; check alg before
  signature; concrete issuers accept only their own alg.
- Metadata/JAR/federation: shared SSRF-guarded dialer; never fetch anchor keys.
- Proxy input uses canonical peer trust (`security.trusted_proxies`): XFF,
  forwarded host/proto, header mTLS, region headers, mesh `X-Auth-*`, audit/push
  IPs, tenant XFH, RS middleware. Edges strip/reset headers; unset is unsafe legacy first-hop trust.
- Trust scores advise enforced conditional access; anomalies are asynchronous,
  never authentication decisions. Static authenticators beat same-named dynamic connections.
- Fail open + audit/logging: refresh/ID-token issuance helpers, geo, risk/trust,
  audit sinks, tenant-suspension lookup outages, default JTI-replay-store errors, anomaly runner.
- Fail closed: signatures/validation, scope expansion, refresh rotation/family
  reuse, federation chains, CAEP receiver, invalidation-bus recovery. Re-subscribe,
  flush caches, re-seed revocation deny-sets before clearing degraded readiness.
- Tenant mismatch: `403 tenant_mismatch`; suspension: `ErrTenantSuspended`,
  fail-open on store outage. Admin mutations invalidate suspension/residency caches;
  residency errors are governance, not credential oracles.
- Rotation: old keys verify-only through token TTL; algorithm-match peers before
  adoption; retirement never shortens verification windows; degraded key state: 503.
- CAEP: affected clients only, tenant-local queries, validated HTTPS client
  receiver attributes (never request input), JTI replay checks.
- Federation: collapse trust errors to `ErrTrustChainInvalid`; pre-registered
  clients win; never auto-register empty secrets.

## 4. Extensions and Modules

- Storage: interface + real `Memory*` + optional durable backends; prefer real implementations to mocks.
- Admin HTTP/gRPC: `admin:read`/`admin:write`; HTTP 401: `Bearer realm="admin"`;
  `user:*` includes narrower permissions.
- Audit metadata: `audit.SetMeta` only; new events classified in `auditreport`; bounded cardinality + W3C trace IDs.
- Cross-replica invalidation: token revocation, key rotation, client/authz-policy changes, tenant suspension.

Follow [ADR-0009](docs/adr/ADR-0009-static-and-runtime-modules.md) and [plugin-system](docs/plugin-system.md):

- Cold builds: `python cli.py configure` → `dist/`; root `go.mod`/`go.sum` unchanged.
- `snaplink.module.json`: strict data, no shell/templates/arbitrary Go/blank
  imports/`init` registration/removable kernel security. Route/config gates do not prove compiled isolation.
- Hot in-process: precompiled modules + generation leases/drain/readiness/stop.
  Installable third-party code: typed authenticated out-of-process protocol,
  never `plugin.Open`; `FeatureGates`, `Server.Handle`, `AddReadyCheck`,
  `audit.Recorder.AddSink` are not hot registries.
- Profile changes: `python cli.py modules check` + final `go version -m` inventory.

Nested modules own `go.mod`, including `sdks/go`; no `go.work`. Full inventory:
`Makefile` `ci-modules`. Redis/Postgres remain root-module packages.

## 5. Change and Verification Workflow

Non-trivial work: [bounded spec](docs/templates/feature-spec.md) → targeted tests → independent review.

1. Verify code/contracts, owner, surface/defaults and security/wire impact; check budgets first.
2. Smallest cohesive change; no speculative framework or unrelated cleanup.
3. Tests beside code; cross-server: `test/` (`package ssotest`); race fixes: `-count=10+`.
   Apply [EVALUATION](docs/agent-os/EVALUATION.md).
4. Update together: `Err*` → `docs/error-codes.md`, endpoint → `docs/openapi.yaml`,
   config → `docs/config-reference.md`. Report pre-existing gate failures separately.

| Change | Integration pattern |
|---|---|
| Authenticator | `domains/authenticators` → config → `cmd/sso-server/serverbuildauthn` |
| Audit sink | `audit.Sink` (+ `audit.Closer`) → `audit.New`/`MultiSink` |
| Permissions backend | `permissions.Provider` + `permissionstest.ConformanceSuite` |
| gRPC service | proto → regenerate → `interfaces/grpcserver` → bufconn test |
| OAuth/OIDC grant | §3 + route/discovery wiring |

After **every `.go` edit**, fail fast before continuing:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```

Before handoff, run checks proportional to the change:

```bash
go test ./... -race
go test ./test/ -run TestE2E -v
make ci
```

`make ci` is the handoff gate (nested modules, examples, config, modules and SDK
contracts included). Python harness reports are supplementary, never substitutes.

## 6. Repository Discipline

- Paths/headers/error codes belong in `consts.go`; comments explain constraints, not mechanics.
- No emojis or deferred-refactor TODOs. Never assign `e.Metadata` directly or bypass hooks
  (`--no-verify`/`--no-gpg-sign`); never add exemptions.
- Preserve unrelated worktree changes; no unrequested Markdown or “while here” cleanup.
  No git-config changes, `git reset --hard`, force-push or branch deletion without authorization.
- Commits: conventional, imperative, explain why; AI co-author trailer when applicable; no binaries.
