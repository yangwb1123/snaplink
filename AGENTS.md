# AGENTS.md

Execution contract for AI agents working on Snaplink. User instructions override
this file. Security, wire-compatibility, and engineering gates are regression
boundaries, not suggestions.

## 1. Product and Source of Truth

Snaplink is an embeddable OAuth 2.0/OIDC SSO SDK plus an API-only
`sso-server`. Optional protocols, storage backends, and integrations are
composed as modules. Browser UIs remain separate projects; an OpenResty/Envoy
deployment may mount those assets and proxy the API, but the Go server must not
become a static-frontend host.

Use the narrowest authoritative source: executable code and gates for current
behavior; [DIRECTORY_MAP](docs/architecture/DIRECTORY_MAP.md) for ownership;
[OpenAPI](docs/openapi.yaml), [Config](docs/config-reference.md),
[Features](docs/feature-matrix.md), [Errors](docs/error-codes.md), and
[Observability](docs/observability.md) for public contracts; and the Agent OS
[BOOTSTRAP](docs/agent-os/BOOTSTRAP.md) →
[ARCHITECTURE](docs/agent-os/ARCHITECTURE.md) →
[HARNESS](docs/agent-os/HARNESS.md) →
[EVALUATION](docs/agent-os/EVALUATION.md) →
[CHECKS_REGISTRY](docs/agent-os/CHECKS_REGISTRY.md) for execution.
Plans/requirements/analysis describe intent, not shipped functionality.

Treat code/document or gate/config disagreement as drift: satisfy the stricter
contract, report it, and never relax a threshold during unrelated work.

## 2. Engineering Gates

### Budgets

| Metric | Limit | Required response |
|---|---:|---|
| Go file | 500 lines | Stop and split first |
| Function | 50 lines | Extract focused functions |
| Cyclomatic complexity | 15 | Simplify or use [the refactor skill](docs/skills/refactor-high-complexity/SKILL.md) |
| `if` nesting | 3 | Use guards and early returns |
| Directory depth | 3 | Flatten; `gen/`, `ops/deploy/`, `testdata` exempt |
| Non-test Go files/directory | 10 | Extract cohesive subpackages |
| Subdirectories/directory | 15 | Do not exploit the Go gate's temporary `>16` drift |

- Split before feature work if the change would cross a budget.
- Exemption maps never grow. File/function exemptions are capped at zero;
  fan-out ceilings are frozen; `layerExemptions` is shrink-only.
- `interfaces/sso` is at its 60-file ceiling. Extend an existing file or move
  behavior down to a domain package; `_test.go` files do not count.

### Architecture

Imports flow toward the shared kernel:

```text
composition → interfaces → infrastructure → protocols → domains → platform → shared
```

- No upward import, no `protocols/oauth ↔ protocols/oidc` import, and no package
  imports `cmd/`. OAuth/OIDC coordination belongs in
  `interfaces/sso/handlers.go`.
- New top-level or `internal/` packages must be classified in `layerName()` in
  `architecture_layer_test.go`. Never add a `layerExemptions` entry.
- The repository root contains no production Go. Only gate tests and files
  allowed by `engineering.yaml` `root_policy` may live there.
- Place code by responsibility, extend an existing package for one-off work,
  and preserve the hexagonal boundary: domain `HandleX(deps Deps, ctx)` plus a
  thin `*sso.Server` adapter/accessor.
- Probes remain outside rate limiting; preserve the documented middleware order.

### Mandatory verification

After every `.go` edit, fail fast before continuing:

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

`make ci` is the full gate, including nested modules, examples, config, and
module validation. Use `python cli.py <command>` for a targeted check; see the
checks registry for coverage and known gaps.

## 3. Security and Wire Contracts

### Oracle-safe responses

Different internal causes in each row must remain indistinguishable:

| Surface | Required behavior |
|---|---|
| AuthCode/Refresh/Device/PAR unknown, expired, consumed, or mismatched at `/token` | `400 invalid_grant` |
| Missing/stale PAR `request_uri` | `invalid_request_uri` |
| DPoP or mTLS failure | `invalid_token` |
| `private_key_jwt` failure | `invalid_client` |
| `/register/:client_id` missing, wrong, or unknown bearer | identical `401 invalid_token` |
| `/token/revoke` with valid client credentials | `200` regardless of token existence |
| Inactive introspection | `{"active":false}` |
| Unknown, disabled, cross-tenant, or broken login provider/connection | byte-identical `400 unsupported_provider`; details only in audit |
| Unknown bcrypt user | cost-matched dummy hash |
| Unknown WebAuthn user/session | `404 session_invalid` |
| Any MFA failure | `400 mfa_invalid`; details only in `mfa_failure` audit |

### OAuth/OIDC invariants

- Bind form and JSON through `oauth.BindParams` via `bindOAuthParams`. HTTP
  Basic wins over body credentials on `/token`, `/introspect`, `/revoke`,
  and `/par`.
- Capture PKCE at login and verify it only for authorization-code exchange.
  Refresh never carries a verifier.
- Single-use stores consume atomically (`DELETE RETURNING`, not read/delete).
  Carry `FamilyID` through refresh rotation; reuse deletes the family and
  returns `invalid_grant`. Concurrent retries are idempotent only inside the
  grace window.
- Refuse expired/revoked sessions before refresh. Production clocks slew; they
  do not step backward.
- Discovery is derived from server state. `aud` accepts string/array and emits
  a compact string for a single audience.
- Credential endpoints, including errors, use `Cache-Control: no-store` and
  `Pragma: no-cache`. New bearer endpoints call `tokenNoStoreHeaders` and set
  401 challenges via `setBearerChallenge`; descriptions use
  `security.QuoteAuthParam`.
- Every authorization response resolves issuer with `s.resolveIssuer(ctx)`;
  new authorization handlers use `s.authzErrorBody`, not `errorBody`.
- Every RFC 9068 issue sets `Subject.ClientID`; `jti` is generated. Preserve
  login `AuthTime`/`AMR`/`ACR`, authorization-code login time, refresh auth
  context, and token-exchange `AuthTime`/`ACR`/`AMR`/`SID` plus the `act` chain.
  Client credentials set client identity only.
- `at_hash` is mandatory when an ID-token response contains an access token.
  OIDC requested claims survive the AuthCode store and token projection.

### Trust, isolation, and failure modes

- Accepted JWS algorithms are EdDSA, ES256-512, RS256, and PS256 only.
  Reject `none`; check the algorithm before signature verification; each
  concrete issuer accepts only its own algorithm.
- Outbound metadata/JAR/federation requests use the shared SSRF-guarded dialer.
  Anchor keys are never fetched.
- `security.trusted_proxies` gates XFF, forwarded host/proto, header mTLS,
  region headers, mesh `X-Auth-*`, audit/push IPs, tenant XFH, and the resource
  server middleware. A trusted edge strips and re-sets these headers. Unset
  means legacy first-hop trust and is unsafe at an untrusted edge. New
  proxy-supplied consumers must reuse the canonical peer-trust context.
- Trust scoring is fail-open advisory input to enforced conditional access.
  Anomaly detection stays asynchronous and never decides authentication.
- A statically registered authenticator name wins over a dynamic connection.
- Fail open with audit/logging: refresh or ID-token issuance helpers, geo,
  risk/trust scoring, audit sink errors, tenant-suspension lookup outage,
  default JTI-replay-store errors, and anomaly runner.
- Fail closed: signatures/validation, scope expansion, refresh rotation,
  refresh-family reuse, federation trust chains, CAEP receiver, and
  invalidation-bus recovery. Recovery re-subscribes, flushes caches, and
  re-seeds revocation deny-sets before clearing degraded readiness.
- Tenant mismatch is `403 tenant_mismatch`; suspension uses
  `ErrTenantSuspended` and fails open on store outage. Admin mutations
  invalidate suspension/residency caches. Residency errors are governance
  errors, not credential oracles.
- Signing-key rotation keeps the old key verify-only through token TTL.
  Peer-key adoption is algorithm-matched before install; deferred retirement
  may widen, never shorten, the verification window. Degraded key state is 503.
- CAEP transmits only to affected clients; tenant events query only that tenant.
  Receiver endpoints come from validated HTTPS client attributes, never request
  input, and receivers fail closed with JTI replay checks.
- Federation is fail closed: collapse trust errors to
  `ErrTrustChainInvalid`; a pre-registered client wins; auto-registration never
  creates an empty secret.

## 4. Extension and Module Rules

- Every storage concern is an interface plus a real `Memory*` implementation
  and optional durable backends. Prefer those implementations over mocks; a new
  permissions backend must pass `permissionstest.ConformanceSuite`.
- `shared/core` imports no Snaplink package. Implementation interface guards
  live with implementations, not interfaces.
- Admin HTTP/gRPC uses `admin:read` and `admin:write`; HTTP 401 identifies
  `Bearer realm="admin"`. `user:*`-style wildcards include narrower permissions.
- Audit metadata is added only through `audit.SetMeta`. New event types must be
  classified in `auditreport`; preserve bounded cardinality and W3C trace IDs.
- Cross-replica invalidation covers token revocation, signing-key rotation,
  client/authz-policy changes, and tenant suspension.

Module/profile changes obey [ADR-0009](docs/adr/ADR-0009-static-and-runtime-modules.md)
and [plugin-system.md](docs/plugin-system.md):

- Generate cold builds with `python cli.py configure`; repository output stays
  under `dist/`. Root `go.mod` and `go.sum` remain unchanged.
- Manifests are strict `snaplink.module.json` data: no shell/templates,
  arbitrary Go expressions, blank imports, `init` registration, or removable
  kernel-security invariants. Route/config gating does not prove code was
  compiled out.
- In-process hot activation is only for precompiled modules with generation
  leases, drain, readiness, and stop lifecycle. Installable third-party code
  runs out of process over a typed authenticated protocol; never use
  `plugin.Open`. `FeatureGates`, `Server.Handle`, `AddReadyCheck`, and
  `audit.Recorder.AddSink` are not hot-plugin registries.
- Run `python cli.py modules check` and prove the final `go version -m`
  inventory for profile changes.

Nested modules own their `go.mod` and use no `go.work`:
`infrastructure/{kms/{awskms,gcpkms,azurekeyvault,pkcs11},saml,ldap,kerberos,radius,extauthz,kafka,mqtt}`,
`cmd/sso-mcp`, and `cmd/sso-operator`. Redis and Postgres remain root-module
packages.

## 5. Change Workflow

1. Confirm the requested behavior exists in code/current contracts; do not
   implement roadmap prose by assumption.
2. Identify the owning layer and affected security/wire contracts.
3. Check file, function, directory, and fan-out budgets before editing.
4. Make the smallest cohesive change; no speculative framework or unrelated
   cleanup.
5. Test beside the code; cross-server integration belongs in `test/`
   (`package ssotest`). Race fixes run with `-count=10+`.
6. Update contracts in the same change: new `Err*` →
   `docs/error-codes.md`; endpoint → `docs/openapi.yaml`; config knob →
   `docs/config-reference.md`.
7. Run mandatory gates and report any pre-existing failure separately.

| Change | Required pattern |
|---|---|
| Authenticator | `domains/authenticators` → config → `cmd/sso-server/serverbuildauthn` |
| Audit sink | `audit.Sink` (+ `audit.Closer`) → `audit.New`/`MultiSink` |
| Permissions backend | `permissions.Provider` → `permissionstest.ConformanceSuite` |
| gRPC service | proto → regenerate → `interfaces/grpcserver` → bufconn test |
| OAuth/OIDC grant | bind params, oracle safety, atomic consume, route, discovery |
| Credential endpoint | no-store headers + correct bearer challenge |
| Domain extraction | domain free function + thin Server wrapper + accessors |
| Cold/hot module | follow the lifecycle rules above and module validation |

## 6. Coding and Repository Discipline

- Put paths, headers, and error codes in `consts.go`; avoid literal leaks.
- Comments explain hidden constraints and reasons, not visible mechanics.
- No emojis in code, comments, or commits. No deferred-refactor TODOs.
- Do not assign `e.Metadata` directly, add exemptions, or bypass hooks
  (`--no-verify`/`--no-gpg-sign`).
- Do not change git configuration or use `git reset --hard`, force-push, or
  delete branches without explicit authorization.
- Preserve unrelated worktree changes. Do not add Markdown or perform
  “while here” cleanup unless requested.
- Commits are conventional and imperative; the body explains why. Add an
  AI co-author trailer when applicable, and never commit binaries.
