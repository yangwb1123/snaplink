# EVALUATION.md — Acceptance criteria per module type

Referenced by `docs/templates/feature-spec.md` §3 ("Check applicable
EVALUATION.md criteria"). This is where those criteria IDs are defined. It
operationalizes invariants `AGENTS.md` §3 already states as prose, so a
Reviewer agent can check boxes instead of re-deriving the rules each time —
the checkboxes are a lookup aid, not a substitute for reading `AGENTS.md`.

## Universal (all changes) — U1-U9

Reported by `python cli.py accept` (`checks/acceptance.py`). This command is not
the whole release gate: run the committed Go gates and `make ci` as well.

| ID | Criterion | Enforced by |
|---|---|---|
| U1 | `go build ./...` succeeds | `checks/acceptance.py` |
| U2 | `go vet ./...` clean | `checks/acceptance.py` |
| U3 | File size ≤ 500 lines (non-exempt, non-generated) | `checks/filesize.py` |
| U4 | *(reserved — see note below)* | — |
| U5 | Architecture dependency direction holds (no *new* violations; pre-existing debt is allow-listed) | `checks/architecture.py` |
| U6 | *(reserved — see note below)* | — |
| U7 | *(reserved — see note below)* | — |
| U8 | Root file count ≤ 15 non-exempt | `checks/root_files.py` (repository debt is reported as `DIAGNOSTIC`; the criterion is not falsely marked PASS) |
| U9 | No business code (`*_handler.go`, `*_service.go`, `*_store.go`, `*_grant.go`) at repo root | `checks/root_business_code.py` (repository debt is reported as `DIAGNOSTIC`; the criterion is not falsely marked PASS) |

Coverage is also printed as "Section 4" by `checks/acceptance.py`. It is
blocking: a failing test subprocess, unresolved package target, or missing
coverage row fails the acceptance command.

> U4/U6/U7 are placeholders in the current acceptance suite. Their underlying
> gates exist and already run inside `go test ./...` (per-function complexity,
> cognitive layer boundaries, directory fan-out/depth — see `HARNESS.md`) —
> they are just not yet wired as discrete, individually-reported steps inside
> `checks/acceptance.py`. Treat the `go test` gates as authoritative for these
> three; don't invent pass/fail content against U4/U6/U7 themselves.

Required universal verification for a code change:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
make ci
```

## sec 2: Module-type criteria

Pick the section(s) matching your feature-spec's "Module Classification".

### If OAuth Grant / OIDC Flow Handler — O1-O11

| ID | Criterion |
|---|---|
| O1 | Unknown/expired/consumed/mismatched AuthCode, Refresh, Device, or PAR grant on `/token` returns `400 invalid_grant` (no distinguishing detail) |
| O2 | Stale or missing PAR `request_uri` returns `invalid_request_uri` |
| O3 | DPoP/mTLS failure returns `invalid_token` |
| O4 | `private_key_jwt` failure returns `invalid_client` |
| O5 | `/register/:client_id` with missing/wrong/unknown bearer returns an identical `401 invalid_token` |
| O6 | `/token/revoke` returns 200 with valid client creds regardless of whether the token exists |
| O7 | `/token/introspect` on an inactive/unknown token returns exactly `{"active":false}` |
| O8 | Every credential-endpoint response (including errors) sets `Cache-Control: no-store` + `Pragma: no-cache` (`tokenNoStoreHeaders`) |
| O9 | Every 401 sets `WWW-Authenticate` via `setBearerChallenge` (no `error=` on missing token; `error="invalid_token"` on validation failure) |
| O10 | `Issue` sets `Subject.ClientID`; `jti` auto-generated; RFC 9068 claims populated per grant type (`AGENTS.md` §3 "RFC 9068 Claims") |
| O11 | New authz error paths use `s.authzErrorBody(ctx, code)` (not `errorBody`); `/auth/login` responses use `s.resolveIssuer(ctx)` for the RFC 9207 `iss` |

### If Store Implementation (Memory / SQLite) — S1-S7

| ID | Criterion |
|---|---|
| S1 | Interface + at least one `memory` implementation exist (no test-only mocks) |
| S2 | Single-use tokens/codes are consumed atomically: SQLite uses `DELETE ... RETURNING`; memory stores remove under one critical section (no read-then-delete race) |
| S3 | Refresh-family rotation carries `FamilyID`; reuse triggers `DeleteFamily` → `invalid_grant` |
| S4 | Store errors on the credential path fail per `AGENTS.md` §3 "Fail Modes" (fail-open vs fail-closed, per operation) |
| S5 | SQLite implementation is pure-Go (no CGO); forward-only migration via `migrate/` |
| S6 | Bounded / reaped where applicable (JTI-replay, refresh, device-code, PAR memory stores don't grow unbounded) |
| S7 | Conforms to any published conformance suite for its SPI (e.g. `permissionstest.ConformanceSuite` for a `permissions.Provider`) |

### If Admin Endpoint — A1-A4

| ID | Criterion |
|---|---|
| A1 | Scoped via `admin:read` / `admin:write`; 401 sets `Bearer realm="admin"` |
| A2 | Mutation invalidates the relevant cache (`InvalidateTenantSuspensionCache`, `InvalidateTenantResidencyCache`, signing-key verify set, etc.) |
| A3 | Cross-tenant isolation holds — no tenant can read/write another tenant's data through the endpoint |
| A4 | Documented in `docs/openapi.yaml` in the same commit |

### If Authenticator — N1-N5

| ID | Criterion |
|---|---|
| N1 | Implements the `Authenticator` SPI; wired through `cmd/sso-server/serverbuildauthn.BuildAuthenticators` |
| N2 | Unknown-user path returns a cost-matched dummy result (no timing/response oracle for user existence) |
| N3 | Config surface added to `config/config.go` (YAML key + validation) |
| N4 | Failure modes classified per `AGENTS.md` §3 "Fail Modes" (does a provider outage fail open or closed?) |
| N5 | AMR value contributed on success maps to a registered AMR string, consumed by RFC 9068 claim population |

### If Cold Module / Build Profile / Hot Lifecycle — M1-M9

| ID | Criterion |
|---|---|
| M1 | `snaplink.module.json`, catalog and profiles pass `python cli.py modules check`; manifests contain data only |
| M2 | Build materialization leaves root `go.mod`/`go.sum` unchanged and the final compile succeeds with the generated alternate module graph in readonly mode |
| M3 | Missing/ambiguous capabilities, conflicts, dependency cycles, unsupported targets and declared module CGO/FIPS/license metadata policy violations fail before compilation; transitive SBOM/license and FIPS evidence remain release checks |
| M4 | Registration is an explicit allow-listed call; no blank import, arbitrary generated expression, or `init` registration |
| M5 | Kernel security invariants and embedded modules cannot be excluded; route/config gating is not reported as binary isolation |
| M6 | `go version -m`, compiled inventory and behavior prove a selected module is present; excluded isolated dependencies are absent |
| M7 | `modules.lock.json` is canonical and contains no secrets, timestamps or absolute local paths; the binary reports its lock digest |
| M8 | A purported hot in-process module uses generation leases, readiness, drain and reverse-order cleanup; otherwise it is classified cold |
| M9 | Installable third-party hot code is out of process behind typed/authenticated RPC, bounded resources and host-owned OAuth-safe error mapping |

## Using this file

1. Pick your module classification in `feature-spec.md`.
2. Check every ID in the matching section before requesting review.
3. A Reviewer agent verifies by re-deriving from `AGENTS.md` §3, not by
   trusting the checkboxes.
