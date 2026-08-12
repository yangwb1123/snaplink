# Requirements Spec: cmd/sso-server — issuer wiring (B4-1 iss allowlist)

> Source: `docs/architect-analysis/auto/analyses/cmd-snaplink-audit-provisioner-7492095d.json`
> direction 1. Scope: module `cmd/sso-server` plus its config/SDK seams
> (`config.Config.ServerOptions`, `interfaces/sso` issuer resolution).
>
> **Verdict (verification against the current tree): the direction's core
> claim — "cmd/sso-server never passes `sso.WithIssuer`" — is FALSE. The
> wiring already exists end to end.** `config.Config.ServerOptions()`
> (config/config_load.go:301-308) always emits `sso.WithIssuer(c.Server.Issuer)`,
> `cmd/sso-server/build_app_core.go:154` appends it into `b.opts`, and
> `cmd/sso-server/build_app.go:257` feeds `b.opts` to `sso.NewServer`.
> The JWT `iss` claim is pinned from the same `cfg.Server.Issuer` value
> (cmd/sso-server/serverbuildsign/build_signing_issuers.go:43). The
> `issuer_test.go:15` comment the analysis calls "drift" is accurate, and the
> wiring is itself covered by `config/security_test.go`. The one real gap is
> the direction's own acceptance: no test pins the four cross-path issuer
> equalities end to end. This spec therefore makes the supplied acceptance
> checks testable and adds no production code change.

## 1. Verified evidence for every cited symbol

| Citation in direction | Verdict | Current tree |
|---|---|---|
| `interfaces/sso/options.go:349-351` — `WithIssuer` sets `s.issuer` | Correct | `func WithIssuer(issuer string) Option { return func(s *Server) { s.issuer = issuer } }` at options.go:350-351 |
| `cmd/sso-server/build_app.go:257` — `sso.NewServer(b.opts...)` | Correct | `srv = sso.NewServer(b.opts...)` at build_app.go:257 |
| `cmd/sso-server/build_app_oidc.go:137` — `caep.WithIssuer` | Correct but misread | It wires the CAEP transmitter's SET issuer only, **not** the SSO server's |
| `cmd/sso-minimal/app.go:79` — wires `sso.WithIssuer` | Correct | `sso.WithIssuer(cfg.Issuer)` (flag-based config, separate binary) |
| `interfaces/sso/server_discovery.go:251-257` — `resolveIssuer` falls back to `requestBaseURL` | Correct | Fallback is reachable only when `s.issuer == ""` or the sentinel |
| `interfaces/sso/server_discovery.go:265-269` — `authzErrorBody` stamps RFC 9207 `iss` | Correct | `KeyIss: s.resolveIssuer(ctx)` at server_discovery.go:268 |
| `interfaces/sso/server_discovery.go:342-343` — `renderFormPostResponse` passes `resolveIssuer` | Correct | server_discovery.go:343 |
| `interfaces/sso/server_discovery_config.go:144` — discovery seeds `Issuer: base` | Correct | `buildBaseMetadata` seeds `Issuer: base` (request base URL) |
| `interfaces/sso/server_discovery_config.go:264` — issuer override | Correct, context missing | `applyMFAIssuerSigning` (called unconditionally at buildOIDCConfiguration:112) overrides `cfg.Issuer = s.issuer` when non-sentinel — so discovery **does** honor `WithIssuer` |
| `config/config_load.go:48-71` — cmd default `server.issuer` = `"sso-server"` | Correct | `DefaultServerIssuer = "sso-server"` (config_load.go:51); `applyDefaults` (config_load.go:66-70) |
| `config/config_load.go:182-184` — sentinel rejection | Correct | `if c.Server.Issuer == sso.DefaultIssuer { return fmt.Errorf(...) }` at config_load.go:184 |
| `cmd/sso-server/issuer_test.go` comment "drift" | **Inverted** | The comment (issuer_test.go:15) lists `WithIssuer via ServerOptions` — that wiring exists; the comment is accurate |

**Claims falsified by the tree** (all introduced by commit `305dc6c0`,
2026-06-19, which the analysis predates or misread):

- "cmd/sso-server never passes it" — false. `config.Config.ServerOptions()`
  (config/config_load.go:301-308) prepends `sso.WithIssuer(c.Server.Issuer)`;
  `build_app_core.go:154` does `b.opts = append(cfg.ServerOptions(), ...)`
  inside `wireSigningIssuer` (build_app_core.go:133), which runs on the build
  path before `sso.NewServer`.
- "nothing consumes it in the SSO server" — false. Three consumers:
  (1) `ServerOptions` → `s.issuer` → `resolveIssuer` / discovery override;
  (2) `serverbuildsign/build_signing_issuers.go:43`
  `defaultimpl.WithEd25519Issuer(srv.Issuer)` → JWT `iss` claim;
  (3) `tracing.WithServiceName` (per the issuer_test.go comment).
- "G1 trust-path identity anchor can disagree with the token issuer" — no:
  both anchors derive from the same `cfg.Server.Issuer`, and the config
  loader's own comment (config_load.go:43-50) documents this invariant.
- `config/security_test.go:72-124` pins the issuer option's presence in
  `ServerOptions` output in three configurations.

**Coverage that already exists:**

- SDK `resolveIssuer` override: `interfaces/sso/rootcov_accessors_test.go:64-68`
  wires `WithIssuer("https://accessor.example.com")` and asserts
  `ResolveIssuer` wins over the request base URL (lines 246-248).
- Sentinel rejection: `cmd/sso-server/issuer_test.go:37-53`
  (`TestConfigRejectsSDKSentinel`) + `config_load.go:184`.
- No regression risk for acceptance (d): the rejection test would fail on any
  relaxation.

## 2. Goal

Close the residual gap between the direction's acceptance criteria and the
test suite: pin, end to end at the `cmd/sso-server` binary level, that
`server.issuer` — not the request Host — is the single source of truth for
the discovery issuer, the RFC 9207 `iss` in authorization error bodies,
form_post responses, and the access/id-token `iss` claims. No production
behavior changes; the change set is tests only.

## 3. Product boundary

- Surface: stock `sso-server` binary (cmd/sso-server) and its config loader.
- Default: enabled — the behavior under test is the shipped default
  (`DefaultServerIssuer` when unset, operator URL when set).
- Explicit non-goals: no production code change, no config schema change, no
  discovery-cache key change, no `docs/*` contract updates (no contract
  changes), no change to `cmd/sso-minimal`, no new SDK options.

## 4. Acceptance criteria (preserved from the direction, made testable)

New tests live in `cmd/sso-server` (package `main`, mirroring
`cache_ttl_test.go` / `backchannel_logout_test.go`, which already build the
app via `buildApp` and fetch discovery via the `fetchDiscovery` helper at
`operator_metadata_test.go:15`). All four checks are Given/When/Then
regressions against a single `buildApp`-built server with
`cfg.Server.Issuer = "https://sso.example.com"`.

### T-2a — Discovery issuer is never Host-derived

Given `server.issuer = https://sso.example.com` and a request carrying
tampered `X-Forwarded-Host: attacker.example` (plus, to be thorough,
`X-Forwarded-Proto: http`) — the legacy first-hop-trust path honors those
headers (`interfaces/middleware/request_url.go:18-40`,
`ForwardedHeadersTrusted` default-true at trusted_proxy.go:176), so the
request base URL differs from the configured issuer —

When `GET /.well-known/openid-configuration` is served —

Then `doc["issuer"] == "https://sso.example.com"` (the value flows
`ServerOptions` → `s.issuer` → `applyMFAIssuerSigning` override at
server_discovery_config.go:264-265, which is applied unconditionally at
server_discovery_config.go:112).

Test name: `TestBuildApp_DiscoveryIssuerIgnoresTamperedHost`. Existing
discovery tests assert only presence (`rootcov_discovery_test.go:49,268`,
`cache_ttl_test.go:90`), so this is a new assertion, not a duplicate.

### T-2b — Authorization error body `iss` == discovery issuer

Given the same server —

When an authorization-endpoint request that fails before authentication
(e.g. `POST /auth/login` with an unknown `client_id`) is served, and the
response body is compared with the discovery document from T-2a —

Then `body["iss"] == doc["issuer"] == "https://sso.example.com"` (both are
`resolveIssuer` results: authzErrorBody at server_discovery.go:266-269; the
discovery value from the same `s.issuer`). The response must also carry the
no-store header set (`Cache-Control: no-store`, `Pragma: no-cache`) as
required by AGENTS.md for credential endpoints — asserted as a guard, not
changed. Also assert the form_post response path
(`renderFormPostResponse`, server_discovery.go:343): an
`response_mode=form_post` success renders an auto-POST HTML form whose
hidden `iss` input equals the same value (pattern:
`TestRcov2L_FormPostResponseMode` at rootcov2_login_test.go:112-144).

Test name: `TestBuildApp_AuthzErrorIssMatchesDiscoveryIssuer`.

### T-2c — Access-token and id-token `iss` claims == discovery issuer

Given the same server (which wires the shared `Ed25519JWTIssuer` built with
`WithEd25519Issuer(srv.Issuer)` at build_signing_issuers.go:43) —

When (i) a client-credentials grant at `POST /token` mints an access token
and (ii) a full authorization-code flow (login with `response_type=code`,
then `POST /token` `grant_type=authorization_code`) mints an access token
plus an id token —

Then decoding each JWT payload yields `iss == "https://sso.example.com"`,
equal to the discovery issuer from T-2a. The id-token path exercises
`WithIDTokenIssuer(jwtIssuer)` wiring at build_app_core.go:169; the
access-token path exercises the default token strategy. No authorization-
code-flow test exists in cmd/sso-server today, so this is net-new coverage.

Test name: `TestBuildApp_TokenIssClaimsMatchDiscoveryIssuer`.

### T-2d — Sentinel `snaplink-sso` still rejected at config load

Given the existing `TestConfigRejectsSDKSentinel`
(cmd/sso-server/issuer_test.go:37-53) and `config_load.go:184` —

When a YAML with `server.issuer: snaplink-sso` is loaded —

Then `config.Load` fails with an error containing "must not equal". This
check is already implemented and tested; the spec requires it to stay green
unchanged (regression pin only — no new test needed).

## 5. Files

### Create

```text
cmd/sso-server/issuer_wiring_test.go — T-2a/T-2b/T-2c end-to-end pinning
tests (buildApp + httptest + JWT payload decode); reuses fetchDiscovery,
quietLogger, and the existing seeded test user/client pattern from
build_app_coverage_test.go / consent_ttl_test.go
```

### Modify

```text
none — production behavior is verified present; no contract docs change
(no new Err*, endpoint, or config knob)
```

## 6. Out of scope (explicit)

- Changing `config.Config.ServerOptions`, `resolveIssuer`,
  `applyMFAIssuerSigning`, or the signing-issuer construction.
- The other two directions in the source analysis (B4-5 audit outbox /
  governance connector; B4-4 strict Content-Type mode) — separate specs.
- `cmd/snaplink-audit-provisioner` itself: the direction targets
  `cmd/sso-server`; the module label in the analysis file is a batch filing
  artifact, not a scope statement.

## 7. Verification plan

1. New tests: `go test ./cmd/sso-server/ -run 'TestBuildApp_(DiscoveryIssuerIgnoresTamperedHost|AuthzErrorIssMatchesDiscoveryIssuer|TokenIssClaimsMatchDiscoveryIssuer)' -v`.
2. Mandatory gates after edit:
   `go build ./... && go vet ./...` and
   `go test -run 'TestMaintainability_|TestArchitecture_' .`
   (the new file must respect the 500-line / 10-file-per-dir / fan-out
   budgets; extend `issuer_wiring_test.go` only — `interfaces/sso` is at
   its 60-file ceiling).
3. Pre-handoff: `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
   `make ci`.
4. Report pre-existing failures separately if any appear; the new tests must
   not be skipped or relaxed.
