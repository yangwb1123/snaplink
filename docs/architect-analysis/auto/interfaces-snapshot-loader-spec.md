# Requirements Spec: interfaces/snapshot/loader — issuer allowlist replacing the Host-derived resolveIssuer fallback (RFC 9207 discovery parity)

> Scope: module `interfaces/snapshot/loader` (filing module). The analyzed
> module is a 101-line `file://`/`inline:` snapshot-storage URI resolver
> (`interfaces/snapshot/loader/loader.go`) with no issuer surface; the gate
> items for this direction land in `interfaces/sso` (issuer resolution +
> discovery) and `config` (startup validation + wiring). See
> [interfaces-snapshot-loader-9f0c6a1c.json](analyses/interfaces-snapshot-loader-9f0c6a1c.json).
>
> Source of truth for the direction: contract item 1 (iss) — the issuer must
> come from a configurable allowlist and never be Host-derived.

## 1. Goal and user outcome

Operators can pin every issuer-identifying surface (minted authorization
responses, RFC 9207 `iss` on authorization endpoints, discovery document
`issuer`, JWT `iss`) to a configurable allowlist. A spoofed, absent, or
misconfigured `Host`/`X-Forwarded-Host` header can no longer change any issuer
value, so mix-up detection (RFC 9207 §2) and RFC 9068/OIDC validator
comparisons stay meaningful. The allowlist is opt-in; deployments that do not
configure it keep today's behavior byte-identical.

## 2. Product boundary

- Surface: SDK option (`sso.WithIssuerAllowlist`) + stock `sso-server` config
  key (`server.issuer_allowlist`).
- Default: feature off — empty/unset allowlist preserves the legacy
  Host-derived fallback byte-for-byte. Feature on requires `WithIssuer` (or
  `server.issuer`) set to an allowlist member; the Host-derived fallback is
  then unreachable.
- Explicit non-goals:
  - Per-request multi-host issuer selection from a multi-entry allowlist.
    The minted JWT `iss` is fixed at token-issuer construction time
    (`infrastructure/defaultimpl/ed25519_jwt_issuer.go:324`), so any
    semantics under which discovery `issuer` varies per request would break
    the parity invariant in T-2. Multi-entry allowlists are therefore valid
    only to bound the one configured issuer (a membership set), not to select
    per request.
  - Changing endpoint derivation in the discovery document
    (`authorization_endpoint`, `token_endpoint`, ... remain request-base
    derived; only the `issuer` field is allowlist-pinned).
  - Changing `interfaces/middleware/request_url.go` `BaseURL` (the Host/base
    extractor itself is out of scope; trusted-proxy semantics unchanged).
  - Any change to `interfaces/snapshot/loader` or the snapshot pipeline.
  - New wire error codes or endpoint changes (resolution always succeeds when
    the feature is on; see §4 S4).

## 3. Verified gap (evidence)

1. `interfaces/sso/server_discovery.go:251-256` — `resolveIssuer` returns
   `s.issuer` only when set and non-default, otherwise
   `return requestBaseURL(ctx.Request())` (:255). `requestBaseURL` is
   `middleware.BaseURL` (`interfaces/sso/server_federation.go:40`,
   `interfaces/middleware/request_url.go:22-53`), which derives
   `scheme://host` from `X-Forwarded-Proto`/`X-Forwarded-Host` (trusted
   proxies) or `r.Host` — Host-derived by construction.
2. `interfaces/sso/server_discovery.go:247-249` — the code's own invariant
   comment: "Critical invariant: the value returned here MUST equal
   `oidc.ProviderMetadata.Issuer` for the same request — RFC 9207 §2 ...".
   When `WithIssuer` is unset (`s.issuer == DefaultIssuer`, `sso.go:67`,
   `aliases.go:179`, `shared/core/consts_oauth.go:139`), resolveIssuer and the
   discovery issuer are both Host-derived, but the JWT `iss` claim is the
   construction-fixed `sso.DefaultIssuer` literal
   (`infrastructure/defaultimpl/ed25519_jwt_issuer.go:324`) — the invariant
   then holds only by the cmd default being non-sentinel
   (`config/config_load.go:60` `DefaultServerIssuer = "sso-server"`, guarded
   by `cmd/sso-server/issuer_test.go:22-36`).
3. `interfaces/sso/server_discovery_config.go:62` —
   `base := requestBaseURL(ctx.Request())` in `handleOIDCDiscovery`; `:142-144`
   `buildBaseMetadata` seeds `Issuer: base`; `:264-265` `applyMFAIssuerSigning`
   overrides `cfg.Issuer = s.issuer` only when `s.issuer != "" &&
   s.issuer != DefaultIssuer`. So the discovery `issuer` is Host-derived
   exactly when resolveIssuer is Host-derived — the two must change together.
4. `interfaces/sso/server_discovery.go:265-272` — `authzErrorBody` stamps
   `KeyIss: s.resolveIssuer(ctx)` (:268); the same value feeds the login
   success response (`server_finish_login.go:191`), JARM signing
   (`server_finish_login.go:456`), form-post (`server_discovery.go:343`),
   JAR verification (`server_jar.go:365`), bearer challenges
   (`mesh_authz.go:179,217,253`), and logout/MFA/me responses
   (`server_logout.go:259`, `server_mfa.go:139`, `server_me.go:43,49,90`).
   Pinning resolveIssuer pins all of them.
5. Startup-rejection precedent: `config/config_load.go:183-184` already
   rejects `server.issuer == sso.DefaultIssuer` ("must not equal ...") in
   `validate()`; `ServerOptions()` (`config/config_load.go:308`) applies
   `sso.WithIssuer(c.Server.Issuer)`. SDK option-combination rejection
   precedent: `interfaces/sso/options_grants.go:78` panics in
   `WithCustomGrant` for a nil handler. `config.Load` is the single startup
   gate (also exercised by `--validate-only`).

Line-number drift vs the analysis JSON (244/251-257/263/146): HEAD puts the
invariant comment at 247, `resolveIssuer` at 251-256, `authzErrorBody` at
265, and `Issuer: base` at 144. All cited symbols exist as described.

## 4. Proposed behavior

### S1 — New surface

- SDK: `sso.WithIssuerAllowlist(issuers []string) Option` — stores a
  normalized copy (trim, drop empties, dedupe, preserve order) on the Server.
  Empty after normalization = feature off. Placed next to `WithIssuer`
  (`interfaces/sso/options.go:349-351`); `interfaces/sso` is at its 60-file
  ceiling, so the option lives in the existing `options.go`, never a new
  production file.
- Config: `server.issuer_allowlist: []string` (YAML) —
  `config/config_load.go` `Server` struct, `applyDefaults` (empty default),
  `validate()`, and `ServerOptions()` appends
  `sso.WithIssuerAllowlist(c.Server.IssuerAllowlist)`. Documented in
  `docs/config-reference.md` (OIDC section, next to the `server.issuer` row)
  and the reference `cmd/sso-server/config.yaml`.

### S2 — Startup rejection (both surfaces)

- `config.Load` (`config/config_load.go` `validate()`): when
  `server.issuer_allowlist` is non-empty, `server.issuer` (post-defaults,
  `config_load.go:70-71`) MUST be a member (exact string equality, after the
  same normalization); otherwise return an error mirroring the sentinel
  rejection wording at `config_load.go:183-184`. Also reject empty entries
  and duplicates in the allowlist itself.
- SDK `NewServer` (`interfaces/sso/sso.go:58`): after options apply, when
  the allowlist is non-empty and `s.issuer == "" || s.issuer ==
  DefaultIssuer || s.issuer ∉ allowlist`, panic with a message naming the
  offending issuer (precedent `options_grants.go:78`). This is the only
  rejection mechanism available without changing the `NewServer` signature.
  No existing caller is affected — the option is new.

### S3 — Resolution semantics

- Allowlist empty (feature off): `resolveIssuer` and the discovery issuer
  behave byte-identically to today (WithIssuer if set and non-default, else
  `requestBaseURL`). Existing discovery tests must pass unmodified.
- Allowlist non-empty (feature on): `resolveIssuer` returns `s.issuer` (an
  allowlist member by S2) and MUST NOT call `requestBaseURL` — gate the
  fallback on `len(s.issuerAllowlist) == 0`, and update the doc comment at
  `server_discovery.go:242-249` to state the allowlist rule. The discovery
  `issuer` field must equal `resolveIssuer` for the same request: the
  existing `applyMFAIssuerSigning` override (`server_discovery_config.go:264-265`)
  already yields `cfg.Issuer = s.issuer` whenever the feature is on (S2
  guarantees non-default `s.issuer`); make this structural by deriving the
  `Issuer` seed in `buildBaseMetadata`/`buildOIDCConfiguration` from the same
  allowlist-resolved value rather than from `base`, so a future reordering of
  the override cannot leak the Host back into discovery. `authzErrorBody`
  (`server_discovery.go:265-272`) and every other `resolveIssuer` consumer
  (§3 item 4) follow automatically.
- JWT `iss`: the token issuer's construction-time issuer
  (`serverbuildsign/build_signing_issuers.go:43,70,98` uses
  `cfg.Server.Issuer`; `ed25519_jwt_issuer.go:324` defaults to
  `sso.DefaultIssuer`) equals the allowlist member in the stock build by S2.
  The spec makes this a documented SDK requirement: with the feature on, any
  wired `TokenIssuer` must be constructed with an issuer string that is an
  allowlist member, enforced by a guard test (§5), not by the Server (the
  Server cannot rewrite a caller-constructed issuer).

### S4 — Failure modes

- No runtime failure mode: with the feature on, resolution always returns
  the allowlist member (S2 + S3). No new wire error codes, no change to
  `docs/error-codes.md`, no change to credential-endpoint no-store headers or
  bearer challenges. Discovery caching keyed by base URL
  (`server_discovery_config.go:57-84`) is unchanged — endpoints remain
  base-derived even though the issuer field is pinned.

## 5. Acceptance criteria

Universal gates: `go build ./... && go vet ./...`,
`go test -run 'TestMaintainability_|TestArchitecture_' .`, and `make ci`
must pass; feature-off behavior must remain byte-identical (existing
discovery/issuer tests pass unmodified).

1. **Startup rejection** — Given a config with
   `server.issuer_allowlist: ["https://sso.example.com"]` and
   `server.issuer: "https://other.example.com"` (or the default
   `"sso-server"`), when `config.Load` runs, then it returns an error whose
   message names the allowlist; with `server.issuer: "https://sso.example.com"`
   it loads. On the SDK: `NewServer(WithIssuerAllowlist(["https://sso.example.com"]),
   WithIssuer("https://other.example.com"))` panics; the same with
   `WithIssuer("https://sso.example.com")` succeeds; `WithIssuerAllowlist(nil)`
   with any issuer never panics (feature off).
2. **T-9** — Given a server with
   `WithIssuerAllowlist(["https://sso.example.com"])` +
   `WithIssuer("https://sso.example.com")`, when the discovery endpoint
   (`/.well-known/openid-configuration`) is requested with (a) `Host:
   evil.example.com`, (b) no `Host`, and (c) a trusted-edge
   `X-Forwarded-Host: evil.example.com`, then in every case the document's
   `issuer` field equals `"https://sso.example.com"` and never the request
   host.
3. **T-2** — Given the same server plus a wired token issuer constructed with
   `WithEd25519Issuer("https://sso.example.com")`, when an authorization
   response is produced (login success and every `authzErrorBody` error path)
   and an access token is minted, each with `Host: evil.example.com`, then the
   response `iss` field and the minted token `iss` claim both equal the
   discovery `issuer` (`"https://sso.example.com"`), and neither equals
   `"evil.example.com"`.
4. **Feature-off regression** — Given a server without the allowlist option,
   then `resolveIssuer` returns `requestBaseURL` for a non-default-issuer-free
   server and the discovery `issuer` equals the request base, byte-identical
   to today (existing discovery tests are the proof).
5. **Invariant regression** — the parity comment at
   `server_discovery.go:247-249` is updated to state the allowlist rule, and
   a test asserts `resolveIssuer(ctx)` equals the discovery `issuer` for the
   same request in both feature-on and feature-off configurations.

## 6. Files

### Create

```text
interfaces/sso/issuer_allowlist_test.go — T-9, T-2, feature-off regression,
    and parity tests via the rcov harness (rootcov_flow_test.go:62).
    Test files do not count against the interfaces/sso 60-file ceiling.
config/issuer_allowlist_test.go — S2 config.Load acceptance/rejection cases.
```

### Modify

```text
interfaces/sso/options.go — add WithIssuerAllowlist next to WithIssuer
    (options.go:349-351); option stores the normalized allowlist.
interfaces/sso/sso.go — NewServer post-options validation (panic) per S2.
interfaces/sso/server_discovery.go — resolveIssuer fallback gated on
    allowlist-empty (server_discovery.go:251-256); update doc comment
    (242-249) with the allowlist rule.
interfaces/sso/server_discovery_config.go — derive the discovery Issuer seed
    from the allowlist-resolved value so buildBaseMetadata
    (server_discovery_config.go:142-144) can never be Host-derived when the
    feature is on; keep the applyMFAIssuerSigning override (264-265).
config/config_load.go — Server.IssuerAllowlist field, defaults, validate()
    membership/empty/duplicate checks (mirroring 183-184), ServerOptions()
    wiring (308).
cmd/sso-server/config.yaml — document server.issuer_allowlist in the
    reference config (commented).
docs/config-reference.md — OIDC section: new server.issuer_allowlist row,
    update the server.issuer row to state allowlist membership when set.
docs/feature-matrix.md — RFC 9207 row (line 125): note the allowlist option.
cmd/sso-server/issuer_test.go — extend with config.Load allowlist cases.
```

### Do not modify

```text
interfaces/snapshot/loader/loader.go — orthogonal URI resolver; no issuer
    surface; the direction must not touch the snapshot pipeline.
interfaces/middleware/request_url.go — BaseURL/Host extraction semantics
    (trusted-proxy gating) are unchanged.
interfaces/sso/server_federation.go — requestBaseURL stays the endpoint
    derivation primitive.
```

Confirm budgets before editing: `interfaces/sso` is at its 60-file ceiling
(production files; extend existing files only); `server_discovery.go` /
`server_discovery_config.go` / `options.go` must stay within the 500-line,
50-line-function, and 15-complexity budgets (the change adds one gate in
`resolveIssuer` and one override path — no new functions beyond the option
setter).

## 7. Dependencies and compatibility

- New option: `sso.WithIssuerAllowlist([]string)`; new YAML key:
  `server.issuer_allowlist`. No SPI changes, no storage migration, no
  HTTP/proto surface change (discovery document shape unchanged).
- Rollout: configurable + default-off, so a rollback is a config revert.
  Feature-on deployments must set `server.issuer` to an allowlist member at
  the same time (S2 makes the intermediate state a loud startup error, never
  a silent divergence).
- Compatibility note: with the feature on, the minted JWT `iss` no longer
  derives from the request host in any path — deployments relying on the
  legacy per-host fallback must not enable the allowlist.

## 8. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./interfaces/sso/ -run 'TestIssuerAllowlist|TestRcovDisc' -v
go test ./config/ -run 'TestIssuerAllowlist|TestConfig' -v
go test ./cmd/sso-server/ -run 'TestConfig.*Issuer' -v
make ci
```

Race runs for the new tests (`go test -race -count=10 ./interfaces/sso/ -run
'TestIssuerAllowlist'`). No `test/` e2e additions are required — the surface
is Server-internal resolution plus config validation, both covered by unit
tests; if a cross-server check is desired later it belongs in `test/`
(`package ssotest`).
