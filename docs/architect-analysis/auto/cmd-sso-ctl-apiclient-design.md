# Design: `sso-ctl check` — deploy-tree live sweep built on apiclient (T-2 truthiness + T-8a/T-8d/T-9 probes)

Design for the direction "Deploy-tree B4 live sweep subcommand built on
apiclient (T-2 truthiness + T-8/T-9 probe surface)", per
[cmd-sso-ctl-apiclient-requirements.md](cmd-sso-ctl-apiclient-requirements.md).
Every claim in the supplied evidence was re-verified against this tree; two
minor line citations are corrected (§1). Three independent reviews (CLI
conventions, test-plan, security) produced required amendments; §0 records
each and where it lands. The amendments supersede the requirements' literal
text where the two conflict (flagged inline); the requirements describe intent,
this doc is the implementation contract. Doc-only artifact: this file triggers
no gates, but implementation now includes **one** additive `apiclient.go`
change (the review-mandated `WithNoRedirect` option, §2.4/§3.2) plus the
`check.go`/test/main.go surface.

Module: `cmd/sso-ctl/apiclient` (composition layer; dispatch table
`cmd/sso-ctl/main.go:46-63`).

## 0. Review amendments incorporated (traceability)

| Review | Amendment | Where it lands |
|---|---|---|
| CLI F-1 (must-fix) | No credentials = missing-required-input misuse → **exit 2** (tree convention: configcmd `--file`, importcmd `--format`, legacysync env pw, auditverify `--bearer`); `check OK` is **never** printed when a group was skipped — a skipped group forces `check INCOMPLETE` + exit 1 (auditverify's "prefix verified … not the full chain" precedent) | §3.1, §5 (table header, rows 24-25, skip rule), §6, §7 A8 |
| CLI F-2 (must-fix) | `flag.ContinueOnError` + explicit `errors.Is(err, flag.ErrHelp) → return 0` with usage on stderr — the first subcommand in the tree to special-case `ErrHelp` (every `ContinueOnError` user today returns 2 on `-h`); `sso-ctl check -h` never reaches main.go's help case, so this mapping is mandatory | §3.1, §5 row 24, §7 A1 |
| CLI F-3 | Preflight validates the **effective** addr — env `SSO_ADMIN_ADDR` wins over `--addr` (apiclient.go:60-61), so the env-sourced value is validated too, or the fail-fast rationale is only half-honored; exit-2-for-bad-URL documented as a deliberate deviation from auditverify's exit-1 runtime classification | §2.1, §5 row 24 |
| CLI F-4/F-5 | `--addr` is the only flag-vocabulary divergence (consistent with apiclient's own `DefaultAddr`/`WithAddr`/`EnvAddr`); collect-all-failures is the tree's first non-fail-fast `Run` — one sentence so it is not misread as a bug | §3.1, §5 aggregation |
| Security 1 (blocking) | **`WithNoRedirect` pin**: one additive `WithNoRedirect()` option in `apiclient.go` (`CheckRedirect: http.ErrUseLastResponse`) + contract test — default redirect-following would forward 307/308 POST bodies (`client_secret`), forward the admin bearer on same-hostname/subdomain redirects, and let a 302 discovery fetch coerce the sweep into fetching an arbitrary URL as the discovery doc; 3xx row semantics: truthiness rows pass, content rows fail | §2.4, §3.2-3.3, §5 (rows 1/3/7/17/19/21/22 + redirect posture), §6, §7 A2/REQ-6 |
| Security 2 | `--addr`/advertised-URL validation: non-empty `Host`, reject `userinfo` (Go auto-sends `Authorization: Basic` from it — on the wire *and* into diagnostics), reject query/fragment on the base (concatenation fetches a different resource), validate the effective addr, never echo raw values | §2.1, §2.3, §5 rows 2/24 |
| Security 3 | R7 body-echo pin (body echo only for non-2xx; decode failures print only the decode error — never the token string, never the body; ~200-byte truncation) + shared `redactURL`/`sanitizeBody` used by every stderr diagnostic (R1/R4/R7/R19/R22/R24) | §3.2, §5 rows 1/4/7/19/20/22/24, global pin |
| Security 4 | crypto/rand pins: `rand.Read` failure → exit 1, never a `math/rand` fallback; explicit 62-char alphanumeric charset; probe scope never on stdout **or stderr**; prefix guarantees `≠ openid/device_sso` | §2.2, §3.2, §5 rows 20 |
| Security 5 | T-9 target = the **advertised** `introspection_endpoint` (doubles as its T-2 row); absent → skip with stderr notice, never fall back to canonical `PathIntrospect`; dummy token is a fixed literal, never the minted token; `SSO_ADMIN_TOKEN` exported → stderr notice (bearer rides only to advertised hosts under the no-redirect pin); decoy-field canary test; residual disclosure documented | §2.3, §4.5, §5 rows 22/23, §7 A3/A7 |
| Test plan | A1's registration test cannot live in `apiclient/` — `TestSubcommands_CheckIsWired` in `cmd/sso-ctl/dispatch_test.go` (package main, heir of `TestSubcommands_GenerateIsWired`); testkit line drift corrected (:21-50, :61-281, 290-line file); row-coverage gaps (rows 1, 4, 7, 8, 9-14, 17, 18) closed with six tests + two data-driven extensions; golden-determinism pins | §1 C4, §7 |

## 1. Evidence verification — untrusted claims re-checked against the tree

All 8 citations verify TRUE. Two line-number citations drift (C1, C4); no
semantic claim failed. The two corrections the requirements doc itself made
(smoke.sh existence; 16/16 subdir ceiling) are independently confirmed.

| # | Claim | Verdict | Evidence (this tree) |
|---|---|---|---|
| C1 | `apiclient.go` — `Do`, `DefaultAddr`, 188 lines, zero tests | ✅ (line drift) | `wc -l` = 188; `DefaultAddr = "http://127.0.0.1:8443"` at :24; `New` :47-62 (design draft's ":47-71" drifted — :71 is `WithToken`'s body) with `SSO_ADMIN_TOKEN` env fallback :57-59 and `SSO_ADMIN_ADDR` override :60-61 (env wins over `WithAddr` — verified, load-bearing for `--addr` semantics); `Do` :81-111 (Bearer only when token non-empty, JSON Content-Type on body, `Accept: application/json` always); `ReadBody` :134-142 (1MB cap via `io.LimitReader`). Package dir contains exactly `apiclient.go` — zero `_test.go` files confirmed. The §3.2 amendment (`WithNoRedirect`, ~6 lines after `WithAddr` :77, before `Do` :81) shifts later line numbers; re-pin at implementation. |
| C2 | `main.go:45-62` — 16-entry subcommands map | ✅ | `var subcommands = map[string]func([]string) int{` :46, 16 entries :47-62, closing `}` :63. Adding `check` costs one entry + one usage line (:95-110 block, stderr, exit 2 on unknown). |
| C3 | `auditverify/main.go` live-API pattern `--from-url`/`--bearer`, `readFromURL` | ✅ | `--from-url`/`--bearer` bound at :102-104; `readFromURL` :403-448; `fetchEventPage` :450-473 hand-rolls `http.Client` with `Authorization: Bearer` :461 — the bare-client precedent the T-9 probe reuses. |
| C4 | `test/oidc_discovery_test.go:61-88`; no 404-sweep test exists | ✅ (line drift) | `TestDiscovery_AdvertisesRequiredFields` :61, `IssuerComesFromWithIssuer` :80, `EndpointsAreAbsoluteURLs` :88; 13 `TestDiscovery_*` tests total (:61-281; file is 290 lines — design draft's ":61-296" drifted); `grep 404\|NotFound` over the file: zero. The "no 404-sweep test" gap stands. Testkit confirmed: `newDiscoveryServer` **:21-50** (design draft said :31-50) = `sso.NewServer` + `defaultimpl.NewMemoryClientStore` seeded `{ID:"demo", Secret:"s", Active:true, AllowedScopes:["read","write"]}` + Ed25519 issuer + `httptest.NewServer` — exactly the green-path harness REQ-2/REQ-3 need, and the seeded client's non-empty `AllowedScopes` doubles as the restricted client T-8d requires. Fixture is unexported (`package ssotest`): reuse is by pattern, not literal import. |
| C5 | `server_discovery_config.go:139-152` `buildBaseMetadata` | ✅ (line drift) | Function :142-163; `AuthorizationEndpoint: base+PathLogin` :145, `TokenEndpoint: base+PathToken` :146, `JWKSURI` :147, `RevocationEndpoint` :148, `IntrospectionEndpoint` :149 (unconditional — a snaplink server always advertises the T-8a/T-8d/T-9 targets); `UserInfoEndpoint`/`EndSessionEndpoint` gated by `s.oidcGateOn()` :158-163 (`omitempty` — advertised-only). JSON names pinned in `protocols/oidc/metadata.go:15-19`. |
| C6 | `shared/core/consts.go:21` — `PathToken="/token"` | ✅ | :21 exactly; same block: `PathIntrospect="/token/introspect"` :22, `PathRevoke="/token/revoke"` :23, `PathLogin="/auth/login"` :20, `PathUserInfo="/userinfo"` :27, `PathLogout="/logout"` :28. `PathOIDCDiscovery="/.well-known/openid-configuration"` is in `interfaces/sso/server_discovery.go:18` (GET mounted :27; `handleJWKS` :386). |
| C7 | `server_token.go:190-207` — `rejectUnregisteredScopes` seam, plain `invalid_scope` body | ✅ (line drift) | Function at :203 (doc comment :189-202; called from `dispatchTokenGrant` :130-132). Plain body: `protocols/oauth/scoperegistry/reject.go:37` `ctx.JSON(400, core.ErrorBody(core.ErrInvalidScope))`; allowlist fallback: `internal/handler/tokengrant/token_client_credentials.go:40` — **same bytes**. `core.ErrorBody` = `{"error":code}` (`shared/core/error_body.go:11-16`); `ErrInvalidScope="invalid_scope"` (`shared/core/errors.go:170`). `ctx.JSON` encodes via `json.Encoder.Encode` → trailing `\n` (`shared/core/router.go:143-148`) — the byte-exact assertion target `{"error":"invalid_scope"}\n`. |
| C8 | `implementation-gate.md` T-2 definition | ✅ (content) | B4-3 row (:13): "T-2：sweep 全绿（广告端点绝不 404）；`metadata.token_endpoint == "/token"`". File is paragraph-per-line, so "line 13" has no line-level meaning — the doc's own caveat is correct. |

Load-bearing findings, independently confirmed:

| Finding | Verdict | Evidence |
|---|---|---|
| Router collapses method mismatch to 404 | ✅ (line citation corrected) | `StdRouter.ServeHTTP` is at `shared/core/router.go:276-320` — **not** 376-412 (that range holds `GateHTTPHandler`/`GatedRegistrar` docs; semantic claim unaffected). `req.Method != route.method → continue` :280, unmatched fall-through `http.NotFound` :319. A GET on a POST-only route is byte-identical to an unmounted path — canonical-method probing is mandatory. |
| `/token` accepts JSON bodies | ✅ | `oauthwire.BindParams` (`protocols/oauth/oauthwire/bind.go:24-46`) dispatches on Content-Type, JSON accepted; `server_token.go:30` binds via `bindOAuthParams` before client auth (:33 `authenticateTokenClient`). `apiclient.Do` sends `application/json` — no `Do`/`Get`/`Post`/`ReadBody` changes needed. |
| T-8a claim emission is wiring-conditional | ✅ | `buildAccessPayload` (`infrastructure/defaultimpl/issue_payload.go:27-51`): `iss/sub/scope/client_id/jti` unconditional; `TenantID` :49 stamped unconditionally, omitted by `omitempty` (`ed25519_types.go:50`); `roles` emitted only when `len(subject.Roles)>0` (`applyOptionalClaims` :85-88, field `ed25519_types.go:57`); `aud` only from `subject.Resources` (:101-104, polymorphic `audClaim` `ed25519_types.go:113-119`). `kid` in all three issuers' headers (`ed25519_issue.go:33`). Roles sources: user-token paths only — `server_login.go:108,120`, `server_oauth.go:90`, `token_refresh.go:279,310`; cc path builds a Roles-less Subject (`token_client_credentials.go:50-58`); admin `IssueTempToken` likewise (`grpcadmin/admin_tokens.go:174`). The expectation-flag matrix (REQ-3) is the only honest shape. |
| T-8d needs authenticated + restricted client | ✅ | `GrantedScopes` rule 2 (`protocols/oauth/oauthvalidate/scope.go:94-96`): nil client or empty `AllowedScopes` → pass-through. Both enforcement layers emit byte-identical bodies (`reject.go:37`, `token_client_credentials.go:40`). 200 probe response = genuine enforcement-absent failure. |
| T-9 probe: parseable body, zero creds | ✅ | `HandleIntrospect` binds the body :124-128 BEFORE client auth; empty body → 400 `invalid_request`; `authenticateIntrospectionClient` :389-392 (`id==""\|\|secret==""` → error) → 401 `core.ErrorBody(core.ErrInvalidClient)` :233-235. Body `{"token":"<dummy>"}` reaches the auth gate. |
| `apiclient.New` cannot express "no bearer" | ✅ | env fallback :57-59 means an exported `SSO_ADMIN_TOKEN` leaks a bearer into any apiclient probe. T-9 uses a bare `http.Client` (auditverify precedent). |
| smoke.sh exists but lacks the probes | ✅ | `ops/deploy/baremetal-ha/smoke.sh` (55 lines): discovery `grep '"issuer"'` + `readyz` loop + curl cc→introspect→revoke round trip when creds passed. No 404-sweep, no `token_endpoint` suffix assertion, no claims/kid check, no `invalid_scope` probe, no credential-less 401 probe. Gap stands. |
| `cmd/sso-ctl` at the 16/16 subdir ceiling | ✅ | `directory_fanout_test.go:35` `maxSubdirsPerDir = 16`; `dirSubdirExemptions` :66-71 has only `".":21` — no `cmd/sso-ctl` entry; `TestArchitecture_DirectorySubdirFanout` :127-131. `cmd/sso-ctl` has exactly 16 subdirs (apiclient, auditexport, auditverify, clientscmd, configcmd, entitiescmd, generate, hashcmd, importcmd, legacysync, migratecmd, sessionscmd, snapshotcmd, soc2report, tokenscmd, tui). A new subpackage fails the gate — the sweep lives in `apiclient` (which existing subcommands — tokenscmd, sessionscmd, clientscmd, entitiescmd, tui — already import; the "natural carrier" claim confirmed). |
| Default `http.Client` follows redirects | ✅ (security review, empirically verified) | Up to 10 redirects; 307/308 preserve method **and body** across hosts (the mint POST body carrying `client_secret` would be forwarded verbatim); same-hostname (any port) and subdomain redirects forward `Authorization`; a 302 discovery fetch would make the sweep parse an arbitrary URL as the discovery doc. The no-redirect pin (§2.4) is the single blocking amendment. |

## 2. Design decisions beyond the requirements

The requirements spec is adopted except for the review amendments recorded in
§0 (they supersede REQ-1's skip semantics, REQ-5's canonical-path shorthand,
and REQ-6's "apiclient.go do not modify"), one fail-fast validation, and the
pins below.

### 2.1 Effective-addr fail-fast validation (CLI F-3 + security item 2)

The requirements leave `--addr` handling to `apiclient.New`, which concatenates
`baseURL + path` and lets an invalid base surface as a per-probe transport
failure. This design adds one upfront validation in `CheckRun`: the
**effective** base URL — `SSO_ADMIN_ADDR` if set, else `--addr`, else
`DefaultAddr` (matching `apiclient.New`'s env-wins ordering at :60-61, so a bad
env value cannot bypass preflight and a bad `--addr` cannot exit 2 when a valid
env value would have overridden it) — must be:

1. parseable as an absolute URL with scheme `http` or `https`;
2. non-empty `Host` (`url.Parse("http://")` **succeeds** with an empty host and
   would otherwise fail per-row with confusing transport errors — exactly the
   failure mode this validation exists to prevent);
3. free of `userinfo` (Go's transport sends `Authorization: Basic
   base64(user:pass)` from URL userinfo — embedded credentials would go on the
   wire even over plain http *and* into R1/R4 diagnostics);
4. free of query and fragment (`apiclient.Do` concatenates `baseURL + path` — a
   query-bearing base fetches `https://h/?x/.well-known/...`, a different
   resource than the intended well-known document).

Violations exit 2 with a usage diagnostic on stderr; the rejection message
**never echoes the raw value** (it may contain credentials; §5 row 24).
Deliberate deviation, documented: auditverify classifies `url.Parse` failure as
a runtime error (exit 1, "parse base URL: %w"); exit-2-for-bad-URL is the
misuse class per the tree's missing-required-input convention, chosen for
deterministic fail-fast CLI diagnosis.

### 2.2 Probe-scope randomness (pin; security item 4)

`"sweep-probe-"` + 12 alphanumeric characters via `crypto/rand` (not
`math/rand`): the whole point is that the scope cannot be registered in any
deployment, and the requirements forbid `openid`/`device_sso` (scope.go:113-120
bypass — the design draft's "103-107" citation drifts, semantics identical).
Pins, per security review:

1. `crypto/rand.Read` failure → exit 1 with a stderr diagnostic — **never** a
   `math/rand` fallback (the global is runtime-seeded, not cryptographically
   unpredictable, and seedable);
2. explicit 62-char alphanumeric charset (rejection sampling or unpadded
   base64url);
3. the probe scope never appears on stdout **or any stderr diagnostic** (R19/
   R20/R22 bodies are server content, not the scope — pin it anyway);
4. the prefix already guarantees `≠ openid/device_sso`; 62¹² collision risk is
   negligible.

No determinism hazard: the value appears only in the mint request body, never
on stdout — byte-determinism (REQ-1) preserved.

### 2.3 Bare T-9 client construction (pin; security items 1/5)

`&http.Client{Timeout: 30 * time.Second}` — same timeout as `apiclient.New`
(:52-54), no `Authorization` header, no `client_id`/`client_secret` fields, no
assertion fields. Structural pins, per security review:

1. **Target = the advertised `introspection_endpoint`** (it doubles as the T-2
   row and is issued exactly once per run, REQ-5). When the field is absent,
   the T-9 group is **skipped** with a stderr notice — never fall back to
   probing the unadvertised canonical path (`PathIntrospect`), which would
   break the advertised-only invariant. (REQ-5's literal `<base>/token/
   introspect` is shorthand; the advertised-URL semantics are pinned here.)
   A skipped group forces `check INCOMPLETE` + exit 1 (§5 skip rule).
2. **Userinfo on any advertised endpoint URL = row failure** (extends row 2):
   Go's transport would attach `Authorization: Basic base64(user:pass)`
   automatically — the probe would not be credential-less in the byte sense.
3. **Dummy token is a fixed literal** `{"token":"sweep-probe-dummy"}`, never
   the minted T-8a access token (order-independent; a 200 "enforcement absent"
   response from T-8d can never be mistaken for a T-9 credential).
4. Structurally bearer-less: the bare client has no env-credential path
   (`apiclient.New`'s `SSO_ADMIN_TOKEN` fallback at :57-59 cannot apply), and
   pins 2 + the §2.1 userinfo rejection close the transport's auto-Basic path.

### 2.4 No-redirect pin (security item 1 — the blocking amendment)

Default `http.Client` behavior follows up to 10 redirects and forwards
credentials: 307/308 preserve method **and body** across hosts (the mint POST
body carrying `client_secret` and the T-8d probe scope is forwarded verbatim),
same-hostname (any port) and subdomain redirects forward `Authorization` (an
exported `SSO_ADMIN_TOKEN` would ride an apiclient GET to the redirect target),
and a 302 on the discovery fetch makes the sweep fetch and parse an arbitrary
URL as the discovery document — which then steers the sweep's subsequent
credential-bearing probes anywhere. That is the one live coercion vector
against "advertised-only".

Fix (the single change to a file the requirements marked "do not modify"): one
**additive** option in `apiclient.go` —

```go
// WithNoRedirect disables redirect following: CheckRedirect returns
// http.ErrUseLastResponse so the 3xx response is observed, never followed.
// Sweep probes use it so credentials can never be forwarded to a redirect
// target (307/308 bodies, same-host/subdomain Authorization).
func WithNoRedirect() Option {
    return func(c *Client) {
        c.http.CheckRedirect = func(*http.Request, []*http.Request) error {
            return http.ErrUseLastResponse
        }
    }
}
```

~6 lines, opt-in: the default client still follows redirects, so **existing
subcommands' behavior is untouched** (verified: `New` builds the client with
only `Timeout`; setting `CheckRedirect` replaces the nil default). `CheckRun`
constructs the sweep client as
`apiclient.New(apiclient.WithAddr(effectiveAddr), apiclient.WithNoRedirect())`.
Routing all probes through bare clients would still leave the A2-mandated
apiclient discovery fetch exposed, so the apiclient change is unavoidable.

**Row semantics under the pin:** truthiness rows treat any 3xx as pass
("non-404" without following — preserves A3 and the authorization_endpoint
login-page 302 case); content rows (discovery 200, jwks 200, mint 200, revoke
200, invalid_scope 400, introspect 401) fail on any 3xx. An operator behind an
http→https redirector points `--addr` at the final origin. Contract test:
`TestNew_NoRedirect` (§7 REQ-6 row).

## 3. API changes

### 3.1 New CLI surface — `sso-ctl check`

```text
sso-ctl check [flags]
  Deploy-tree live sweep: T-2 discovery truthiness + T-8a mint/claims/revoke +
  T-8d invalid_scope + T-9 credential-less introspect probes.
  Exit 0 = all four probe groups executed and passed; 1 = any executed check
  failed, or any group was skipped (check INCOMPLETE — check OK is never
  printed on a run that skipped a group); 2 = CLI misuse (incl. missing
  --client-id/--client-secret).

Flags:
  --addr string            base URL (default "http://127.0.0.1:8443";
                           SSO_ADMIN_ADDR env honored — env wins, per apiclient.New;
                           preflight validates the EFFECTIVE addr, flag or env)
  --client-id string       OAuth client ID (T-8a/T-8d; REQUIRED with --client-secret)
  --client-secret string   OAuth client secret (T-8a/T-8d)
  --scope string           space-separated scopes to request at mint (optional)
  --resource string        RFC 8707 resource indicator; repeatable (optional)
  --expect-tenant-id string  declare the minted token MUST carry this tenant_id (optional)
  --expect-roles           declare the minted token MUST carry a non-empty roles claim
                           (deterministic FAIL on the cc path — documented, §5 row 16)
  -h, --help               print usage to stderr, exit 0
```

Flag parsing: `flag.NewFlagSet("sso-ctl check", flag.ContinueOnError)` (the
tree's majority convention), then **explicitly** `if errors.Is(err,
flag.ErrHelp) { return 0 }` — with `ContinueOnError`, `-h`/`--help` makes
`fs.Parse` return `flag.ErrHelp`, and every existing `ContinueOnError` user
exits 2 because none special-cases it. This mapping is mandatory, not optional:
`sso-ctl check -h` dispatches straight to `CheckRun` and never reaches main.go's
help case. `check` becomes the first subcommand in the tree to do this —
deliberate, per A1's exit-0 help requirement; the help banner goes to stderr
(as all 16 subcommands do today). `--addr` is the only flag-vocabulary
divergence from the tree's `--from-url`/`--file`/`--dsn` style — defensible
because it matches the apiclient module's own vocabulary
(`DefaultAddr`/`WithAddr`/`EnvAddr`); the help text names the env override.

Misuse (exit 2, usage diagnostic on stderr): missing `--client-id` +
`--client-secret` (F-1: missing required input is the tree's universal misuse
class — configcmd `--file`, importcmd `--format`, legacysync env pw,
auditverify `--bearer`); `--client-id` without `--client-secret` or vice versa;
any of `--scope`/`--resource`/`--expect-*` without both credential flags;
invalid effective addr (flag **or** env, §2.1); unknown flag. Misuse
diagnostics never echo flag values (§5 row 24).

Output contract (REQ-1, determinism): stdout carries exactly one line per
executed check group, in fixed order (constant group-line literals — no URLs,
statuses, or counts embedded), plus a final `check OK` / `check FAIL` /
`check INCOMPLETE` line; stderr carries per-failure diagnostics (`endpoint
<url>: observed 404, expected non-404`), skip notices, and the
`SSO_ADMIN_TOKEN` notice (§4.5). Same deployment + flags ⇒ byte-identical
stdout. When `SSO_ADMIN_TOKEN` is exported, a stderr notice states the admin
bearer rides only to the advertised hosts on the GET rows and is never
forwarded past a redirect (under the §2.4 pin).

### 3.2 New Go surface

| Symbol | Location | Contract |
|---|---|---|
| `func CheckRun(args []string) int` | `cmd/sso-ctl/apiclient/check.go` | Flag parse (incl. `ErrHelp` → 0) → effective-addr + creds preflight → group orchestration → exit-code mapping. Registered as `"check": apiclient.CheckRun` in `main.go` subcommands map. |
| `func WithNoRedirect() Option` | `cmd/sso-ctl/apiclient/apiclient.go` (the one edit to that file) | `CheckRedirect` → `http.ErrUseLastResponse`; opt-in; ~6 lines after `WithAddr`; existing callers untouched. Contract test `TestNew_NoRedirect`. |
| `func validateBaseURL(string) error` | `check.go` | §2.1 rules: absolute, http(s), non-empty host, no userinfo, no query/fragment. Returns a reason string that never echoes the input. |
| `func redactURL(string) string` / `func sanitizeBody([]byte) []byte` | `check.go` | The single pair used by **every** stderr diagnostic: `redactURL` strips userinfo from echoed URLs (and from `url.Error` text — it embeds the request URL); `sanitizeBody` truncates to ~200 bytes and redacts `access_token`/`refresh_token`/`id_token`/`client_secret` JSON fields before printing. No diagnostic ever prints a raw flag value or a minted token. |
| `func probeScope() (string, error)` | `check.go` | §2.2: `crypto/rand` 62-char charset, `"sweep-probe-"` prefix; error → exit 1, no fallback. |
| `func sweepDiscovery(...)` / `probeRow` matrix | `check.go` (or `discovery.go` if the 500-line budget demands) | Data-driven probe table: `{field, method, body, assertionKind}` per §4; targets resolve from the **advertised** doc; fixed slice order, never map iteration. |
| `func mintAndVerify(...)` / `decodeJWT(...)` / `verifyClaims(...)` | `check.go` (or `token.go`) | T-8a mint, header/payload decode (base64url-raw), claims matrix. Mint/revoke/post-revoke/introspect targets resolve from the advertised `token_endpoint`/`introspection_endpoint` (on a coherent snaplink deployment these equal `base+PathToken`/`base+PathIntrospect`, matching REQ-3's spelling, while keeping the advertised-only invariant on misconfigured docs). |
| `func probeInvalidScope(...)` | `check.go` | T-8d, byte-exact comparison. |
| `func probeBareIntrospect(...)` | `check.go` | T-9, bare `http.Client`, advertised target only (§2.3). |
| `apiclient_test.go` | package test | Contract tests (REQ-6) incl. `TestNew_NoRedirect`. |
| `check_test.go` | package test | Sweep tests (REQ-1..REQ-5 criteria; §7). |
| `dispatch_test.go` (edit) | `cmd/sso-ctl/` (package main) | `TestSubcommands_CheckIsWired` beside `TestSubcommands_GenerateIsWired` (test-plan amendment: `subcommands` is package-private, so the registration assertion cannot live in `apiclient/`). |

### 3.3 Explicitly unchanged surfaces (narrowed per security review)

- Server: no endpoints, no `interfaces/sso/*` edits (60-file ceiling), no
  stores, no new error codes (`docs/error-codes.md` unchanged), no config keys
  (`docs/config-reference.md` unchanged), no OpenAPI change.
- `apiclient.Do/Get/Post/Delete/Patch/ReadBody/WriteJSON/WriteTable` — untouched;
  `New` gains exactly the one additive `WithNoRedirect` option (§2.4), opt-in,
  so the "untouched" claim now reads: *`apiclient.go`'s request/response surface
  is unchanged; `New` gains one additive option*. No typed helpers
  (`FetchDiscovery`/`TokenRequest`/`Introspect`) — that is the other
  direction's scope (requirements §7).
- `ops/deploy/*` scripts unchanged in this direction (optional adoption §6).

## 4. Compatibility constraints

1. **Fan-out ceilings (gate-backed).** No new subpackage under `cmd/sso-ctl`
   (16/16 verified, §1 C8 row). `apiclient` grows from 1 to ≤3 non-test files
   (≤10/dir gate); `check.go` target ≤450 lines — split within the package
   (`discovery.go`/`token.go`) if it would cross 500. `main.go` stays well
   under its own budget (+3 lines); `apiclient.go` +6.
2. **Per-function budgets.** Every new function ≤50 lines, cyclomatic
   complexity ≤15 — the probe matrix is data-driven rows, not nested branches
   (mirrors `readFromURL`'s shape). `if`-nesting ≤3 is AGENTS.md discipline,
   not a committed gate (review-enforced only); the data-driven-matrix
   rationale stands on its own.
3. **Import discipline.** `check.go` imports stdlib only (`flag`, `errors`,
   `net/http`, `net/url`, `encoding/json`, `encoding/base64`, `crypto/rand`,
   `strings`, `fmt`, `os`, `time`). No `protocols/*` imports; `apiclient` is
   reused, not re-derived. Tests may import `interfaces/sso` +
   `infrastructure/defaultimpl` (downward flow; testkit proven at
   `test/oidc_discovery_test.go:21-50` — reuse by pattern, the fixture is
   unexported).
4. **Wire-contract compatibility.** No server wire behavior changes; the sweep
   pins existing behavior: canonical-method probing (router 404 collapse),
   byte-exact error bodies (Encoder newline), advertised-only sweep (OIDC-gated
   endpoints never probed when absent), no-store/none (the sweep only observes
   credential-endpoint responses — it never asserts cache headers; T-8b/c/e are
   other directions).
5. **Credential hygiene (rewritten per security review).** Credential-bearing
   probes go via `apiclient` (body carries the client credentials). With the
   §2.4 pin, an exported `SSO_ADMIN_TOKEN` can never be forwarded past a
   redirect — the residual is "the admin bearer rides to the *advertised*
   hosts" on the discovery/jwks/endpoint GET rows; a stderr notice is emitted
   when it is exported (§3.1), and the T-2 GET rows' semantics do not depend on
   it. The T-9 probe is structurally incapable of carrying a bearer (bare
   client + userinfo rejection + advertised target only, §2.3).
   **Residual accepted disclosure (documented):** credential-bearing probes
   inherently disclose the client secret to the *advertised* token/introspect
   endpoints — the same trust set the deployment operator already holds; the
   sweep must run against trusted deployments with scoped credentials.
6. **Determinism.** Probe order fixed (slice, never map); random probe scope
   never printed (stdout or stderr); group-line literals constant; exit code is
   a pure function of (deployment, flags); skip notices stderr-only.
7. **No upward imports, no `cmd/` imports, no `layerExemptions` growth** — the
   new code lives in an existing, already-classified package.

## 5. Failure modes

Exit-code contract: 0 all four groups executed and passed · 1 any executed
check failed, or any group was skipped (final line `check INCOMPLETE` —
`check OK` is never printed on a run that skipped a group) · 2 CLI misuse
(incl. missing credentials, invalid effective addr).

**Skip rule.** A probe group is skipped only when its required advertised
target is absent: T-9 without an advertised `introspection_endpoint`; T-8a/
T-8d without an advertised `token_endpoint` (never reachable against a
snaplink server — both are unconditional in `buildBaseMetadata`, §1 C5). A
skipped group is a stderr notice, forces `check INCOMPLETE` + exit 1, and
never produces a group line on stdout — the auditverify "prefix verified …
not the full chain" precedent (:259-263), which never returns 0 on a partial
run. Optional endpoint rows (userinfo/end_session, row 6) are issued only when
advertised and are never "skipped" — they were never part of the contract.

**Redirect posture (under the §2.4 pin).** No probe follows a redirect.
Truthiness rows treat any 3xx as pass ("non-404" without following — preserves
A3 and the authorization_endpoint login-page 302). Content rows (discovery
200, jwks 200, mint 200, revoke 200, invalid_scope 400, introspect 401) fail
on any 3xx.

**Global diagnostic pins (security items 3/4).** One `redactURL`/`sanitizeBody`
pair is used by every stderr diagnostic; no diagnostic ever prints a raw flag
value, a minted token, or the probe scope. Claim values (kid/iss/sub/
client_id/scope/aud/tenant_id) are not secrets by nature, but URL-shaped
values (iss, aud, base) pass through `redactURL` for uniformity.

| # | Failure mode | Detection | Exit | Diagnostic (stderr) |
|---|---|---|---|---|
| 1 | Discovery fetch: non-200 (incl. any 3xx — redirects never followed), undecodable JSON, empty body | T-2 group | 1 | `discovery: GET <base>/.well-known/openid-configuration -> status <n>; expected 200 + JSON object` (base via `redactURL`; body never echoed) |
| 2 | Advertised endpoint URL unparseable, non-http(s) scheme, empty host, or **userinfo-bearing** | per-row preflight | 1 | `endpoint <field>: <reason>; row failed` — echoed URL via `redactURL` (userinfo stripped); the raw value is never printed (security items 1/2) |
| 3 | Advertised endpoint returns 404 (unmounted route — the T-2 truthiness failure); any other status incl. 3xx passes ("non-404") | per-row status check | 1 | `endpoint <field> <method> <url>: observed 404, expected non-404` (url via `redactURL`) |
| 4 | Transport error on any probe (timeout 30s, conn refused, TLS) | per-row error | 1 | `endpoint <field> <method> <url>: <error>` — `url.Error` embeds the full request URL incl. userinfo; the whole message passes through `redactURL` |
| 5 | `token_endpoint` path suffix ≠ `/token` (A4) | URL path suffix check | 1 | `token_endpoint <url>: path suffix "<path>" != "/token"` (url via `redactURL`) |
| 6 | `userinfo_endpoint`/`end_session_endpoint` absent from doc | — | — | not a failure; rows never issued (advertised-only; never "skipped") |
| 7 | Mint: non-2xx (incl. any 3xx), 200 missing `access_token`, malformed JWT (<3 parts / bad base64url) | T-8a group | 1 | `mint: status <n>` + body echo **only for non-2xx**, via `sanitizeBody` (≤200 bytes); decode failures print only the decode error — **never the token string, never the body** (security item 3: a 200-with-missing-`access_token` body *contains* the token) |
| 8 | Mint response contains `refresh_token` (cc never issues one) | negative assertion | 1 | `mint: unexpected refresh_token in cc response` (body never echoed) |
| 9 | Header `kid` empty or absent from `jwks_uri` JWKS; `jwks_uri` absent from doc | claims matrix | 1 | `claims: kid "<kid>" not in JWKS` / `claims: kid missing` / `claims: jwks_uri absent from discovery` |
| 10 | Header `typ` ≠ `at+jwt` | claims matrix | 1 | `claims: typ "<typ>" != "at+jwt"` |
| 11 | `iss` ≠ discovery `issuer` (B4 item 1 host-derived drift) | claims matrix | 1 | `claims: iss "<iss>" != discovery issuer "<issuer>"` (both via `redactURL`) |
| 12 | `sub`/`client_id` ≠ `--client-id` | claims matrix | 1 | `claims: sub "<sub>" != "<client-id>"` (and client_id) |
| 13 | `scope` misses a requested `--scope` value | claims matrix (when flag given) | 1 | `claims: scope "<scope>" missing "read"` |
| 14 | `aud` misses a `--resource` value (string/array accepted) | claims matrix (when flag given) | 1 | `claims: aud <aud> missing "https://api.example"` (via `redactURL`) |
| 15 | `tenant_id` absent or ≠ `--expect-tenant-id` | claims matrix (when flag given) | 1 | `claims: tenant_id "<v>" != "<T>"` / `claims: tenant_id absent` |
| 16 | `roles` absent under `--expect-roles` | claims matrix (when flag given) | 1 | `claims: roles absent — cc-path mints never resolve Subject.Roles; flag is a declaration, not a guess` (deterministic on the cc path by design — the flag exists so the failure is explicit, not silent) |
| 17 | Revoke non-200 (incl. any 3xx) | T-8a group | 1 | `revoke: status <n>, expected 200` |
| 18 | Post-revoke introspect ≠ `"active":false` | T-8a group | 1 | `revoke: token still active after revoke (active=<v>)` |
| 19 | T-8d: 400 but body not byte-identical to `{"error":"invalid_scope"}\n` | byte comparison | 1 | `invalid_scope probe: status 400 body <sanitizeBody (≤200 bytes)>; expected {"error":"invalid_scope"}\n` |
| 20 | T-8d: 200 (enforcement absent — empty allowlist AND unwired registry); also any 3xx | status check | 1 | `invalid_scope not enforced: probe scope was granted — the client's AllowedScopes is empty or no global scope registry is wired` — body-less by design (a 200 carries a real token); the probe scope is never printed (security item 4) |
| 21 | T-8d: 400 with a different code (`invalid_request`); also any 3xx | code check | 1 | `invalid_scope probe: error code "<code>", expected "invalid_scope"` |
| 22 | T-9: status ≠ 401 (incl. any 3xx) or body not byte-identical `{"error":"invalid_client"}\n` | byte comparison | 1 | `introspect probe: status <n> body <sanitizeBody>; expected 401 {"error":"invalid_client"}\n` |
| 23 | `SSO_ADMIN_TOKEN` exported during T-9 | by construction (bare client, advertised target, userinfo rejected) + contract test | — | impossible by construction; `TestIntrospect_NoAuthHeaderLeak` pins it; when exported, the §3.1 stderr notice applies to the GET rows only |
| 24 | Flag misuse: missing or partial creds, expectation flags without creds, invalid effective addr (flag **or** env), unknown flag | preflight | 2 | `check: <msg>` on stderr + usage() (configcmd precedent: `flag.NewFlagSet(..., flag.ContinueOnError)` + `progName+": <msg>"` + `usage()` + `return 2`, configcmd/main.go:87, 44-48, 57-61 — no `usageErr` helper exists in the tree). Never echoes flag values (esp. `--client-secret`) or the raw addr. `-h`/`--help` → usage on stderr, **exit 0** via the `flag.ErrHelp` special-case (F-2 — the tree's `ContinueOnError` convention returns 2 on `-h`; this deliberate mapping is A1-mandated). Exit-2-for-bad-URL is a deliberate deviation from auditverify's exit-1 runtime classification (F-3) |
| 25 | No credentials supplied | preflight | 2 | `check: missing required --client-id and --client-secret (T-8a/T-8d groups cannot run)` + usage; nothing executes. Supersedes REQ-1's "skipped with a stderr notice, exit unaffected" (F-1: missing-required-input = exit 2 misuse is universal in the tree; a skip-run must never print `check OK`) |

Failure aggregation: all executed probes run; every failure is collected;
stderr lists all diagnostics; exit 1 if any. No fail-fast mid-sweep (a broken
deployment reports its full surface in one run). This collect-all-failures
semantic is a deliberate, documented divergence from the tree's fail-fast
`Run` convention (every existing subcommand returns at the first error,
clientscmd `if !ok { return 1 }`, auditverify checkpoint-before-events) — for a
sweep the full failure surface in one run is the point (CLI F-5).

## 6. Migration steps

No server, config, data, or wire migration exists for this direction — the
server and all existing clients are untouched. The steps are release/adoption
steps only:

1. **Implement** (this direction): `check.go` + `apiclient_test.go` +
   `check_test.go` + the `WithNoRedirect` option in `apiclient.go` (the one
   edit to that file, §2.4) + `main.go` registration + `dispatch_test.go`
   `TestSubcommands_CheckIsWired`. No flags, env, or storage semantics change
   anywhere else.
2. **Gate** (AGENTS.md §2): `go build ./... && go vet ./...`; `go test -run
   'TestMaintainability_|TestArchitecture_' .` (proves the 16/16 subdir
   constraint held); `go test ./cmd/sso-ctl/... -race` (covers the dispatch
   test in the package-main root as well as apiclient); `go test ./test/ -run
   TestE2E -v`; `make ci`.
3. **Release**: ship the rebuilt `sso-ctl` binary. Backward compatible — the
   new subcommand is additive; older binaries keep working against the same
   server; the sweep requires no server version bump (it probes contracts the
   current server already keeps); `WithNoRedirect` is opt-in, so other
   subcommands' binaries are byte-behavior-identical.
4. **Operate**: run `sso-ctl check --addr $base --client-id $C --client-secret
   $S` against a deployment; gate on exit code. Credentials are **required**
   (exit 2 otherwise, per F-1); a run never prints `check OK` unless every
   group executed and passed.
5. **Optional adoption (separate change, not this direction)**: wire the
   subcommand into `ops/deploy/baremetal-ha/smoke.sh` (or deploy CI) replacing
   or supplementing the curl round trip, so the T-2/T-8/T-9 probes run on every
   deploy. The requirements' §5 "Optional adoption" note applies; smoke.sh
   stays untouched here.
6. **Rollback**: revert the `main.go` map entry, delete `check.go`, and revert
   the `WithNoRedirect` option (additive and inert — existing callers never
   pass it, so an intermediate binary that ships it is safe). There is no
   state, cache, or persisted artifact to unwind. Nothing in the server depends
   on the sweep's existence.

## 7. Testable acceptance mapping

Supplied acceptance A1-A8 → requirement → concrete test. Sweep and contract
tests live in `cmd/sso-ctl/apiclient/` (httptest only, no external services,
no `SSO_TEST_*`); **A1's registration test lives in `cmd/sso-ctl/
dispatch_test.go`** (package main — `subcommands` is package-private, so it
cannot be asserted from `apiclient/`; test-plan amendment, heir of
`TestSubcommands_GenerateIsWired`).

| Acceptance (verbatim) | REQ | Test | Criterion |
|---|---|---|---|
| A1 new `sso-ctl` subcommand | REQ-1 | `TestSubcommands_CheckIsWired` (**`cmd/sso-ctl/dispatch_test.go`**, beside `TestSubcommands_GenerateIsWired`) + `TestCheck_HelpExitsZero` (apiclient: `CheckRun(["-h"])`) | `subcommands["check"]` registered, non-nil; `sso-ctl check -h` prints sweep usage on stderr, exit 0 (via the `flag.ErrHelp` special-case, F-2) |
| A2 fetches `/.well-known/openid-configuration` via apiclient | REQ-2 | `TestSweep_GreenPath` (real `sso.NewServer`, testkit pattern of `oidc_discovery_test.go:21-50`); `TestSweep_DiscoveryFetchFail` (data-driven stub: 500, `not json`, empty body, **302** → all fail) | discovery fetched through `apiclient.Get` with `WithNoRedirect`; 200 + decodable JSON required; any 3xx fails (content row, no redirect followed) |
| A3 every advertised endpoint returns non-404 (userinfo/end_session when advertised) | REQ-2 | `TestSweep_GreenPath`; `TestSweep_AdvertisedOnly` (doc without userinfo/end_session → no probes issued, pass); `TestSweep_404RowFails` (one 404 endpoint → row fails, exit 1, stderr names field+method+URL); `TestSweep_BadSchemeRow` (data-driven: `file:///`, unparseable `%zz`, **empty host**, **`https://user:pass@host/...` userinfo** → row fails, zero requests, nothing echoed); `TestSweep_TransportErrorRow` (closed listener → per-row error, exit 1); `TestSweep_DecoyFieldNotFetched` (doc advertises `registration_endpoint` decoy → recorded requests contain no request to it; `issuer` is compared, never fetched) | canonical-method matrix; strictly "not 404" (3xx/405/500 pass); wrong-method results never interpreted; decoy fields never fetched |
| A4 token_endpoint path suffix == `/token` | REQ-2 | `TestSweep_TokenEndpointSuffix` (`https://host/oauth2/token` → A4 fails with observed vs expected suffix) | `strings.HasSuffix(u.Path, "/token")`; base-path prefix tolerated |
| A5 mints/revokes via client-credentials path; token carries kid + iss/aud/scope/client_id/tenant_id/roles | REQ-3 | `TestMint_ClaimsMatrix` (kid in JWKS, `typ=="at+jwt"`, iss==discovery issuer, sub/client_id==client, jti non-empty); `TestMint_ScopeContainsRequested`; `TestMint_AudContainsResource` (string and array forms); `TestMint_TenantIDExpectation` (tenant-bound client passes, non-tenant-bound fails with "tenant_id absent"); `TestMint_RolesExpectationFailsOnCC` (documented deterministic failure); `TestRevoke_RoundTrip` (revoke 200, post-revoke introspect `"active":false`); `TestMint_NoRefreshToken` (negative assertion) | expectation-flag matrix — undeclared claims never asserted absent; mint/revoke targets resolve from the advertised `token_endpoint` |
| A6 unregistered scope → byte-identical 400 `{"error":"invalid_scope"}` | REQ-4 | `TestInvalidScope_ByteExact` (stub 400 + exact bytes → pass); `TestInvalidScope_ExtraFieldFails` (`trace_id` variant → fail, sanitized body on stderr); `TestInvalidScope_EnforcementAbsent` (stub 200 → fail with enforcement-absent diagnostic); `TestInvalidScope_WrongCode` (`invalid_request` → fail) | `{"error":"invalid_scope"}\n` byte-for-byte; probe scope randomized per run (§2.2 pins), never `openid`/`device_sso` |
| A7 introspection without client credentials → 401 | REQ-5 | `TestIntrospect_NoCreds401` (live server → 401 `{"error":"invalid_client"}\n`); `TestIntrospect_NoAuthHeaderLeak` (env `SSO_ADMIN_TOKEN` set → recorded request has no `Authorization` header); `TestIntrospect_200Fails`; `TestIntrospect_400Fails`; `TestIntrospect_SkipWhenNotAdvertised` (stub doc without `introspection_endpoint` → group skipped: stderr notice, **no request to canonical `PathIntrospect`**, final line `check INCOMPLETE`, exit 1) | bare `http.Client`, advertised target only, parseable fixed-literal body, no creds; 401 specifically |
| A8 exit nonzero on any failure (deploy-tree gateable) | REQ-1 | `TestExitCodes` (0/1/2 matrix incl. misuse exit 2: partial creds, expectation flags without creds, bad `--addr`, **missing creds**, **bad `SSO_ADMIN_ADDR` env**; `-h` → 0); `TestCheck_NoCredentialsMisuse` (exit 2 + usage, nothing runs — replaces the draft's skip-run semantics, F-1); `TestCheck_T9SkippedIncomplete` (skipped group → exit 1 + `check INCOMPLETE`, never `check OK`); `TestStdoutDeterministic` (two runs against the **same** server instance: byte-identical stdout + checked-in golden constant; pins: constant group-line literals, fixed slice probe order, skip/notice text stderr-only) | 0/1/2 contract; `check OK` only when all groups executed and passed; golden stdout |
| — (closes the zero-test gap; includes the security pin) | REQ-6 | `TestDo_BearerHeader` (present with `WithToken`, absent without — env unset); `TestDo_JSONHeaders` (`Content-Type: application/json` + `Accept`); `TestNew_OptionEnvPrecedence`; `TestNew_NoRedirect` (httptest 302 → `Do` returns the 3xx response un-followed; a client **without** the option still follows — existing callers untouched); `TestReadBody_CapAndClose` (1MB cap, body closed) | contract tests pin exactly the behaviors the sweep depends on |

Failure-mode row coverage (test-plan amendment): rows 3, 5, 6, 15, 16, 19-25
are covered by the tests above; the draft's gaps — rows 1, 4, 7, 8, 9-14,
17, 18 — are closed by `TestSweep_DiscoveryFetchFail` (row 1), `TestSweep_
TransportErrorRow` (row 4), `TestMint_ResponseFail` (rows 7, 8 — data-driven:
400; 200 without `access_token`; 2-part JWT; bad base64url; 200 with
`refresh_token`; 302), `TestClaimsMatrix_FailureDiagnostics` (rows 9-14 — one
data-driven test over a stub-issued JWT per row, sharing the matrix function:
bad/absent kid, bad `typ`, wrong `iss`, wrong `sub`/`client_id`, missing
`scope`, missing `aud`), `TestRevoke_Non200Fails` (row 17), `TestRevoke_StillActiveFails` (row 18), plus the `TestSweep_BadSchemeRow` extension (row 2:
empty host, userinfo). After these additions **no failure-mode row lacks a
test**.

Green-path sweep tests run against the real `sso.NewServer` (defaultimpl
memory stores, Ed25519 issuer, seeded client `demo/s` with
`AllowedScopes: ["read","write"]` — the same fixture shape as
`test/oidc_discovery_test.go:21-50`, reused by pattern since the fixture is
unexported; its non-empty allowlist also satisfies T-8d's restricted-client
precondition).

## 8. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .   # proves 16/16 subdir ceiling held
go test ./cmd/sso-ctl/... -race                           # apiclient tests + dispatch_test.go wiring test
go test ./test/ -run TestE2E -v
make ci
```

Targeted tests beside the code per §7. The architecture gates additionally
prove: no new subpackage (`TestArchitecture_DirectorySubdirFanout`), no upward
imports (`architecture_layer_test.go`), and `apiclient` staying within
file/fan-out budgets (2-3 non-test files ≤ 10, `apiclient.go` ≤ 500 lines
after the +6-line amendment).
