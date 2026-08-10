# Design: make the B4-1 claims gate real — `--expect-issuer` pin, Host-variance probe, tenant_id exactly-once

Companion to `docs/architect-analysis/cmd-sso-ctl-b4-1-claims-gate-requirements.md`.
This document treats that spec (and the evidence summary that cites it) as
untrusted claims, records what was independently re-verified against the
worktree, and turns the requirements into a concrete, ordered design with API
changes, compatibility constraints, failure modes, migration steps, and
testable acceptance mapping.

## 1. Evidence verification verdict

Every citation was re-checked against the worktree (HEAD `6cb50de3`). All
evidence claims are **accurate**; the material corrections are C1-C6 below.
Notably, the evidence's own corrections (the cmd-default nuance, the refuted
device-leg premise, the flattened-view exactly-once restatement, the weak
`device_codes_test.go` citation) were each re-verified and confirmed.

| # | Claim | Verdict |
|---|---|---|
| E1 | `check.go:77-78` opt-in `--expect-tenant-id`/`--expect-roles`, wired at 116-117 | Confirmed exactly (check.go:77-78, 116-117) |
| E2 | `token.go:187-188` — `iss == ck.doc.Issuer` (discovery issuer) is the only issuer oracle | Confirmed exactly (token.go:187-188); `verifyClaims` spans 175-228 |
| E3 | `token.go:215-228` — tenant_id/roles asserted only when declared; diagnostic at 228 | Confirmed exactly; the diagnostic text at 228 matches verbatim |
| E4 | cc-path mints never resolve `Subject.Roles`/`Claims` (guaranteed-fail `--expect-roles`) | Confirmed — `internal/handler/tokengrant/token_client_credentials.go:51-57` builds `core.Subject{ID, Resources, ClientID, TenantID, TTL, ConfirmationJKT, ConfirmationX5TS256, ServingRegion}`; no `Roles`, no `Claims` |
| E5 | `server_discovery.go:251-256` — `resolveIssuer` falls back to `requestBaseURL` when unset/sentinel | Confirmed exactly (server_discovery.go:251-256); `requestBaseURL` = `middleware.BaseURL` (server_federation.go:40), scheme://host with trusted-proxy X-Forwarded honoring |
| E6 | Discovery issuer is request-base-derived in lockstep (`server_discovery_config.go:144`, override at 264-265) | Confirmed (line 62 seeds `base := requestBaseURL(...)`, line 144 `Issuer: base`, 264-265 `WithIssuer` override) |
| E7 | `issue_payload.go` — `TenantID` stamped unconditionally (line 46); `claimsWithoutEmittedKeys` dedup strip (116-131); bag marshals under nested `ext` (`ed25519_types.go:26`) | Confirmed exactly; `tenant_id`/`roles` omitempty fields at ed25519_types.go:50,57 |
| E8 | `config/config_load.go:60,70-71` — cmd default `server.issuer = "sso-server"` (deliberately NOT the SDK sentinel) | Confirmed — `DefaultServerIssuer = "sso-server"` with the documented divergence rationale; applied when empty |
| E9 | `token_device.go:92-105` — device mint never sets `Subject.Roles`; roles arrive via `dc.Attributes` (approval-time bag) | Confirmed — Subject has `Claims: dc.Attributes` and no `Roles`; `server_device.go:290-303` `applyDeviceDecision` stores `claims.Extra` into the code. The `device_codes_test.go` citation is indeed weak (code-generator unit test only) |
| E10 | Harness defect: `newLiveServer` (`check_test.go:71-89`) wires `sso.WithIssuer(addr)` but the JWT issuer is built without `WithEd25519Issuer` → minted `iss` = sentinel `"snaplink-sso"` ≠ discovery issuer | Confirmed by reading AND by running the suite: every live-server row fails with `claims: iss "snaplink-sso" != discovery issuer "http://127.0.0.1:PORT"` |
| E11 | 11 red apiclient tests; dominant root cause is E10; trace_id/addr-validation/status-400 rows are separate | Confirmed by running `go test ./cmd/sso-ctl/apiclient/`: SIX iss-misalignment rows (`TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestMint_ClaimsMatrix`, `TestMint_ScopeContainsRequested`, `TestMint_AudContainsResource/live-array-form`, `TestRevoke_RoundTrip`) plus out-of-scope rows (`TestIntrospect_Non401Fails/wrong-bytes` trace_id drift, `TestCheck_AddrValidation`, `TestSweep_AdvertisedURLRejection/*`, `TestMint_ResponseFail/status-400`). `TestSweep_TokenEndpointSuffix` is red but NOT iss-misalignment (correction to an earlier draft's grouping): its stub advertises `/oauth2/token`, which satisfies `strings.HasSuffix(path, "/token")` — the suffix diagnostic can never fire — and the stub mounts no `/oauth2/token` handler, so the truthiness row 404s first. It is a stale test expectation, not an implementation defect; fix the fixture to advertise a path that truly lacks the `/token` suffix (e.g. `/oauth2/tokenz`, updating the expected diagnostic) as part of this change's check_test.go edits, or track it with the out-of-scope rows. R5 does not touch it |
| E12 | `apiclient.Do` builds the request internally (`http.NewRequest` at apiclient.go:107) — a Host override must thread through the probe, not the shared `Client` | Confirmed (apiclient.go:98-129); the mint already bypasses `Client.Do` semantics via `probeClient` (token-less, no env fallbacks, no-redirect) |
| E13 | Minted `iss` is a fixed string in the stock server (issuer option value; sentinel default) | Confirmed — `ed25519_jwt_issuer.go:322-326` (`issuer: sso.DefaultIssuer`), `WithEd25519Issuer` at :178, `ed25519_issue.go:43` `buildAccessPayload(j.issuer, ...)`. The Host-variance probe therefore has verified pass/fail polarity (green on any stock deployment, fails only under a Host-derived mint) |
| E14 | Budgets: check.go 277, token.go 413, sweep.go 284, check_test.go 1345 | Confirmed (`_test.go` files are exempt) |
| E15 | `TokenIssuer` SPI shape usable for the regression fixture | Confirmed — `core.TokenIssuer` = `Issue/Validate/Revoke` (shared/core/spi.go:245-250); `Validate` (ed25519_validate.go:16) verifies signature + exp/nbf only, **never compares `iss`**; `WithEd25519Key` (ed25519_jwt_issuer.go:203) allows one shared key across per-request instances |

### Material corrections

- **C1 — the function budgets are already violated at HEAD (the spec's claim is wrong).**
  `go test -run 'TestMaintainability_' .` fails on the untracked WIP files:
  `check.go:CheckRun` 66 lines > 50, `token.go:(*checker).verifyClaims` 58
  lines > 50 **and** cyclo 19 > 15. The spec states "functions all under the
  50-line budget after the additions (split the Host-variance leg into its own
  function if verifyClaims grows past 50)" — the split is not conditional, it
  is already required. This design's refactor (§2.3, §2.4) is therefore
  load-bearing: it absorbs R1-R3 AND repairs the pre-existing gate violation in
  exactly the two functions the change touches. A separate pre-existing
  failure — `TestMaintainability_FileSizeBudget` on
  `infrastructure/defaultimpl/ed25519_jwt_issuer.go` (539 lines) — is in a
  committed file, untouched by this work, and reported separately.
- **C2 — R1.2's "no flag value echoed verbatim" is over-strict as written.**
  The existing iss row already echoes the redacted discovery issuer
  (`claims: iss %q != discovery issuer %q` with `redactURL`), and the declared
  issuer is operator-supplied configuration, not a secret. The correct
  property is the existing `redactURL` discipline: URL-shaped values pass
  through `redactURL` (userinfo stripped), and secret-bearing values (client
  secret, minted token, probe scope) are never echoed. Acceptance R1.2 is
  restated accordingly (§6).
- **C3 — the variance token's lifecycle is unspecified in the spec.** Leaving
  a valid cc token un-revoked until TTL contradicts the sweep's own revoke
  discipline ("no valid probe token outlives the run"). The design revokes the
  variance token through a `revokeToken` helper (the revoke POST only — the
  post-revoke introspection is not repeated for the second token; that leg's
  contract belongs to the first mint). The revoke is best-effort against a
  crash: the residual window between mint and revoke is TTL-bounded and
  documented in §4 F5 (defer-revoke considered and rejected there).
- **C4 (D4) — the Host-variance probe runs only when `--expect-issuer` is
  declared.** The spec's completion marker implies this ("with it declared …
  and additionally mints a second token"); making it always-on would detect
  more but breaks the "unset = byte-identical today" rollout property and adds
  a /token POST to every sweep run. Opt-in is recorded as a decision, not an
  omission.
- **C5 (D5) — `SSO_EXPECT_ISSUER` env parity is explicitly NOT implemented.**
  The spec permits it; flag-only keeps the surface minimal and matches the
  flag-only precedent of `--expect-tenant-id`/`--expect-roles`. Operators
  wiring the flag through their deploy tooling get env parity for free.
- **C6 — the fixture issuer must share one Ed25519 key across per-request
  instances.** A naive per-request `NewEd25519JWTIssuer(WithEd25519Issuer(...))`
  generates a fresh key per mint, breaking mint/validate/revoke coherence and
  the JWKS kid row. `WithEd25519Key` + the fact that `Validate` never checks
  `iss` make a shared-key wrapper the correct fixture shape (§2.6).

## 2. API changes

### 2.1 CLI: `--expect-issuer string` (check.go)

New opt-in flag in `CheckRun`'s flag set and `usage()`:

```text
--expect-issuer string  declare the minted token MUST carry exactly this iss;
                        the sweep also requires iss == the discovery issuer
                        and runs the Host-variance probe (optional)
```

New `checker` field `expectIssuer string` (sweep.go:52-65 struct), wired from
the flag. No env fallback (D5). No URL validation on the flag value: the
comparison is a literal string equality against the minted `iss`, so a typo'd
declared value fails closed via the normal diagnostic — no new exit-2 path, no
new validation surface.

### 2.2 `CheckRun` split: `parseCheckFlags` (check.go)

`CheckRun` is 66 lines at HEAD (C1). Extract the parse/validate/help surface
(flag definitions, `fs.Parse` handling, missing-credentials check,
`effectiveAddr` + `validateBaseURL`) into:

```go
// checkFlags carries the parsed check invocation.
type checkFlags struct {
    addr, clientID, clientSecret, scope string
    resources                            stringList
    expectTenantID                       string
    expectIssuer                         string
    expectRoles                          bool
}

// parseCheckFlags parses and validates the check CLI surface. On help or
// misuse it prints and returns handled=true with the exit code (0 help, 2
// misuse); on success handled=false and f is valid.
func parseCheckFlags(args []string) (f *checkFlags, code int, handled bool)
```

`CheckRun` keeps the runtime surface (probe-scope generation, the
`SSO_ADMIN_TOKEN` warning, checker construction, group execution, verdict):
~35 lines after the split. Both functions land under 50 lines.

### 2.3 Mint refactor: `mintBody` / `mintWithHost` / `mintPost` (token.go; `mintPost` lands in sweep.go per the §3 budget row)

`mint()` (47 lines, grows with the variance leg if left inline) is split into
three focused pieces; `mint()` keeps its exact signature and side effects
(`ck.header`/`ck.payload`):

```go
// mintBody returns the T-8a mint request body (same shape as today).
func (ck *checker) mintBody() map[string]any

// mintPost sends the mint body to target with an optional Host-header
// override. Built directly (http.NewRequest + req.Host) because
// apiclient.Do constructs the request internally; the shared Client
// transport is never touched. The http.Client is probeClient(target).http
// REUSED, not mirrored — token-less (no token field), 30s timeout, and
// CheckRedirect: rejectRedirect (http.ErrUseLastResponse: the 3xx is
// observed, never followed) hold by construction, and the posture is
// pinned by TestSweep_RedirectNotFollowed. Never ck.client.http: New()'s
// SSO_ADMIN_TOKEN env fallback would attach a bearer to the variance
// mint. Never a fresh &http.Transport{}: a zero-value Transport disables
// h2, drops HTTP(S)_PROXY env handling, and loses connection-pool reuse
// versus today's mint — probeClient's nil Transport rides DefaultTransport
// (ForceAttemptHTTP2: true) exactly as the existing mints and T-8d do;
// TestHostVariance_Posture pins ProtoMajor parity. The override is set via
// the req.Host FIELD, never req.Header.Set("Host", ...): on the h2 path Go
// silently drops the Host header ("Host is :authority, already sent") and
// the variance leg would become a silent no-op while h1 would carry it.
// req.Host overrides only the wire Host header; the dial stays on
// req.URL.Host (Go's http.Request contract), so the connection always
// targets the advertised endpoint's address and a redirect Location can
// never steer the secret. THE single transport point for both mint legs
// AND the variance preflight: when the B4-4 form campaign lands, the
// Content-Type and body encoding flip here once and every leg follows.
func mintPost(target string, body map[string]any, host string) (*http.Response, error)

// mintWithHost performs the cc mint; a non-empty host overrides the request
// Host header (variance leg) while the connection still targets the
// advertised token_endpoint.
func (ck *checker) mintWithHost(host string) (token string, header, payload map[string]any, diags []string)

func (ck *checker) mint() (string, []string) {
    token, h, p, diags := ck.mintWithHost("")
    if p != nil {
        ck.header, ck.payload = h, p
    }
    return token, diags
}
```

`mintPost` mirrors `apiclient.Do`'s header semantics minus the bearer:
`Content-Type: application/json` (B4-4: form-encoded), `Accept:
application/json`. `req.Host` is set only when non-empty; per Go's
`http.Request` contract the dial target remains the URL's host while the Host
header is overridden on the wire.

### 2.4 `verifyClaims` split + R1 + R3 (token.go)

`verifyClaims` is 58 lines / cyclo 19 at HEAD (C1). Split along the existing
unconditional/declared seam; the R1 and R3 additions land inside the new
functions, not in the dispatcher:

```go
// verifyClaims runs the REQ-3 claims matrix: unconditional JWT rows,
// the issuer rows, then the declared rows.
func (ck *checker) verifyClaims() []string {
    var diags []string
    diags = append(diags, ck.verifyJWTClaims()...)
    diags = append(diags, ck.verifyIssuerClaims()...)
    diags = append(diags, ck.verifyDeclaredClaims()...)
    return diags
}
```

- `verifyJWTClaims` — kid/typ/sub/client_id/jti rows (verbatim from today).
- `verifyIssuerClaims` — the existing `iss != ck.doc.Issuer` row, then **R1**:

```go
if ck.expectIssuer != "" && iss != ck.expectIssuer {
    diags = append(diags, fmt.Sprintf("claims: iss %q != declared issuer %q",
        redactURL(iss), redactURL(ck.expectIssuer)))
}
```

  Both rows always run (no short-circuit); a wrong minted `iss` yields both
  diagnostics in fixed order. When `--expect-issuer` is unset the second row
  is dead code — byte-identical behavior to today (C4).
- `verifyDeclaredClaims` — the scope/aud/tenant_id/roles groups, with the
  tenant group extracted as `verifyTenantClaim` and roles kept as
  `verifyRolesClaim`. **R3** inside `verifyTenantClaim`, after the value
  match:

```go
if ck.expectTenantID != "" {
    tid, _ := p["tenant_id"].(string)
    if tid != ck.expectTenantID {
        // existing absent/mismatch rows, unchanged
    } else if ext, ok := p["ext"].(map[string]any); ok {
        if _, dup := ext["tenant_id"]; dup {
            diags = append(diags, "claims: tenant_id present in ext bag and as a top-level claim — claimsWithoutEmittedKeys strip missing")
        }
    }
}
```

  Exactly-once is defined over the flattened view (top-level `tenant_id` ∪
  `ext` bag), per D2: `decodeJWT` yields `map[string]any`, so `p["ext"]` is
  the decoded bag. The dedup row fires only when the top-level value matched
  (otherwise the absent/mismatch row is the true statement; both rows firing
  would be noise). Absence of `ext` entirely satisfies the assertion.

Post-split function lengths: `verifyClaims` 8, `verifyJWTClaims` ~22,
`verifyIssuerClaims` ~14, `verifyDeclaredClaims` ~20, `verifyTenantClaim`
~16, `verifyRolesClaim` ~8 — all ≤ 50 lines and ≤ 15 cyclo (C1 repaired).

### 2.5 R2: Host-variance probe (sweep.go; `runT8a` wiring in token.go)

```go
// hostVarianceHost is the fixed, non-echoed Host override for the variance
// mint. .invalid is RFC 2606 reserved — it can never collide with a real
// deployment host.
const hostVarianceHost = "sweep-host-variance.invalid"

// hostVarianceProbe mints a second token against the same advertised
// token_endpoint with an overridden Host header and asserts its iss is
// byte-identical to the first mint's — the B4-1 "iss never Host-derived"
// oracle, scoped to the cc mint leg (T-8a): the probe observes cc-path
// issuance only, so a Host-derived issuer on the device or auth-code legs
// would be silently green by scope (R4 deferred, §8). Runs only when
// --expect-issuer is declared (C4). The variance
// token is revoked before returning (C3).
func (ck *checker) hostVarianceProbe(firstISS string) []string
```

Assertions, in order (all failures are `claims:`-prefixed stderr rows that
force `mint: FAIL` / exit 1 through the existing runT8a plumbing):

0. Preflight (F3a mitigation, rides `mintPost`): a variance-Host POST with
   the real `client_id` and the fixed dummy secret `sweep-invalid-secret`
   (a non-secret constant, never the real one), requiring the oracle-safe
   `401 invalid_client` — server_token_clientauth.go collapses every
   client-auth failure to that shape (wrong secret, unknown client,
   mTLS-missing, public-cc). Any other status or a transport error ABORTS
   the probe before the credentialed mint:
   `claims: host-variance preflight: status %d, expected 401 invalid_client
   — the variance Host did not reach the advertised token endpoint; aborted
   (no credentials sent)`. Byte-exactness is deliberately NOT asserted
   (that contract belongs to T-8d/T-9); the preflight proves routing, not
   the error envelope. This converts F3's credential-bearing rejection
   into a dummy-credential probe and stops live-secret delivery to
   non-snaplink misrouted upstreams (F3a); a credential-compatible wrong
   upstream (a staging mirror holding the same client) still passes — that
   residual is covered by the runbook + credential scoping (§4 F3a). Cost:
   one extra /token POST (and one global rate-limit slot — the 401 is
   answered at client auth, so the per-grant-type `client_credentials` bucket
   is never touched) per run when `--expect-issuer` is declared; full
   accounting in §4.1.
1. Mint succeeds: 200 + `access_token`. Non-2xx →
   `claims: host-variance mint: status %d%s` (existing `bodyEcho` sanitizer);
   transport errors → `claims: host-variance mint: %s` (`redactURL`).
2. `iss2 == firstISS` (byte-identical), else
   `claims: iss %q differs across Host variance` — the echoed `%q` is the
   mint-2 iss CLAIM through `redactURL`, never the mint-2 token (the token
   is decoded, compared via its claims, and discarded).
3. `iss2 == ck.doc.Issuer` (the existing discovery row applied to the second
   mint; same diagnostic shape as `verifyIssuerClaims`).
4. `iss2 == ck.expectIssuer` (the R1 pin applied to the second mint; same
   shape). Rows 2-4 are redundant given row 2 plus the first mint's rows
   (transitive equality), but explicit beats implicit for a security gate.
5. `ck.revokeToken(out.AccessToken)` — the revoke POST only; failures fold
   into the returned diags.

Echo audit (C2) — every emission path above against the no-secret-echo
rule (the minted token and the client secret must never reach stderr):

| Emission | Diagnostic | Redaction | Never echoed |
|---|---|---|---|
| F1 / R1 rows, both mints (mint-1 `verifyIssuerClaims` + mint-2 row 4) | `claims: iss %q != declared issuer %q` | `redactURL` on BOTH sides (minted iss claim, declared issuer) | minted token, client secret |
| F2 / row 2 | `claims: iss %q differs across Host variance` | `redactURL` on the mint-2 iss claim | mint-2 token |
| row 3 | `claims: iss %q != discovery issuer %q` | `redactURL` on both sides | — |
| F3 / row 1 non-2xx | `claims: host-variance mint: status %d%s` | `bodyEcho` → `sanitizeBody`: `access_token`/`refresh_token`/`id_token`/`client_secret` values redacted, 200-byte truncation | token/secret inside the echoed body |
| row 1 transport | `claims: host-variance mint: %s` | `redactURL` | — |
| row 1 200-without-access_token | `mint: response has no access_token` | body never echoed (a 200 body may contain the real token) — same rule as `mint()` | 2xx body |
| F5 / row 5 | `revoke: …` (existing shapes) | status-only; `redactURL` on transport errors; no body echo | revoked token (request-body only) |
| F3a / row 0 | `claims: host-variance preflight: status %d, expected 401 …` | status-only; no body echo; the dummy secret is a fixed non-secret constant | client secret (never sent on this leg) |

`hostVarianceProbe` stays ≤ 50 lines by extracting the preflight into
`variancePreflight(target) []string` (same in-package transport).

`runT8a` wiring, immediately after the `verifyClaims` loop:

```go
if ck.expectIssuer != "" {
    firstISS, _ := ck.payload["iss"].(string)
    for _, d := range ck.hostVarianceProbe(firstISS) {
        fmt.Fprintln(os.Stderr, d)
        failed = true
    }
}
```

`runT8a` stays ~38 lines. The variance leg prints nothing on stdout (the
green-path `goldenGreenStdout` is unchanged: `mint: OK` is printed exactly
once).

`revoke` (token.go) is split into `revokeToken(token) []string` (the revoke
POST + status assertion) and `revoke(token) []string` = `revokeToken` +
post-revoke introspection — the variance leg reuses only the former (C3).

### 2.6 Test-harness changes (check_test.go)

**R5 — `newLiveServer` issuer alignment.** Wire the JWT issuer name so the
minted `iss` equals the discovery issuer:

```go
sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(
    defaultimpl.WithEd25519Issuer(addr),
    defaultimpl.WithEd25519TokenTTL(time.Minute),
)),
```

This repairs the six pre-existing iss-misalignment failures (E11) and is the
hard prerequisite of the R1/R2 green rows.

**R2 regression fixture — `hostDerivedIssuer`.** A `core.TokenIssuer` that
stamps `iss` from the request Host — the production `resolveIssuer` /
`requestBaseURL` fallback shape the B4-1 clause forbids:

```go
// hostDerivedIssuer is the R2 regression fixture: minted iss derives from
// the request Host instead of a fixed configured value. One shared Ed25519
// key keeps mint/validate/revoke and the JWKS advertisement coherent across
// the per-request signing instances (C6); Validate never compares iss
// (ed25519_validate.go), so the canonical instance validates every token.
type hostDerivedIssuer struct {
    key ed25519.PrivateKey
    kid string
    ttl time.Duration
    base *defaultimpl.Ed25519JWTIssuer // canonical: Validate/Revoke/JWKS
}

func (h *hostDerivedIssuer) Issue(ctx context.Context, sub *sso.Subject, scopes []string) (*core.Token, error)
func (h *hostDerivedIssuer) Validate(ctx context.Context, token string) (*core.TokenClaims, error)
func (h *hostDerivedIssuer) Revoke(ctx context.Context, token string) error
func (h *hostDerivedIssuer) JWKS(ctx context.Context) ([]core.JWK, error)
```

- `Issue` reads the request Host from a context stash installed by a wrapping
  middleware (the server handler chain passes `ctx.Request().Context()` into
  `TokenIssuer.Issue` — token_client_credentials.go:50), builds
  `NewEd25519JWTIssuer(WithEd25519Key(h.key), WithEd25519Issuer("http://"+host),
  WithEd25519KeyID(h.kid), WithEd25519TokenTTL(h.ttl))`, and delegates.
- `Validate`/`Revoke`/`JWKS` delegate to `base` (shared key; the deny list
  lives in the canonical instance so revocation survives across requests).
- Fixture server: `sso.NewServer` with `WithTokenIssuer("jwt",
  hostDerivedIssuer)` and **no `WithIssuer`** — discovery issuer is then
  request-base-derived, i.e. mint 1's `iss` == discovery issuer (the lockstep
  blind spot reproduced), while mint 2's `iss` == `http://sweep-host-variance.invalid`
  ≠ mint 1 → the variance row fires with everything else green. Same demo
  client seed as `newLiveServer` (T-8d precondition).
- Fixture robustness: `Issue` MUST return an error when the Host stash is
  absent from ctx (never mint with a default/empty host) so a middleware
  wiring regression fails the mint loudly instead of minting a silently
  wrong `iss`.

**Pinned stderr signature of `TestExpectIssuer_HostVarianceFails`.** The
variance leg's own row 3 (§2.5) reuses the standard discovery diagnostic,
so the regression run's stderr DOES contain `!= discovery issuer` — from
mint 2. The lockstep blind spot is asserted by counting and by the row's
value, not by a plain NotContains (which would fail on a correct
implementation; mint-1 and mint-2 rows are textually identical shapes, so
"for the first mint" is not implementable by substring alone):

```text
claims: iss "http://sweep-host-variance.invalid" differs across Host variance
claims: iss "http://sweep-host-variance.invalid" != discovery issuer "<srv.URL>"
claims: iss "http://sweep-host-variance.invalid" != declared issuer "<srv.URL>"
```

Exactly one `!= discovery issuer` row total, and it is mint-2's — the
variance host value tags its origin (no other row can carry it); a mint-1
discovery row would read `claims: iss "<srv.URL>" != discovery issuer` and
its presence means the blind spot was NOT reproduced (fixture misbuilt).
The three rows are pinned verbatim and in order (differs → discovery →
declared); the preflight (row 0) is silent on success — a 401 is the
expected oracle answer, not a diagnostic — so the pinned signature is
unaffected by it; stdout is the constant `discovery: OK\nmint: FAIL\ninvalid_scope:
OK\nintrospect: OK\ncheck FAIL\n`; exit 1. Assertion:

```go
varianceISS := "http://" + hostVarianceHost
if n := strings.Count(errOut, "!= discovery issuer"); n != 1 {
    t.Errorf("stderr has %d discovery-mismatch rows, want exactly 1 (mint-1 green, mint-2 only):\n%s", n, errOut)
}
if !strings.Contains(errOut, fmt.Sprintf("claims: iss %q != discovery issuer", varianceISS)) {
    t.Errorf("stderr missing mint-2's discovery row: %q", errOut)
}
if strings.Contains(errOut, fmt.Sprintf("claims: iss %q != discovery issuer", srv.URL)) {
    t.Errorf("mint-1 fired the discovery row — lockstep blind spot not reproduced: %q", errOut)
}
want := fmt.Sprintf("claims: iss %q differs across Host variance\n"+
    "claims: iss %q != discovery issuer %q\n"+
    "claims: iss %q != declared issuer %q\n",
    varianceISS, varianceISS, srv.URL, varianceISS, srv.URL)
if errOut != want {
    t.Errorf("stderr = %q, want pinned signature %q", errOut, want)
}
```

## 3. Compatibility constraints

| Surface | Constraint |
|---|---|
| CLI | New opt-in flag only. `--expect-issuer` unset ⇒ behavior byte-identical to today, including stdout golden (`discovery: OK\nmint: OK\ninvalid_scope: OK\nintrospect: OK\ncheck OK\n`), exit-code contract (0/1/2), and stderr text. The variance probe and the R1/R3 rows are dead paths unless declared (C4) |
| Shared client | `apiclient.go` (the committed file) is **not modified**. The Host override rides `mintPost`, a package-local probe transport; `Client.Do`/`Get`/`Post` semantics unchanged for every other subcommand |
| Server | No server-side change anywhere. B4-1's "allowlist" is satisfied sweep-side by the operator-declared pin; `resolveIssuer`'s fallback stays deliberate SDK behavior (it becomes observable, not altered) |
| Wire | The variance mint is a second POST to the already-advertised `token_endpoint` with the same body/credentials; only the Host header differs. No new route, method, or body shape. No bearer is ever attached to either mint (posture comment in check.go:25-32 preserved); the no-redirect pin applies to the variance transport |
| B4-4 coupling | The mint body's wire shape is owned by one function (`mintPost`) — covering the two mint legs and the variance preflight ONLY. If the B4-4 form-urlencoded campaign lands first, the Content-Type + encoding flip there once and both mint legs follow; if this lands first, B4-4 flips the same single point. The two campaigns land in the same shape without a second sweep change. NOT in `mintPost`: the T-8d invalid-scope probe, the revoke POST, and the post-revoke introspection POST send JSON credential bodies via `probeClient.Post` directly (token.go: `runT8d`, `revokeToken`/`revoke`, post-revoke introspection) — under B4-4's strict enforcement those call sites need their own flips; the single-point claim must not be over-read |
| Trusted proxies | The variance probe overrides the direct Host header, never `X-Forwarded-Host`. Copying edges (nginx `proxy_set_header X-Forwarded-Host $host` — the standard shape) propagate the variance Host into XFH, so a base-deriving server (requestBaseURL → middleware.BaseURL; XFH replaces r.Host when ForwardedHeadersTrusted) mints `iss2` = variance host and the probe FIRES — derivation through X-Forwarded-Host is detected, not masked. Forcing edges (XFH := constant) erase the variance: both mints see the constant → green. That blind spot is an irreducible client-side oracle boundary (the stimulus never reaches the server) and is acceptable for a security gate because the minted value is then edge-config-derived (stable, not client-influenceable — B4-1's operational concern), the R1 pin still fires when the forced value diverges from the operator-declared issuer, and the runbook precondition (§5 step 4) requires server-side issuer configuration (§4 F3b) |
| Budgets | Post-refactor: check.go ~290 lines; token.go ~445 lines, sweep.go ~370 lines — the preflight makes the planned move certain: `mintPost` + `hostVarianceProbe` + `variancePreflight` live in sweep.go (284 + ~85 < 500) instead of token.go. All functions ≤ 50 lines / cyclo ≤ 15 (C1 repaired) |
| Test state | The six iss-misalignment rows flip green via R5. `TestSweep_TokenEndpointSuffix` (stale suffix expectation — see E11) receives the one-line fixture fix in this change (advertise `/oauth2/tokenz`, expect the matching diagnostic) or joins the tracked list; the out-of-scope rows (trace_id drift, addr-validation, AdvertisedURLRejection, status-400) stay red and tracked; this change neither fixes nor masks them |

## 4. Failure modes

| # | Trigger | Observed behavior | Mitigation / notes |
|---|---|---|---|
| F1 | Operator declares `--expect-issuer` that differs from the minted `iss` (typo, stale value, or a mint regression) | `claims: iss %q != declared issuer %q` on stderr; `mint: FAIL`; exit 1 | Fail-closed by design. Both values pass `redactURL` (C2). The discovery row also fires when the minted value is broken, giving two independent diagnostics |
| F2 | Host-derived `iss` regression in the deployment (the B4-1 clause violation) | Mint 1 green (lockstep blind spot: `iss` == discovery issuer), mint 2 fires `claims: iss %q differs across Host variance` (+ discovery + declared rows on the second mint); exit 1 | This is the probe's entire purpose; the regression fixture (§2.6) proves the polarity: green on stock servers (E13), red exactly under this shape |
| F3 | A middlebox/edge between the sweep and the server rejects the unknown Host header (`sweep-host-variance.invalid`) | The preflight fails FIRST: `claims: host-variance preflight: status N, expected 401 invalid_client …` (or the transport-error shape on a connection drop); exit 1 — no live credential is ever sent to the rejecting device (the preflight body carries the fixed dummy secret). Rejection flavors: h1 400/421/502, h2 421 Misdirected Request (RFC 9113 §9.1.2), or a connection reset | Known false-positive risk on Host-validating proxies — which enforce a stricter-than-RFC policy: RFC 9112 §3.2 mandates a matching Host only for absent/duplicate/invalid values, and a stock Go server accepts the mismatch (RFC 9110 §7.2 routing-poisoning warning). `.invalid` (RFC 2606) never collides with a real deployment host but makes allowlist-based rejection deterministic — raising the false-positive rate even as it guarantees no collision; the diagnostic names the probe; the opt-in flag is the operator's off switch (C4). No dial-level SSRF: the TCP target is always the advertised endpoint's address — but a Host-routing proxy can still steer the request at the application layer (F3a, F3c) |
| F3a | Host-ROUTING L7 proxy (Envoy vhost / nginx server_name match, k8s nginx-ingress): no vhost matches `sweep-host-variance.invalid`. With a default route, the variance POST — carrying the live client secret — is forwarded to a different upstream; without one (no catch-all backend), the edge rejects the request itself (404/421) | The preflight discriminates: a non-snaplink upstream (404/502/HTML page) → preflight abort, no credentials sent. A snaplink-shaped upstream (another server, or a staging mirror holding the same client) answers the oracle-safe 401 invalid_client and the credentialed mint proceeds — live credentials are delivered to that upstream (rejected unless it holds the same client). Dead-vhost rejection (no catch-all, e.g. k8s nginx-ingress): preflight abort → FALSE POSITIVE on a compliant deployment — same signal class as F3, different trigger (routing, not Host validation) | Three-layer mitigation, all warranted: (1) runbook prohibition — the probe's validity precondition is Host pass-through; verify the edge's unknown-Host default route before enabling `--expect-issuer`, or run the sweep inside the trust zone (direct to the server) (§5 step 4); (2) credential scoping — the sweep client must be dedicated, low-scope, revocable: the edge already terminates TLS on the same credential path, so the marginal exposure is misrouting accidents, bounded by the sweep client's scope; (3) probe design change — the credential-less preflight (row 0) eliminates delivery to non-snaplink endpoints and to rejecting middleboxes. Residual: a credential-compatible wrong upstream is indistinguishable by ANY client-side oracle (two servers with byte-identical wire behavior); covered by (1)+(2). A throwaway variance-credential variant was considered and rejected: it preserves the assertion (iss is credential-independent on the cc path) but adds CLI surface and provisioning for marginal gain |
| F3b | Host-REWRITING proxy (nginx `proxy_set_header Host $upstream`, Envoy `host_rewrite`/`auto_host_rewrite`) silently normalizes the variance Host to the upstream | FALSE GREEN: mint 2 sees the normalized Host, mints `iss2 == iss1`, no diagnostic — the deployment looks healthy while the issuer derives from the upstream host (B4-1 violated) | Irreducible for any client-side Host-variance probe: the stimulus is erased before the server; even a two-Host variance is blind (both normalized). The R1 pin is the normalization-surviving complement: mint-1 iss is compared against the operator-declared CANONICAL issuer, and a rewritten upstream host diverges from it unless the operator declared the internal host. Runbook: no Host rewriting on the sweep path; `--expect-issuer` must carry the external canonical issuer, never the upstream/internal host. Residual (declared issuer == upstream host): operator error, documented (§5 step 4) |
| F3c | Host-ROUTING to a different LIVE backend whose issuer differs (multi-tenant vhost catch-all, or a default route landing on a second server with its own configured issuer) | Probe fires red: `claims: iss %q differs across Host variance` — polarity CORRECT: the deployment's minted `iss` genuinely varies with the request Host, which IS the gated property — but the mechanism is edge routing, not code derivation, and the diagnostic attributes the wrong cause | The true-positive row the design must not mislabel as its own regression shape. Runbook: verify the unknown-Host default route before enabling `--expect-issuer` (§5 step 4); treat a red variance row as "iss is Host-dependent" (edge or code) and confirm the attribution before acting |
| F4 | The `claimsWithoutEmittedKeys` dedup strip regresses on a bag-carrying mint path (tenant_id in both top-level and `ext`) | `claims: tenant_id present in ext bag and as a top-level claim — claimsWithoutEmittedKeys strip missing`; exit 1 | The R3 tripwire. On the cc leg the bag is structurally absent (E4), so today's green runs never hit it — the row is the declaration of the contract the proposed device leg (R4) must honor |
| F5 | Variance mint succeeds but its token cannot be revoked: revocation store failure, or the sweep dies between mint and revoke (SIGKILL/OOM/CI-kill/panic) | Revoke failure: `revoke: …` rows folded into the variance diags; `mint: FAIL`. Crash: the token silently outlives the run until `exp` | Revoke failure is a real deployment defect and must not be silent. The crash window is a DOCUMENTED residual, deliberately: the token exists only in the sweep process memory, is TTL-bounded (`defaultTokenTTL` = 1h, per-client override via `access_token_ttl` — `effectiveAccessTTL`; `Validate` rejects after `exp`), carries only the sweep client's scopes, and the design already minimizes the window by placing no I/O between mint and revoke (rows 2-4 compare decoded claims only — implement the revoke immediately after the mint response). A `defer revokeToken` was considered and rejected: the explicit revoke already covers every normal return (defers would add only panic-unwinding coverage — never SIGKILL/OOM/CI-kill) at the cost of a double-revoke dance. Runbook: set a short `access_token_ttl` on the dedicated sweep client (§5 step 4). The identical window exists TODAY for mint-1's token — R2 adds a second instance of a pre-existing, bounded residual; on a Host-derived deployment the phantom-iss token is strictly less useful downstream (B4-1-configured validators reject it) |
| F6 | The first mint's `iss` is absent/malformed while `--expect-issuer` is set | `firstISS` is `""`; the variance row fires alongside the absent-iss rows | Noise, not a wrong green — the sweep never short-circuits; the run already failed on the first mint's rows |
| F7 | `--expect-issuer` declared on a run whose `token_endpoint` is absent | T-8a group is skipped (`check INCOMPLETE`, exit 1) exactly as today; the flag never changes skip semantics | Unchanged contract; documented so operators do not mistake the skip for a variance failure |
| F8 | `--expect-issuer` declared: the variance leg consumes server-side accounting (audit, metering, signing usage, rate limits) as a REAL issuance, not a probe artifact | Bounded, deterministic deltas per run — accounting table in §4.1 | Not a failure mode; capacity-planning and audit-triage documentation |

## 4.1 Operational footprint of the variance leg

Per run with `--expect-issuer` declared (all deltas relative to today's run):

| Surface | Today's run | Variance leg delta | Interaction notes |
|---|---|---|---|
| Audit — `token_issued` / `token_revoked` | 1 + 1 | +1 + 1 (mint-2 is a real grant; its revoke is a real revocation) | The audit Event carries NO Host/issuer field, so the phantom base URL never lands in audit records. On tenant-wired deployments the tenant middleware no-ops on `sweep-host-variance.invalid` (ErrDomainNotFound is non-fatal; `tenant.ClientOK` passes with no tenant context), so mint-2's record has EMPTY `TenantID` while mint-1's carries the client's tenant — the token's own `tenant_id` claim (client-bound) and the audit record's tenant attribution disagree for exactly this one record. On non-tenant deployments the two records are indistinguishable except by timestamp. |
| Metering / audit report | counted | +1 `token_issued` | `domains/metering` counts per tenant: the client's tenant view undercounts by 1 per run and the empty-tenant bucket gains 1. SOC2 report cardinality is unaffected — its buckets are fixed enums (outcome/event-type/actor; actors unchanged). |
| Anomaly detection | — | +1 issuance for the sweep client | `domains/tokenanomaly` keys per token thumbprint (SHA-256 of jti): the variance token has a fresh jti, so multi_geo/velocity never fire; rate_spike is per-client with a 20/min absolute floor — a constant +1 is never a spike. The preflight's 401 `invalid_client` emits NO audit record (token client-auth failures are unrecorded by design) and matches the sweep's existing 401/400 probe pattern from T-8d/T-9. Anomaly detection is advisory and asynchronous (AGENTS.md). |
| Signing usage | 1 | +1 | `sso_signing_key_usage_total{alg="EdDSA",kid}` +1 per run (same kid as mint-1); a KMS-backed signer pays one real `Sign` op per mint. |
| Token-endpoint RPS / rate limits | 5 POSTs (mint, revoke, introspect, T-8d, T-9) | +3 (preflight, variance mint, variance revoke) | The "probes outside rate limiting" carve-out covers ONLY /metrics /livez /readyz; the sweep's requests are ordinary client traffic. Global (IP-keyed) bucket: +2 — the preflight's 401 still consumes it (the middleware runs pre-auth). Per-grant-type `client_credentials` bucket: +1 — only the credentialed mint reaches `checkGrantRateLimit` (post-auth); the preflight never does. A 429 on the preflight → preflight abort; a 429 on the mint → row-1 non-2xx `host-variance mint: status 429` — both red, both covered by the F3 rejection shapes; operators on tight /token limits should budget the +3. |

## 5. Migration steps

Ordered; each step leaves the tree buildable and the apiclient tests in a
strictly better state.

1. **R5 harness fix** (check_test.go only): `WithEd25519Issuer(addr)` on the
   `newLiveServer` token issuer. Flips the six iss-misalignment rows green
   (E11; `TestSweep_TokenEndpointSuffix`'s stale `/oauth2/token` expectation
   is fixed separately — see E11 — it is not an iss row). Out-of-scope rows
   remain red and tracked (§7 of the requirements
   spec). Gate: `go test ./cmd/sso-ctl/apiclient/ -run 'TestSweep_GreenPath|TestStdoutDeterministic|TestMint_ClaimsMatrix|TestMint_ScopeContainsRequested|TestMint_AudContainsResource|TestRevoke_RoundTrip'` — all six iss rows.
2. **Refactor + R1 + R3** (check.go, token.go, sweep.go): `parseCheckFlags`
   extraction, `verifyClaims` split, `--expect-issuer` flag, the R1 row, the
   R3 dedup row, `mintBody`/`mintWithHost`/`mintPost` (variance leg not yet
   wired). Gate: `TestMaintainability_` function-length and cyclo rows go
   green (C1), `go build ./... && go vet ./...`, existing apiclient rows
   unchanged.
3. **R2 probe** (sweep.go + token.go + check_test.go): `hostVarianceHost`,
   `variancePreflight`, `hostVarianceProbe`, `revokeToken` split, `runT8a`
   wiring, the `hostDerivedIssuer` fixture, and the new test rows (§6).
   Gate: full apiclient suite green except the tracked out-of-scope rows;
   `make ci`.
4. **Contract update in the same change**: `usage()` banner line, the T-8a
   group description in check.go's header comment, and this design doc.
   `docs/config-reference.md` / `docs/openapi.yaml` / `docs/error-codes.md`
   are not applicable (CLI flag, no endpoint, no `Err*`). **Deploy-tree
   runbook (F3a/F3b/F3c/§3 preconditions)**: the edge between the sweep and the
   server must pass Host through unchanged — no unknown-Host default
   routing to a different upstream (F3a) and no Host or X-Forwarded-Host
   rewriting/forcing (F3b, §3); the sweep client must be dedicated,
   low-scope, and revocable (credential scoping), with a short
   `access_token_ttl` so the F5 crash residual stays small; and
   `--expect-issuer` must carry the EXTERNAL canonical issuer, never the
   upstream/internal host.

   **Verify the edge's unknown-Host default route BEFORE enabling
   `--expect-issuer`** — from the same network vantage as the sweep, never
   with the live secret (the dummy secret is a fixed non-secret constant).
   TLS is unaffected by the override (SNI stays the canonical host; only the
   Host header / `:authority` changes):

   1. *Identity check, credential-free*: `curl -sS -H 'Host:
      sweep-host-variance.invalid'
      https://<external-canonical>/.well-known/openid-configuration`. A 200
      discovery document proves an OIDC-shaped server answered the unknown
      Host; 404/421/502/HTML/redirect proves the edge rejects or
      default-routes it elsewhere — do NOT enable. On a server WITHOUT a
      configured issuer, the doc's `issuer` field is the pass-through
      oracle: it carries `sweep-host-variance.invalid` (Host passes through
      — the probe will work) or the upstream/canonical host (Host is
      rewritten — F3b; fix the rewrite, or accept that only the R1 pin
      guards). On a configured-issuer server the doc cannot reveal
      rewriting — confirm the edge config instead: no `proxy_set_header
      Host` / `host_rewrite` / `auto_host_rewrite` on the sweep path, and
      know the default vhost's (`listen … default_server` / catch-all)
      target.
   2. *Preflight rehearsal, dummy secret only*: `curl -sS -H 'Host:
      sweep-host-variance.invalid' --data
      'grant_type=client_credentials&client_id=<sweep-client-id>&client_secret=sweep-invalid-secret'
      https://<external-canonical>/oauth2/token`. A `401` with the
      `{"error":"invalid_client"}` envelope proves the variance Host
      reaches the real token endpoint with the probe's exact wire shape;
      anything else → step 1's conclusion. The in-band preflight (row 0)
      re-verifies this on every run — the manual step is the enablement
      gate, the preflight is the ongoing guard.

   **Trust-zone alternative (coherent with the preflight)**: running the
   sweep direct to the server (inside the trust zone, no edge) makes the
   F3a/F3b/F3c surfaces moot — the preflight still runs and passes (the real
   server answers the dummy secret with 401; there is no middlebox to abort
   on), and the credentialed mint cannot be misrouted. Preconditions:
   server-side issuer configuration (`WithIssuer`) so the minted `iss`
   equals the external canonical `--expect-issuer` regardless of the dialed
   endpoint, and the understanding that the trust zone validates the SERVER
   only — B4-1 guards the production edge path, so the edge must still be
   fixed (or verified per steps 1-2) before the gate's result is meaningful
   for production traffic.
5. **Deploy-tree rollout**: add `--expect-issuer <canonical issuer>` to the
   B4-1 gate invocation (the `docs/campaigns/implementation-gate.md` row-1
   T-8(a) acceptance now has a sweep-side oracle: run the updated binary with
   the declared pin, after the step-4 edge preconditions are verified). Rollback: drop the flag — the previous binary's
   behavior is byte-identical to the new binary without it, so a staged
   rollout is a pure flag flip with no compatibility window.
6. **B4-4 coordination**: whichever campaign lands second flips the single
   transport point in `mintPost` (§3) — the two mint legs and the variance
   preflight. The T-8d invalid-scope, revoke, and post-revoke introspection
   POSTs are separate `probeClient.Post` call sites and need their own
   flips under strict enforcement (§3). No rework of the variance leg.

## 6. Testable acceptance mapping

| Req | Acceptance row | Named test | Assertion |
|---|---|---|---|
| R1 | Live green: aligned issuer + `--expect-issuer <addr>` → exit 0, `mint: OK`, golden stdout unchanged | `TestMint_ClaimsMatrix` (updated: add `--expect-issuer srv.URL` to `checkArgs`) | exit 0; stdout == `goldenGreenStdout`; no stderr |
| R1 | Live + `--expect-issuer https://u:p@other.example` → exit 1, `claims: iss … != declared issuer …`, `mint: FAIL`; URL-shaped values redacted (userinfo stripped, C2) | `TestExpectIssuer_Mismatch` (new) | exit 1; stderr contains exactly TWO `!= declared issuer` rows (one per mint: the mint-1 R1 pin plus the variance leg's row 4 — a partial implementation that keeps only one of them cannot satisfy the row) with the userinfo stripped (`!= declared issuer "https://other.example"`) and never `u:p`; stdout contains `mint: FAIL` |
| R1 | Stub minted `iss` ≠ declared value → same failure shape | `TestExpectIssuer_StubMismatch` (new; stub `mintToken` carries a different iss, run with `--expect-issuer`) | exit 1; declared-iss row on stderr |
| R2 | Live green: `--expect-issuer <addr>` → both mints carry `<addr>` → exit 0 (variance leg rides `TestMint_ClaimsMatrix`) | same as R1 green | exit 0, no variance diagnostic |
| R2 | Regression fixture (Host-derived mint): first mint `iss` = real host, second = altered host → exit 1 with the variance diagnostic | `TestExpectIssuer_HostVarianceFails` (new; `hostDerivedIssuer` server, run with `--expect-issuer srv.URL`) | exit 1; stderr contains exactly one `!= discovery issuer` row and it carries the variance host (`claims: iss "http://sweep-host-variance.invalid" != discovery issuer` — mint 2's row; a plain NotContains is wrong: the variance leg's own row 3 re-emits the standard discovery diagnostic for mint 2); no `claims: iss "<srv.URL>" != discovery issuer` row (mint-1's form — the lockstep blind spot is reproduced); stderr == the pinned 3-row signature in §2.6 (differs → discovery → declared) |
| R2 | Posture: variance requests carry no Authorization header, Host == `sweep-host-variance.invalid`, target the advertised endpoint, redirects never followed, preflight precedes the credentialed mint | `TestHostVariance_Posture` (new; stub records requests; run with `--expect-issuer` matching the stub minted iss; the stub answers the dummy-secret preflight with 401 invalid_client — the existing handleToken would mint it, so the preflight branch must be stubbed explicitly) | recorded order: preflight (dummy secret) THEN credentialed mint (real secret); both `Authorization`-empty, `Host` == `sweep-host-variance.invalid`, URL == advertised token_endpoint; no redirect followed; both mint responses report the same `ProtoMajor` as the first mint's (the transport must be the real probeClient shape — a zero-value `&http.Transport{}` would silently downgrade to h1) |
| R2 | Preflight abort: the variance Host yields anything other than 401 invalid_client → the credentialed mint never runs | `TestHostVariance_PreflightAborts` (new; stub answers the variance Host with 502) | exit 1; stderr contains `host-variance preflight` and `no credentials sent`; stub records NO credentialed variance mint (the real secret never leaves the probe) |
| R3 | Live, tenant-bound client, `--expect-tenant-id t1` → exit 0 | `TestMint_TenantIDLive` (new; live server seeded with a `TenantID: "t1"` client) | exit 0 (top-level `tenant_id` stamped, bag absent → dedup row silent) |
| R3 | Stub payload with `ext: {"tenant_id":"t1"}` AND top-level `tenant_id: "t1"` → exit 1, dedup diagnostic | `TestMint_TenantIDExpectation/dup-in-ext` (new row) | exit 1; stderr contains `claimsWithoutEmittedKeys strip missing`; no values echoed |
| R3 | Stub payload with only `ext.tenant_id` (no top-level) → exit 1, `tenant_id absent` (unchanged semantics: the declared claim is a top-level claim) | `TestMint_TenantIDExpectation/ext-only` (new row) | exit 1; `claims: tenant_id absent`; no dedup row (premise false) |
| R5 | Green-path rows pass after the harness alignment, with `--expect-issuer <addr>` added to the green-path arguments | `TestSweep_GreenPath`, `TestStdoutDeterministic` (updated) | exit 0; stdout deterministic and equal to `goldenGreenStdout` |
| R5 | Out-of-scope pre-existing failures remain red and are tracked, neither fixed nor masked | `TestIntrospect_Non401Fails/wrong-bytes`, `TestCheck_AddrValidation`, `TestSweep_AdvertisedURLRejection/*`, `TestMint_ResponseFail/status-400` | unchanged red state; reported separately per AGENTS.md §2.7 |

Exit-code contract: all new rows route through the existing plumbing — any
`claims:`-prefixed failure forces `mint: FAIL` and exit 1; CLI misuse stays
exit 2; help stays exit 0.

## 7. Files

### Create

```text
docs/architect-analysis/cmd-sso-ctl-b4-1-claims-gate-design.md  (this document)
```

### Modify

```text
cmd/sso-ctl/apiclient/check.go     — R1 flag + usage line; parseCheckFlags extraction
cmd/sso-ctl/apiclient/sweep.go     — checker.expectIssuer field
cmd/sso-ctl/apiclient/token.go     — verifyClaims split (R1/R3 rows); mintBody/mintWithHost/
                                     mintPost; hostVarianceProbe; revokeToken split
cmd/sso-ctl/apiclient/check_test.go — R5 newLiveServer alignment; hostDerivedIssuer fixture;
                                     new/updated rows per §6
```

### Do not modify

```text
cmd/sso-ctl/apiclient/apiclient.go — shared client transport; the Host override rides
                                     mintPost, never Client.Do (E12)
interfaces/sso/server_discovery.go — resolveIssuer fallback is deliberate SDK behavior;
                                     the sweep-side pin makes it observable
infrastructure/defaultimpl/issue_payload.go — buildAccessPayload/claimsWithoutEmittedKeys
                                     are the contract under test, not the fix surface
internal/handler/tokengrant/token_client_credentials.go — cc Subject shape (no Roles/Claims)
                                     is the verified fact behind the existing diagnostic
internal/handler/tokengrant/token_device.go — the bag-carrying premise for R4; unchanged
```

## 8. Scope guard

Unchanged from requirements §3, plus the decisions recorded above: no
server-side issuer allowlist, no `--expect-roles` semantic change on the cc
path, no device-flow leg (R4 stays proposed; this design pins the claim-shape
contract the leg must satisfy), no changes to T-8d/T-9, the mint body shape,
the discovery sweep, the revoke/introspect legs, or exit-code semantics.
Additionally: no `SSO_EXPECT_ISSUER` env parity (D5), variance probe strictly
opt-in (D4), and no repair of the pre-existing failures not rooted in the
issuer misalignment (reported, tracked, not fixed).

## 9. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/apiclient/ -run 'TestSweep_|TestMint_|TestRevoke_|TestStdoutDeterministic|TestExpectIssuer_|TestHostVariance_' -v
make ci
```

Handoff gate: `make ci` green; all apiclient tests green except the tracked
out-of-scope rows above (and the `TestSweep_TokenEndpointSuffix` fixture fix
applied per E11 — its stale `/oauth2/token` expectation makes it impossible
under any correct implementation); `TestMaintainability_` green for the
apiclient files
(pre-existing `TestMaintainability_FileSizeBudget` failure on
`infrastructure/defaultimpl/ed25519_jwt_issuer.go` reported separately);
each §6 acceptance row maps to a named test.
