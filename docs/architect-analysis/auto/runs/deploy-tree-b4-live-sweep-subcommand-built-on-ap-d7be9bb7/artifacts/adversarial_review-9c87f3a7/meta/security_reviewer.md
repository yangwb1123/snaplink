All verification complete. Here is the adversarial review.

---

# Adversarial review — sweep credential hygiene (`cmd-sso-ctl-apiclient-design.md`)

Reviewed against the working tree (apiclient.go, main.go, auditverify, scope.go, handle_introspect.go, router.go, configcmd, requirements doc) plus empirical Go 1.26.5 behavior tests (URL parsing, userinfo Basic-auth, redirect semantics).

## 1. T-9 bearer-less — CONFIRMED, conditional on three pins

**Structural verification.** `apiclient.New` (apiclient.go:47-62) applies opts, then unconditionally falls back to `SSO_ADMIN_TOKEN` — `WithToken("")` cannot opt out; there is genuinely no tokenless apiclient construction. The design's bare-client pin (§2.3, row 23) is therefore load-bearing, and `TestIntrospect_NoAuthHeaderLeak` (env set → recorded request has no `Authorization`) is the correct enforcement. The bare `&http.Client{Timeout: 30s}` + `http.NewRequest` with a fixed-literal body `{"token":"sweep-probe-dummy"}` has no env-credential path: default transport adds auth from no source other than the request URL itself (see below) or explicit headers.

**Three residual paths to close in `check.go`:**

1. **URL userinfo → auto Basic auth (empirically verified).** If the T-9 target (the advertised `introspection_endpoint`) carries `userinfo`, Go's transport attaches `Authorization: Basic base64(user:pass)` automatically — attacker-chosen creds, not env creds, but the probe is then not credential-less in the byte sense the row asserts. Fix: userinfo on any advertised endpoint = row failure (extends row 2).
2. **T-9 target pin.** The probe must target the *advertised* `introspection_endpoint` (it doubles as the T-2 row); when absent, skip with a stderr notice — never fall back to probing the unadvertised canonical path (`PathIntrospect`), which would break the advertised-only invariant. (REQ-5's literal `<base>/token/introspect` is shorthand; pin the advertised-URL semantics in `check.go`.)
3. **Dummy token pin.** The dummy is a fixed literal, never the minted T-8a access token (order-independent; also guarantees a 200 "enforcement absent" response from T-8d can never be mistaken for a T-9 credential).

## 2. Row-by-row stderr scan of the 25-row table

22 of 25 rows are clean — no row echoes `--client-secret`, the admin token, or the minted access token. Three gaps and two hardening pins:

| Row | Verdict |
|---|---|
| R1, R4 | **GAP.** `discovery: GET <base>...` and `endpoint ... <url>: <error>` echo operator/attacker-supplied URLs; `url.Error` embeds the full request URL including userinfo. If `--addr` or an advertised URL carries `user:pass@`, the secret lands on stderr (and CI logs). Fix: userinfo rejection at validation (item 3) + a `redactURL` helper applied in every diagnostic (belt-and-braces). |
| R7 | **GAP.** `mint: status <n> body <truncated>` is the one row that can echo a *real* access token: on the 200-with-missing-`access_token` or malformed-JWT branches the body *contains* the token. Pin: body echo only for non-2xx responses; decode failures print only the decode error (never the token string, never the body); truncate ~200 bytes. |
| R19, R22 | **HARDEN.** Body echoes are error/introspection bodies (safe by nature), but pin truncation + a shared `sanitizeBody` that redacts `access_token`/`refresh_token`/`id_token`/`client_secret` fields before printing. |
| R20 | ✅ Correctly body-less — a 200 there would carry a real token for the probe scope; the enforcement-absent diagnostic must stay that way. |
| R24 | **HARDEN.** Misuse diagnostics must never echo flag values (especially `--client-secret`). `flag.ContinueOnError`'s own errors don't echo string-flag values (only typed-flag values; all sweep flags are string/bool — safe). Note the `-h` divergence: with `ContinueOnError`, `-h` returns `flag.ErrHelp`; the design's A1 requires exit 0, while the configcmd precedent returns 2 — the design must deliberately map `ErrHelp` → 0. |
| R9–R16, R23, R25 | ✅ Clean — claim values (kid/iss/sub/client_id/scope/aud/tenant_id) are not secrets by nature; run URL-shaped values (iss, aud) through `redactURL` for uniformity. R23's "impossible by construction" holds given the item-1 pins. |

**Global pin:** one `redactURL`/`sanitizeBody` pair used by every stderr diagnostic; no diagnostic ever prints a raw flag value or a minted token.

## 3. `--addr` fail-fast validation — direction correct, four gaps

Verified empirically: `url.Parse("http://")` **succeeds** with an empty host (as does `http:///path`); `https://h:badport` errors (Go validates ports). The §2.1 scheme check alone is insufficient:

1. **Require non-empty `Host`** (else the sweep "fails" per-row with confusing transport errors — exactly the failure mode §2.1 exists to prevent).
2. **Reject `userinfo`.** Verified: Go sends `Authorization: Basic base64(user:pass)` from URL userinfo — embedded credentials go on the wire (even over plain http) *and* into R1/R4 diagnostics. This is the strongest single validation gap.
3. **Reject query/fragment.** `apiclient.Do` concatenates `baseURL + path` — a query-bearing base fetches `https://h/?x/.well-known/...`, a *different resource* than the intended well-known document (a fetch-beyond-intent vector).
4. **Validate the effective addr** (env `SSO_ADMIN_ADDR` wins over the flag — verified New() ordering) and **never echo the raw value in the rejection message**.

Exit-2 fail-fast timing, scheme whitelist, and the misuse-class placement are correct.

## 4. crypto/rand probe-scope pin — justified; add four pins

**Justification verified.** The bypass is real: scope.go:113-120 (`openid`/`device_sso` skip the allowlist — the design's "103-107" citation drifts, semantics identical). A fixed or guessable scope could be pre-registered or special-cased by a deployment; per-run unpredictability is the entire point. `math/rand` is wrong: the global is runtime-seeded (not cryptographically unpredictable), seedable, and the design must not leave the door open to a lazy `NewSource(fixedSeed)`. **No determinism hazard:** the value appears only in the mint request body, never on stdout — byte-determinism (REQ-1) preserved. Pins to add: (a) `crypto/rand.Read` failure → exit 1, *never* a math/rand fallback; (b) explicit 62-char alphanumeric charset (rejection sampling or base64url); (c) the scope must also never appear in *any* stderr diagnostic (R19/R20/R22 bodies are server content, not the scope — pin it anyway); (d) prefix already guarantees `≠ openid/device_sso`; 62¹² collision risk negligible.

## 5. Advertised-only coercion — GAP: redirects (the one live coercion vector)

**Empirically verified on the repo toolchain (go1.26.5):**

- Default `http.Client` follows up to 10 redirects; the design pins nothing.
- **307/308 preserve method AND body across hosts** — the mint POST body carrying `client_secret` (+ the T-8d probe scope) is forwarded verbatim to the redirect target (verified: `[307 target] method=POST body="{"client_secret":"TOPSECRET"}"`). This is a credential-exfiltration vector, not just a fetch-beyond.
- **Same-hostname redirects (any port) and subdomain redirects forward `Authorization`** (verified cross-port) — with `SSO_ADMIN_TOKEN` exported, an apiclient GET (discovery, jwks, endpoint rows) forwards the admin bearer to the redirect target.
- **A 302 on the discovery fetch makes the sweep fetch and parse an arbitrary URL as the discovery document** — the most direct "coerced into fetching beyond discovery metadata" path: the attacker doc then steers the sweep's subsequent probes (with credentials) anywhere.

**The fix conflicts with the requirements.** §3.3/REQ-6 say apiclient.go is untouched, but `apiclient.New`'s internal client has no `CheckRedirect` injection point — the sweep cannot pin redirects through apiclient without a change. **Required amendment:** one additive `WithNoRedirect()` option (or `CheckRedirect: http.ErrUseLastResponse` wired in New) — ~5 lines in apiclient.go + a contract test; existing subcommands' behavior untouched; §3.3's "untouched" claim narrows to `Do/Get/Post/ReadBody`. (Routing all probes through bare clients still leaves the A2-mandated apiclient discovery fetch exposed, so the apiclient change is unavoidable.)

**Row semantics under the pin:** truthiness rows treat 3xx as pass ("non-404" without following — preserves A3 and the login-page 302 case); content rows (discovery 200, jwks 200, mint 200, revoke 200, introspect 401, invalid_scope 400) fail on any 3xx. An operator behind an http→https redirector points `--addr` at the final origin.

**Other coercion vectors — status:** userinfo/empty-host/relative/non-http(s) URLs (reject, row 2 extension + item-3 rules) · decoy fields (design fetches only the 7 enumerated fields + `jwks_uri`; `issuer` is compared, never fetched — add a canary test asserting no request to a decoy `registration_endpoint`) · redirect-to-`file://` (refused by Go itself — "unsupported protocol scheme"). **Residual accepted disclosure to document:** credential-bearing probes inherently disclose the client secret to the *advertised* token/introspect endpoints — the same trust set the deployment operator already holds; the sweep must run against trusted deployments with scoped credentials. And §4.5's "`SSO_ADMIN_TOKEN` presence is harmless there" is **incorrect** as written for the GET rows plus redirects; with the no-redirect pin the residual is "bearer rides to advertised hosts" — add a stderr notice when `SSO_ADMIN_TOKEN` is exported, or route the T-2 GET rows through bare clients (which also makes the pinned "userinfo GET → 401 when mounted" row semantics env-independent).

## Summary

The design's hygiene posture is sound in intent — T-9 is structurally bearer-less, stdout is byte-deterministic, no row echoes the client secret or minted token — but four amendments are required before implementation: **(1)** the no-redirect pin (307/308 body exfiltration + same-hostname bearer forwarding + discovery-fetch coercion), which forces the one additive apiclient change; **(2)** `--addr`/advertised-URL validation rejecting userinfo, empty host, and query/fragment; **(3)** the R7 body-echo pin (non-2xx-only, never the token string) plus shared `redactURL`/`sanitizeBody` helpers; **(4)** the crypto/rand failure-handling and never-print pins (probe scope on stdout *or* stderr). Item 1 is the only one that changes a file the requirements marked "do not modify," and it is the one that makes "advertised-only cannot be coerced into fetching beyond discovery metadata" actually true on Go 1.26.

VERDICT: APPROVE WITH REQUIRED AMENDMENTS — T-9 bearer-less confirmed (pins 1-3 of §1), 22/25 failure-table rows clean with three diagnostic-echo gaps (§2 R1/R4/R7 + R24), `--addr` validation direction correct but incomplete (§3), crypto/rand pin justified with no determinism or leak hazard (§4), and the advertised-only sweep is coercible via default redirect-following until the CheckRedirect pin lands (§5) — the single blocking finding.
