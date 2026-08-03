All claims below are source-verified; current-behavior tests were executed (`go test ./interfaces/ssoclient/...` green; targeted no-op/logout tests PASS). No code was modified — advisory review only.

---

# Security Review: `interfaces/ssoclient` Direction 2 design

**Reviewed revision:** `docs/auto/interfaces-ssoclient-direction2-design.md` against current source. **Method:** source tracing of every load-bearing claim; executed `go test ./interfaces/ssoclient/...` (all pass) and `-count=1 -run` of the four behavior-pinning tests (`TestRemoteAuth_LogoutWithoutURLIsNoop`, `TestRemoteAuth_LogoutCallsConfiguredURL`, `TestRemoteAuth_RejectsExpired`, `TestLocalAuth_Logout_SessionIDWithoutManagerIsNoop` — all PASS, confirming current behavior).

**Verdict up front:** the design correctly fixes the real High-severity class (missing iss/aud enforcement + silent logout). No Critical/High findings in the design. I found one factual error that would ship wrong operator guidance, one parity hole the design's own contract principle demands closing, one unfinished "unify", and two test/ordering gaps.

## 1. Assets, trust boundaries, attacker capabilities, entry points

**Assets**
- `AuthClient.ValidateToken` output (`ssoclient.Subject`) — feeds authorization: `docs/examples/appcore/handler.go:52-57` resolves `clientID := firstAudience(subj)` and calls `Authz.Check` with it (**Verified**). A wrong or absent `aud`/`iss` pin directly steers privilege lookups.
- JWKS cache key material — the local-verification trust anchor (`remote/jwks.go`).
- Client credentials for the new `WithRevokeURL` (new secret class in the facade).
- Revocation capability: server-side sessions, refresh tokens, per-issuer revocation chains behind `POST /logout` and `POST /token/revoke`.
- New design state: four in-memory option fields — no storage, no config schema (**Verified** in Decision 5).

**Trust boundaries**
- Untrusted: token bytes arriving from the network; attacker-chosen claims inside signed payloads.
- Trusted-by-config: JWKS URL, logout/revoke URLs, client credentials, issuer pin value. No untrusted input ever selects a URL or a key — the facade has no SSRF surface (outbound only, operator-configured endpoints).
- Cryptographic boundary: `security.VerifyCompactJWS` (`shared/security/securityverify/jwks_verify.go`) — the seam between untrusted bytes and claims.

**Attacker capabilities**
- Network attacker: presents arbitrary JWT bytes (forged, replayed, or legitimately minted for another client/tenant/issuer) to any App's validation path.
- Rogue user of a shared central SSO: holds a valid token for issuer B / client B and presents it to App A. This is the attack the design's issuer+aud pins close.
- Attacker does NOT control: signing keys, JWKS URL, endpoint URLs, client secrets (trusted-by-config).

**Entry points (this direction's surface)**
- `remote.ValidateToken` — per-request, network-facing in Apps (iss/aud gaps live here).
- `local.ValidateToken` — in-process (aud gap only).
- `remote.Logout` / `local.Logout` — credential lifecycle (silent-nil gap lives in remote; a second silent-drop lives in local, see F3).
- Out of scope but inventoried: `remote.AuthzClient`/`AuditClient` (gRPC, unauthenticated by documented design — no change proposed), `dev.AuthClient` stub (documented no-op, risk #9 acknowledged).

## 2. Findings

### F1 — Medium — Design fact error: login-path `aud` is NOT client ID for access tokens

**Evidence (Verified):** The design states twice that login-path tokens carry `aud = client.ID` (Decision 2 consequences; Decision 7.2 remote-app rationale, citing `server_finish_login.go:298`). Line 298 is the **ID-token** issuance (`IssueIDToken{... Audience: client.ID ...}`). The facade never validates ID tokens — `parseAccessTokenKID` enforces the `at+jwt` typ gate, and `defaultimpl` access-token mints stamp `aud` **only** from `Subject.Resources`, and only when non-empty (`infrastructure/defaultimpl/issue_payload.go` `applyOptionalClaims`: `if len(subject.Resources) > 0 { payload.Aud = audClaim(...) }`; login path passes `Resources: append([]string(nil), req.Resource...)` at `server_login.go:117`; token path flows RFC 8707 resources through the grants). So a login-path **access** token carries `aud` = requested resource indicators or **no `aud` at all** — never `client.ID`. `ClientID` is a separate claim.

**Exploit preconditions/steps:** none required — this is a doc-driven availability trap. An operator following the design pins `WithExpectedAud(clientID)` for login-path tokens → every token lacks `aud=clientID` → 100% `ErrAudienceMismatch` (fail-closed denial of the app's own users). The design's own risk #2 covers the token path but states the login path incorrectly, so the mitigation text compounds the error.

**Impact:** availability (false denial); enshrines a wrong fact in the remote-app example comment that future operators copy. No bypass (fail-closed), which is why this is Medium, not High.

**Remediation:** correct both statements: *login-path access tokens carry `aud` = RFC 8707 resource indicators, or no `aud`; `aud = client.ID` applies only to ID tokens, which the facade rejects by typ gate.* Rewrite Decision 7.2's rationale accordingly (the conclusion — leave `WithExpectedAud` unwired in remote-app — stays correct).

**Regression test:** mint via `defaultimpl` a token with `Resources: []string{"urn:app"}`, pin that value → validates; pin `clientID` → `ErrAudienceMismatch`; token with no `aud` + any pin → `ErrAudienceMismatch` (documents the fail-closed no-aud cell).

### F2 — Medium — Missing-`exp` gate divergence; the design's "identical cross-layer error classes" claim is false in one cell

**Evidence (Verified):** `remote.validateTokenTime` (`remote/auth.go`): `if p.Exp != 0 && now >= p.Exp` — a token **without** `exp` passes. `rs.validateClaims` (`rs/claims.go`): `if c.ExpiresAt == 0 { return ErrTokenMalformed: missing exp }` — exp is REQUIRED per RFC 9068 §2.2. The design's error-priority table ("config → … → iss → time → aud … keeps cross-layer error classes identical for the same token") is false for the no-exp cell: no-exp + wrong-aud → remote accepts (or `ErrAudienceMismatch` if pinned) while rs says `ErrTokenMalformed`; no-exp + correct iss/aud → remote **validates**, rs rejects. This also violates the design's own contract principle ("facade must never be weaker than the layer it wraps"), and a no-exp token has no TTL bound, which interacts with the rotation rule "old key verify-only through token TTL" (AGENTS.md §3) — the key-retirement window is unbounded for such a token (**Partial**: practical window is bounded by server key-retention scheduling; the TTL assumption is what breaks).

**Exploit preconditions:** requires the issuer signing key or a compromised/misconfigured key-holder — no standalone network path. This is a defense-in-depth/parity gap, but it lives in the exact function the design is already editing.

**Remediation:** in the same edit, reject `Exp == 0` with a facade-level malformed-class sentinel (rs semantics), and optionally check `iat` when present (rs does). This is a one-line gate that makes the parity matrix fully true.

**Regression test:** sign a payload with the fixture key omitting `exp` → assert rejection; assert the error class equals rs's class for the same token (iss-ok, no-exp, wrong-aud → malformed, not audience).

### F3 — Medium — "Unify" is incomplete: `local.Logout` keeps its own silent-nil

**Evidence (Verified + executed):** `local/auth.go:68`: `if req.SessionID != "" && c.sessionMgr != nil` — `SessionID` set without `WithSessionManager` is silently dropped, returning nil; `TestLocalAuth_Logout_SessionIDWithoutManagerIsNoop` (**PASS**, executed) pins this as intended behavior. The design's Decision 3 changes only `remote`; the same input (`Logout{SessionID:"x"}`) returns `ErrLogoutNotConfigured` from remote and `nil` from local — the two implementations still disagree, and the local side still "claims success when nothing was revoked", which the spec calls "the worst kind of best-effort".

**Remediation:** pick one: (a) extend `ErrLogoutNotConfigured` to local (rewrite the no-op test), or (b) explicitly document the local asymmetry in the facade contract. The design must not claim unification without one of these; option (a) is the honest completion.

**Regression test:** `local.Logout({SessionID:"x"})` without manager returns non-nil (if (a)).

### F4 — Medium — New revoke wire path is validated only by mocks; one missing header would guarantee 400

**Evidence (Verified):** `protocols/oauth/oauthwire/bind.go:26-45` — `BindParams` parses form **only** when `Content-Type: application/x-www-form-urlencoded` is set; any other/missing CT defaults to JSON decode. The design's `WithRevokeURL` spec says "form-encoded `token` + `token_type_hint`" but never pins the Content-Type header — omit it and every revoke gets `400 invalid_request`. Also, the design's claim that `TestRemoteAuth_LogoutCallsConfiguredURL` "stays valid" is wrong as written: it sends **both** fields with only `WithLogoutURL` configured and asserts nil + 1 call; under the new contract the token leg yields `ErrLogoutNotConfigured` (**Verified reasoning**: the design's own failure-mode #7). It must be rewritten (session-only request, or both URLs configured). Acceptance tests are httptest-only; the entire value of this path is byte-exactness against the real handler (form CT, Basic-wins precedence, always-200), which only a real-server E2E proves.

**Remediation:** pin the Content-Type header in the implementation notes; rewrite the test explicitly; add one `test/` E2E case driving `remote.Logout` with an `AccessToken` against the real `/token/revoke` and `SessionID` against `/logout`.

**Regression test:** httptest asserting CT header, form body, Basic auth, and 200→nil / 401→error; plus the E2E above.

### F5 — Low — Config-error partial logout ordering

**Evidence (Verified):** with both fields set, the design routes SessionID first and short-circuits on first failure (failure mode #10). If the token leg is merely misconfigured (no `WithRevokeURL`), the session is destroyed server-side **before** `ErrLogoutNotConfigured` is returned — a half-logout caused purely by config, reported only after the fact.

**Remediation:** mandate a pre-flight capability check (every set field's endpoint configured) **before** any HTTP call, so `ErrLogoutNotConfigured` is never returned after a performed leg. Transport-failure mid-way partiality is inherent and correctly handled by the loud contract.

### F6 — Low — Pre-existing remote error classes stay opaque

**Evidence (Verified):** remote's malformed/signature/expired failures are plain errors; rs has typed sentinels (`ErrTokenMalformed`, `ErrSignatureInvalid`, `ErrTokenExpired`). The new `errors.go` adds only the four new sentinels, so `errors.Is` parity across the facade remains partial. Decision 4 should state this explicitly (it currently implies a complete taxonomy). Also recommend (optional) a grep gate forbidding `ssoclient/dev` imports in non-dev code — the design names the stub's weakness (risk #9) but a wiring accident would silently install it.

### F7 — Info — Secret and endpoint hygiene for `WithRevokeURL`

In-memory plaintext `clientSecret` is unavoidable for an SDK. Requirements to pin in docs: HTTPS-only for both URLs (no scheme enforcement exists or is proposed); error wrapping must never include request headers (Go's `url.Error` does not — **Verified** behavior — but state it as a rule); the 2xx-trusts-server contract means a misconfigured (attacker-owned) revoke URL yields a false "revoked" — inherent to operator-config trust, worth one doc sentence. Single-issuer-per-client and no facade introspection mode remain documented residuals (risk #3; rs docs).

## 3. Abuse-case table

| Abuse case | Today (verified) | After design | Gate/regression |
|---|---|---|---|
| **Identity spoofing** — attacker presents a valid token minted by issuer B (central/multi-tenant SSO sharing a JWKS URL or gateway) at App A | **Accepted** — `iss` parsed and dropped (`remote/auth.go:74`, `subjectFromPayload`) | `ErrIssuerMismatch`, exact match, iss before time/aud | Two-issuer + two-JWKS fixture; missing-`iss` token → `ErrIssuerMismatch` (`"" != pin`) |
| **Cross-tenant access** — rogue tenant-B user at tenant-A app, same key material | **Accepted** (same path as above) | Same fix | Same fixture |
| **Cross-client privilege** — token minted for client B presented at App A; `appcore` resolves `firstAudience` → B's roles via `Authz.Check` | **Accepted** — aud passed through unchecked | `ErrAudienceMismatch` when pinned (opt-in; empty expectation unchanged) | String/array-`aud` containment tests; missing-`aud` fails closed |
| **Replay — revocation blindness** — `Logout` returns nil, nothing was sent; revoked token keeps validating until exp | **Confirmed** (`remote/auth.go:106-107`; test executed) | Loud contract; routing to `/logout` (session) and `/token/revoke` (token) | `ErrLogoutNotConfigured` assertions; E2E against real endpoints |
| **Replay — JWT within TTL** — stateless local validation cannot see revocation | Inherent, documented in rs; facade unchanged | Unchanged (no introspection mode — out of scope) | Residual risk; document only |
| **Proxy/header forgery** | **No surface** — facade makes no inbound decisions, no XFF handling; server trusted-proxy gates untouched by this direction | Unchanged | Verified no code path; no regression needed |
| **Resource exhaustion** — JWKS miss amplification | Mitigated: 10s forced-fetch debounce + singleflight (`remote/jwks.go`, **Verified**) | Unchanged; new revoke path is outbound-only, idempotent server-side | No new server surface |
| **Sensitive-data leakage** — access token placement | Today: token in `Authorization: Bearer` of the `/logout` request | Fix: token as form field of `/token/revoke` with Basic client creds; error text carries status only, no secret/claim echo beyond rs's `iss %q` | Wire tests assert body/header shapes |
| **Oracle probing** — multi-defect token | Gate order differs from rs (no iss gate) | iss→time→aud mirrors rs; same token reports the same class at both layers; SDK sentinels never reach a wire (AGENTS.md §5.6) | Parity matrix test (incl. F2's no-exp cell) |

## 4. Positive controls verified, residual risks, prioritized validation plan

**Positive controls (Verified):**
- Signature path: `VerifyCompactJWS` — alg allowlist checked **before** parsing (`none`/HS* impossible), kid binding, key/alg-type consistency, EC on-curve, empty-signature rejection (`securityverify/jwks_verify.go`).
- rs reference gates: iss exact-match first, exp required, time with skew, aud containment, region gate fail-closed last; unknown-kid collapses into the signature-error class (no key oracle).
- Server contracts the facade will call: `/token/revoke` — always-200 on valid creds, Basic-wins-over-body, no-store headers, 401 `invalid_client` collapse (`protocols/oauth/handle_revoke.go`); `/logout` — JSON `session_id` + optional bearer, 400 on both-empty (`server_logout.go`). The design's routing split is the **correct** reading of both handlers (**Verified**).
- Design choices consistent with AGENTS.md: fail-closed gates, opt-in aud (no regression), loud logout, rs-ordered error priorities, zero new storage/config/server surface, budgets respected (remote/auth.go 217 lines today; ~290 projected < 500), no `interfaces/sso` files, no upward imports.
- Migration claims verified: bare `remote.NewAuthClient(jwks)` in `cmd/sso-mcp/snaplink.go:33` and `docs/examples/remote-app/main.go:39`; `Config.Issuer`/`ResourceURI` exist (`cmd/sso-mcp/config.go:26-27`); zero non-test `Logout` consumers; `local` already loud on empty requests.

**Residual risks:**
1. F2's missing-`exp`/`iat` asymmetry if not fixed in the same change (parity matrix has a false cell).
2. F3's local `SessionID` silent-drop if not unified.
3. `dev` stub weaker than contract (documented; recommend import-gate).
4. aud-pin false denial on miswiring — fail-closed by design, but F1's wrong login-path fact actively invites it until corrected.
5. Time-skew asymmetry (design risk #8, accepted).
6. Out-of-repo consumers of the silent-nil Logout (intended price, documented).
7. URL scheme enforcement is operator responsibility (no HTTPS check proposed or existing).
8. Revocation invisible to facade-local validation until exp (pre-existing, rs-documented).

**Prioritized validation plan:**
1. **Before implementation:** correct F1 facts in the doc; decide F2 (add exp-required) and F3 (unify local) — all same-change decisions; pin the form Content-Type header in Decision 3.
2. **Per-edit:** `go build ./... && go vet ./...` + `go test -run 'TestMaintainability_|TestArchitecture_' .`; then `go test ./interfaces/ssoclient/... -race`.
3. **New tests:** cross-issuer, cross-client, missing-`iss`, no-`aud`, string/array-`aud` (incl. non-string element with expectation set → fail-closed), parity-matrix test comparing facade vs rs error classes per defect cell, revoke wire-shape tests (CT, form, Basic, 200/401/5xx), rewritten logout tests per F4/F5.
4. **Real-server:** one `test/` E2E driving both `Logout` legs against the actual routes; `go test ./test/ -run TestE2E -v`.
5. **Handoff:** `make ci` (covers nested `cmd/sso-mcp`), grep gates (no bare `remote.NewAuthClient(` outside tests, no `clientID=""`, no "silently skips").

**Evidence gaps (not blockers):** I did not execute the design's proposed tests (none exist yet); no runtime verification of `WithRevokeURL` wire behavior is possible until implemented; F2's key-retirement interaction is partially inferred from AGENTS.md prose.
