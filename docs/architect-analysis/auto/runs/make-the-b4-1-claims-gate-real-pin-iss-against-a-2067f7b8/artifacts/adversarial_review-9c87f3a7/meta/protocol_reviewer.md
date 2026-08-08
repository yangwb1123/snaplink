All validation complete. Here is the adversarial wire-level review.

---

# Adversarial review: R2 Host-variance probe wire-level soundness

**Scope**: `docs/architect-analysis/cmd-sso-ctl-b4-1-claims-gate-design.md` §2.3/§2.5/§3/§4. Methods: stdlib source (go1.26.5) + empirical probe harness (h1 raw-wire capture, h2 TLS server with SNI recorder) + worktree reads of the mint path, the cc handler, the defaultimpl issuer, and `middleware.BaseURL`. No repo files modified.

## 1. Go `req.Host` override semantics — all design claims confirmed, with three sharpenings

**Empirical results** (harness in `/tmp/hostprobe`, Go 1.26.5; server cert valid only for `localhost`, so a leaked ServerName would have failed verification):

| Observation | Result |
|---|---|
| h1 wire (raw TCP capture) | `POST /token HTTP/1.1\r\nHost: sweep-host-variance.invalid\r\nUser-Agent: Go-http-client/1.1...` — verbatim override, origin-form target to the advertised host |
| Go h1 server accepts the mismatch | `r.Host="sweep-host-variance.invalid"`, `status=200` — no default 400 |
| probeClient-shaped client (nil Transport → `DefaultTransport` clone) | **negotiates `HTTP/2.0`** (ALPN) for all three mints |
| h2 `:authority` | server `r.Host` = override over HTTP/2.0; source: `httpcommon.EncodeHeaders` — `host := req.Host; if host == "" { host = req.URL.Host }`, sent as `:authority` |
| SNI | `ClientHello ServerName` = `localhost` (URL host) on **every** handshake, never the override; source: `addTLS(ctx, cm.tlsHost())`, `tlsHost()` = URL host |
| Connection targeting/reuse | `connectMethodKey{proxy, scheme, addr}` / `http2authorityAddr(req.URL.Scheme, req.URL.Host)` — keyed on URL host; empirically mint1 (no override) → mint2 (override) → mint3 (no override) all rode **one h2 connection** (3 TCP accepts for 4 requests), `:authority` switching per stream |
| zero-value `&http.Transport{}` | no h2 negotiated (all h1) — the control that proves the transport shape matters |

**Citation correction (minor)**: in RFC 9112, §7.2 is "Transfer Codings for Compression". The Host-must-match-authority rule is RFC 9112 §3.2 (origin-form/absolute-form; client MUST send Host identical to the target authority) plus the field definition in RFC 9110 §7.2 ("Host and :authority"). The probe does deliberately violate that client MUST. The server-side MUST-400 in RFC 9112 §3.2 covers only *lacking / more than one / invalid* Host — **not** mismatch — so a stock Go server accepting the request is RFC-compliant; a rejecting middlebox is enforcing a stricter (legitimate, per RFC 9110 §7.2's routing-poisoning warning) policy.

**h2 override trap (sharpening 1 — implementation guard)**: on the h2 path, `req.Header["Host"]` is silently dropped ("Host is :authority, already sent", `httpcommon.go:309`), while on h1 it would be written. If an implementer sets the override via `req.Header.Set("Host", ...)` instead of the `req.Host` **field**, the variance leg becomes a silent no-op on h2 — green when it should be red. The design correctly specifies the field; `TestHostVariance_Posture` (asserts server-observed `r.Host`) is the guard that would catch the mistake — it must stay.

**probeClient h2 (sharpening 2)**: `probeClient` (`check.go:262-271`) is `&http.Client{Timeout: 30s, CheckRedirect: ...}` with nil Transport → `DefaultTransport` (`ForceAttemptHTTP2: true`) → **h2 is already negotiated by the sweep's existing mints and T-8d today**; the variance leg introduces no new transport class, only the override. The override semantics are identical across h1/h2 (server-side `r.Host`), so h2 does **not** change override behavior server-side. What changes is the middlebox-behavior surface: on h2, a strict edge rejects a mismatched `:authority` with **421 Misdirected Request** (RFC 9113 §9.1.2) rather than 400 — a rejection flavor F3 does not name. Since both mint legs go through the same `mintPost`, both are consistently h1 or h2 — no leg asymmetry by construction.

**Transport-shape pin (sharpening 3)**: `mintPost` must literally reuse the probeClient shape (nil Transport → `DefaultTransport`). A fresh `&http.Transport{}` would silently disable h2 **and** drop `HTTP(S)_PROXY` env handling and pool reuse versus today's mint — a behavioral divergence, not just a protocol one. The design's "identical posture to probeClient" covers this only if implemented literally; the test rows should assert `resp.ProtoMajor` parity or at least ride the real `probeClient`.

## 2. Oracle efficacy — full middlebox enumeration (design documents only rejection)

The probe's oracle statement is: *"is the minted `iss` a function of the request Host?"* — and both code derivation and edge routing can make it one. Against a stock (fixed-issuer) server:

| # | Middlebox behavior | Probe outcome | Classification | Design coverage |
|---|---|---|---|---|
| M1 | Transparent (L4 LB, passthrough) | green on stock; red iff Host-derived mint | true negative / true positive (the intended oracle) | ✓ F2 |
| M2 | Reject on unknown/mismatched Host (Host-validating WAF/gateway; h1 400/421/502/conn-RST; h2 421) | **red** on stock | **false positive** — no mint happened; clause not violated. `.invalid` makes allowlist-based rejection *deterministic*, which raises the FP rate even as it guarantees no collision | partial — F3 documents the 4xx/5xx shape; 421 (h2) and connection-drop (transport error) variants missing; the RFC note that this is stricter-than-RFC policy is worth one line |
| M3 | Rewrite/normalize Host to upstream canonical (`proxy_set_header Host $proxy_host`, `auto_host_rewrite`, WAF sanitize, strip-and-synthesize) | **green always** | **silently green (false negative)** for the code-level oracle — but *benign today*: the edge normalizes production mints identically, so the B4-1 hazard cannot manifest through this edge; latent if edge config later passes Host through. Undetectable by any probe variant (R1's pin also matches) | **NOT documented — must be** |
| M4a | Route-by-Host → dead vhost / ingress 404 (e.g. k8s nginx-ingress, no catch-all) | **red** (status) | **false positive**, same class as M2; notably common in k8s deployments — the probe reds on a compliant deployment unless a default backend exists | NOT documented (F3's "reject" outcome subsumes the signal but not the trigger; deployment-relevant) |
| M4b | Route-by-Host → different live backend (multi-tenant vhost / catch-all) | **red** (`differs across Host variance`) | polarity **correct** — the deployment's `iss` genuinely varies with the request Host, which *is* the gated property — but the mechanism is edge routing, not code derivation; the diagnostic attributes the wrong cause | NOT documented — must be; this is the strongest missing row (a true positive the design would mislabel as its own regression shape) |
| M4c | Route-by-Host → same-issuer backend | green | true negative (outcome Host-independent) | NOT documented |
| M5 | Trusted edge honoring X-Forwarded-Host (BaseURL derivation) | green; probe varies only the direct Host | correct polarity — XFH is edge-controlled and stripped/re-set by trusted edges per AGENTS.md | ✓ §3 row is accurate |
| M6 | Scope-based: Host-derived issuer on device/auth-code mints | green | silently green **by scope** — the probe is cc-leg-only; R4 deferred. The acceptance wording ("fails exactly when the mint derives iss from the request Host") should be scoped to the cc leg | partially documented (R4 deferred) — worth one explicit line |

Also note: on a deployment with unset `server.issuer` (sentinel JWT issuer, request-base-derived discovery), mint 1 is already red for that root cause (E10 shape); the variance rows add noise on top of an already-failed run (F6 covers this). The probe's green signal is only meaningful when the mint-1 issuer rows are green.

## 3. `mintPost` header parity with `apiclient.Do`

`apiclient.Do` (`apiclient.go:107-129`) sets exactly: `Authorization: Bearer` (only when token ≠ ""), `Content-Type: application/json` (only when body ≠ nil), `Accept: application/json` (always), **no `User-Agent`** (Go injects `Go-http-client/1.1` or `/2.0`), no Host. The design's `mintPost` ("mirrors Do minus the bearer: Content-Type, Accept") is parity-correct **provided** it also: (a) leaves User-Agent unset, (b) sets Content-Type only when body ≠ nil (the mint body is never nil, so effectively unconditional), (c) marshals the same map via `json.Marshal` (sorted keys → both legs byte-identical), (d) uses the field not the header for Host (§1). Both legs route through `mintPost` with the same body value, so the B4-4 flip cannot break one leg — the single-point claim holds for the two mint legs, verified by construction.

**Coordination gap**: T-8d's invalid-scope probe, `revoke`, and post-revoke introspection POST **also** send JSON credential bodies to `/token`/`/revoke`/`/introspect` via `probeClient.Post` directly — they are *not* in `mintPost`. If B4-4's server-side strict enforcement rejects JSON credential bodies, those legs need their own flips. The design's §3/migration-6 "single transport point" wording should explicitly name these three call sites so the claim is not over-read (the strict campaign already owns the flip per the cross-campaign reviewer).

## 4. cc-path replay vs statelessness / one-time-use — confirmed no interaction

Read of `token_client_credentials.go:34-100`: the grant is stateless — client auth → scope resolution → `ti.Issue` → `RecordTokenIssued` (audit) → 200. No auth-code/PAR/device/refresh store is touched; there are no one-time-use semantics on this path; each mint is an independent issuance with a fresh 128-bit `jti` (`ed25519_issue.go` `generateJTI`, crypto/rand). The issuer name is fixed at construction (`serverbuildsign/build_signing_issuers.go:43` `WithEd25519Issuer(srv.Issuer)`; sentinel defaults otherwise) — never request-derived. `IssuerForClient` resolves per client, and both legs send the same client → same issuer instance → same name. `Validate` is read-only (signature + exp/nbf, `ed25519_validate.go:16`); `Revoke` is idempotent and per-`jti` (deny-list keyed by token, exp-bounded) — revoking the variance token cannot touch mint 1's token, and the revoke POST itself is 200-regardless per AGENTS.md. C3's `revokeToken` split (revoke POST only, no repeated post-revoke introspection) is sound. No DPoP/mTLS/PKCE/PAR interaction: neither leg attaches any of these, and a deployment requiring mTLS breaks mint 1 first (pre-existing, unchanged).

Residuals (ops, not soundness — one line each in the F-table would help): the variance mint adds a real second token issuance in audit with a Host-derived base (`middleware.BaseURL` → `r.Host`) that doesn't exist in DNS; it bumps the signing-usage counter; and it consumes one token-endpoint RPS budget unit (valid creds → no failure counters; anomaly detection is advisory per AGENTS.md).

## Verdict

The R2 mechanism is **wire-sound as designed**: every Go-semantics claim in §2.3/§2.5/§3 was confirmed empirically and in stdlib source (h1 verbatim Host / h2 `:authority` override; SNI and connection target bound to the URL host; probeClient negotiates h2 without changing server-observed Host; both legs single-point through `mintPost`); the cc replay is stateless and one-time-use-free; `mintPost`'s header parity with `apiclient.Do` is correct and the B4-4 flip cannot split the legs. **No blocking defect.** Required design edits are documentation and pinning, not rework: (1) add the M3 silently-green and M4a/M4b routing rows to the F-table, plus the h2/421 and connection-drop flavors in F3; (2) pin the two implementation guards — `req.Host` *field* (h2 silently drops the header) and the literal probeClient/DefaultTransport shape (a zero `&http.Transport{}` would silently drop h2, proxy-env, and pool parity); (3) scope the oracle claim to the cc leg; (4) name the T-8d/revoke/introspect body sites in the B4-4 coordination row.

VERDICT: R2's Host-variance probe is mechanically sound and correctly polarized against stock wiring (all Go override/SNI/h2 claims empirically verified on go1.26.5); the design's oracle documentation is incomplete — it covers only middlebox rejection (F3) while rewrite-to-upstream yields a silently-green false negative and route-by-Host yields both an undocumented false-positive class (dead vhost) and an undocumented true-positive class (live vhost with different issuer) — and two implementation pins (req.Host field vs header; DefaultTransport vs zero Transport) must be made explicit before implementation; none of these findings invalidates the mechanism, and the cc-path body/credential replay is confirmed free of statelessness and one-time-use interactions.
