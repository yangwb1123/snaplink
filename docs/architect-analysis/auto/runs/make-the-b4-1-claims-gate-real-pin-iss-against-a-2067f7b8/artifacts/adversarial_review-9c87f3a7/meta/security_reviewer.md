Done. The design document is hardened in all four areas (`docs/architect-analysis/cmd-sso-ctl-b4-1-claims-gate-design.md`). Summary of the assessments and the edits:

## 1. Host-ROUTING proxies (new F3a row) — real, bounded, three-layer mitigation

The F3 "no SSRF surface" claim was only dial-level true: the TCP target is always the advertised endpoint's address, but a vhost-matching proxy routes the unknown-Host variance POST at the application layer, delivering the live secret to the default upstream. Mitigations, all warranted and now in the design:

- **Runbook prohibition (required):** Host pass-through is the probe's validity precondition; verify the edge's unknown-Host default route before enabling `--expect-issuer`, or run the sweep inside the trust zone. Folded into §5 step 4/5.
- **Credential scoping (required):** dedicated, low-scope, revocable sweep client — the edge already terminates TLS on the same credential path, so the marginal exposure is misrouting accidents.
- **Probe design change (warranted, zero CLI surface):** a credential-less **preflight** (row 0) — variance-Host POST with real `client_id` + fixed dummy secret, requiring the oracle-safe `401 invalid_client` (verified: `server_token_clientauth.go:140,147,196,211,215,260` collapse every client-auth failure to that shape) **before** the credentialed mint. This converts F3's credential-bearing rejection into a dummy-credential probe and eliminates live-secret delivery to non-snaplink upstreams. Residual (a staging-mirror upstream holding the same client passes the 401 oracle): indistinguishable by any client-side oracle — documented, covered by runbook + scoping. Throwaway-credential variant considered and rejected (CLI surface for marginal gain).

## 2. Host-REWRITING proxies (new F3b row) — false green is real and irreducible; the R1 pin is the complement

Normalization erases the stimulus before the server; even a two-Host variance is blind. The design now documents that the **R1 pin survives normalization** because it compares against an operator constant, not another request-derived value: a rewritten upstream host diverges from the declared external canonical issuer and fires. Runbook: no Host rewriting on the sweep path; declare the external issuer, never the internal host.

## 3. Echo audit (C2) — all paths clean, four gaps closed in the spec

Added a per-emission audit table covering F1/F3/F5 and rows 1–5: `redactURL` on **both sides** of every mismatch row (R1, discovery, variance rows); `bodyEcho`→`sanitizeBody` on the variance non-2xx body; explicit no-echo rules added for the previously-underspecified paths — row 2's `%q` is the mint-2 **iss claim** (redactURL'd), never the token; the 200-without-`access_token` branch reuses `mint()`'s never-echo rule; revoke rows stay status-only.

## 4. mintPost enforceability — YES, by construction (not by convention)

`probeClient` (check.go) already provides the exact posture: token-less `*Client` wrapping `http.Client{Timeout: 30s, CheckRedirect: rejectRedirect}` (`http.ErrUseLastResponse` — 3xx observed, never followed; pinned by `TestSweep_RedirectNotFollowed`). The design now mandates **reusing** `probeClient(target).http` rather than mirroring it, and explicitly forbids `ck.client.http` (whose `New()` env fallback would attach `SSO_ADMIN_TOKEN` to the variance mint). `req.Host` overrides only the wire header; the dial stays on `req.URL.Host` — a redirect Location can never steer the secret.

## 5. XFH blind spot — acceptable, but the §3 row was materially refined

The original "mints an unchanged iss → probe green" claim was only half-right. `middleware.BaseURL` (request_url.go) replaces `r.Host` with XFH when the peer is trusted: **copying edges** (nginx `X-Forwarded-Host $host`) propagate the variance Host into XFH — the probe **fires** through X-Forwarded-Host derivation (a strength, now documented); **forcing edges** (XFH := constant) erase the variance — the blind spot. It's acceptable as a documented oracle boundary because the minted value is then edge-config-derived (stable, not client-influenceable — B4-1's operational concern), the R1 pin still fires on divergence from the declared issuer, and the runbook requires server-side issuer configuration. The concurrent hardening pass's pinned F2 stderr signature remains valid (the preflight is silent on success against a real server).

Budget note updated: the preflight makes the planned `mintPost`/`hostVarianceProbe`/`variancePreflight` move to sweep.go (~370 lines) certain; all functions stay ≤ 50 lines. New acceptance rows: `TestHostVariance_PreflightAborts` and an updated `TestHostVariance_Posture` (with the stub trap flagged — the existing `handleToken` would mint the dummy-secret preflight, so the 401 branch must be stubbed explicitly).
