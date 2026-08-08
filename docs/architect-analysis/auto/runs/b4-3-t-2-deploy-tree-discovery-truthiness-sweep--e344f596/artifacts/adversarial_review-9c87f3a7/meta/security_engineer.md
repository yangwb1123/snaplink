Hardening review complete and written to the pipeline's adversarial-review output directory. Summary of what was verified and found:

## Deliverable
`docs/architect-analysis/auto/runs/b4-3-t-2-deploy-tree-discovery-truthiness-sweep--e344f596/artifacts/adversarial_review-9c87f3a7/meta/outbound_fetch_security_reviewer.md` (+ `.meta.json`), following the run's reviewer-artifact convention. The design artifact itself is left untouched — the `design_gate` stage consumes this review.

## Findings (all empirically probed on Go 1.26.5 + the tree)

**1. Redirect policy — 1 blocking gap.** Verified correct: redirect-to-404 classifies as violation (final status wins), loops error after 10 hops, `file://` targets error out, POST→301/302/303 converts to GET, and cross-host Authorization copying (domain-based in `shouldCopyHeaderOnRedirect`) is moot since the sweep sends no credentials. **Gap:** the default client **follows https→http downgrade redirects** (proven live: TLS server 302 → plaintext 200). The design's "no scheme downgrade/leak is possible" claim is false as written — it must specify an explicit `CheckRedirect` on one shared client: refuse https→http hops, refuse non-http(s) targets, keep the 10-hop cap, allow cross-host https→https (needed for foreign docs; equality pass already pins the four always-present fields same-host).

**2. TLS posture — sound, pin it.** Default verification ON (x509 failure probe), TLS ≥ 1.2 default (crypto/tls source). Must state `InsecureSkipVerify` never set, no `--insecure` flag, plus a `httptest.NewTLSServer` → exit 1 acceptance test to lock it.

**3. Port() panic trap / IPv6.** The historical panic is gone; the live trap is **silent last-colon mis-split** (`Host:"host:8080:0"` → `Port()=="0"`, passes a naive range check) — unreachable if shape checks run only on `url.Parse`-verified URLs. New gaps: `host:` empty port passes shape (silent for never-probed `issuer`), `user:pass@` userinfo is the only credential vector (must reject), Atoi overflow (`host:18446744073709551616`) must be a violation not a skip. IPv6 works correctly via `Hostname()`/`Port()` — never manual colon splitting.

**4. Read-only guarantee — verified sound.** Handlers token/introspect/revoke/PAR/device/login all bind params + authenticate before any store write (checked each call chain); login 415/403 gates precede session work. Client-side: no cookies/auth headers, GET conversion on 3xx, POST retry only on GET-404. Residual: scope the claim to this server; add a 1 MiB doc-body cap (currently time-bounded only).

**5. SSRF-dialer claim — CONFIRMED consistent.** AGENTS.md §3 scopes the guarded dialer to wire-influenceable server outbound; `auditverify.readFromURL` (main.go:403-415) is a plain `http.Client{Timeout}` on the operator URL — even with a bearer token — so the precedent citation is accurate. Strongest argument: the dialer's purpose is rejecting loopback targets, which are the tool's primary targets (its own acceptance suite runs on 127.0.0.1). Must document the second-order-fetch nuance (probe URLs come from the doc; bounded by trust anchor + zero credentials + downgrade refusal), but not add the dialer.

No amendment changes the exit-code taxonomy, field table, C1a mechanism, allowlist gate, or T-9 byte-identity constraints — they're additive client-construction/shape-check rules plus three new acceptance tests.
