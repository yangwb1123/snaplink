Deliverable written to `docs/architect-analysis/auto/runs/replace-host-derived-issuer-fallback-with-a-conf-ed324fea/artifacts/adversarial_review-9c87f3a7/meta/test_coverage_reviewer.md` (the role the pipeline selected but never executed).

**Provenance caveat first:** the pipeline persisted only the 15-line design *summary* — the full F1–F7 definitions and A-1..A-7 rows were lost when the design task died mid-investigation. The review materializes them from the summary + verbatim T-2 + fresh HEAD verification of every cited location, and marks the reconstruction for reconciliation.

**Mapping (T-2 → F → A → files → assertions):**

| Clause | F modes | A item | Test homes |
|---|---|---|---|
| T-2.1 allowlisted iss, never host | F6 | A-1 | extend `cmd/sso-server/issuer_wiring_test.go` (existing `newIssuerWiringServer` + `issWireDoGET` tampered-header helpers) — assert `iss == allowlist entry` across discovery/authz/token/form_post |
| T-2.2 discovery == resolveIssuer | F7 | A-2 | new `interfaces/sso/issuer_allowlist_test.go` (3-branch byte-equality), extend `test/oidc_discovery_test.go` (deny → visible `"issuer":""`, non-omitempty pinned) |
| T-2.3 boot fail-closed (∉ / empty) | F1, F2, F4 | A-3, A-4 | extend `cmd/sso-server/issuer_test.go`, new `config/issuer_allowlist_test.go` — including a direct `applyDefaults()`→`validate()` ordering pin |
| T-2.4 no path reaches host fallback | F3, F7 | A-5, A-6 | mode-off: existing pins unchanged (`rootcov_flow_test.go:235-236`, `TestDiscovery_IssuerComesFromWithIssuer`, `security_test.go` counts, 3 wiring tests); sweep + concurrent `-race` leg in wiring/unit/bearer-challenge files |
| migration | F5 | A-7 | new `config/issuer_allowlist_test.go` — table over all 5 shipped YAMLs (load, membership post-defaults, no unknown-key WARN, rendered==kustomize drift guard) |

**Gaps flagged (all five requested, plus extras):**
1. **Empty allowlist** — design never defines `[]`/nil semantics; must be pinned as mode-off or the migration claim drifts.
2. **Sentinel in config** — `issuer: sso-server` + `issuer_allowlist: [sso-server]` validates under membership-only rules (legacy-consistent but must be pinned + documented); `snaplink-sso` must fail on both rules.
3. **Shipped YAMLs** — `make config-validate-all` covers *none* of the 5; migration rests solely on the new test table; rendered YAMLs are regenerable and need the drift guard.
4. **Boot ordering** — determinism rests on one call pair (`source.go:143-144`); needs a direct-ordering test. Bigger: **T-2.3 has no SDK-side enforcement** (no `NewServer` panic in the summary) — cmd-path-only as written; decision required.
5. **Concurrent/boot-path** — needs a dedicated boot-path walk of every entry under tampered Host plus a `t.Parallel()`+`-race` rotating-host test; also covers the discovery cache (base-keyed, TTL'd) and the new per-request ERROR log (log-flood vector to decide on).

**Blocking extra finding:** the summary's own file homes violate budgets — `options.go` is at 499 lines, `sso_protocol.go` at exactly 500, so `WithAllowedIssuers`/the field cannot land there; `sso_wiring.go` (462, headroom 38) is the verified-safe home (the sibling run used it), and `config_load.go` (497) has only 3 lines of headroom for the validation hook.
