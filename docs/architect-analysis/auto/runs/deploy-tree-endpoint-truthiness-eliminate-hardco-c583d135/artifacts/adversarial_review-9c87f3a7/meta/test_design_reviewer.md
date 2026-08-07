Audit complete — report written to `docs/architect-analysis/auto/runs/deploy-tree-endpoint-truthiness-eliminate-hardco-c583d135/artifacts/audit-r1-r2-drift-value/audit.md`. Summary of findings:

**Tautology — clean.** R1 compares two independent sources of truth (operator literal ↔ root const concatenation, byte-verified at `ssoconfigdrift_controller.go:40-41` vs `consts.go:34,463,467`); it fails on either side's drift. R2 uses fixed expectations against a live server. R1 is genuinely load-bearing: the operator's existing 8 tests use path-agnostic mock servers (`runningServer`/`diffServer` never check `req.URL.Path`), so R1 is the only pin on the actual runtime strings, and R2 can't see the operator literal.

**R2 location — confirmed.** `config_audit_test.go` is `package sso_test`, same package as `feature_gate_hotreload_test.go` — `fghrGet`/`fghrAssertIdentical`/`fghrNeverMountedBaseline` reusable as-is. Caveat: the file's existing `cfgAuditGet`/`cfgAuditPost` discard headers/raw body — R2 must use the fghr helpers.

**Byte-identity baseline — stable and Go-version-independent, empirically verified.** Both 404 sources are the same stdlib `http.NotFound` (`router.go:319` native, `:370` gated) in the same process — self-referential comparison, no hardcoded bytes. I ran the full R2 scenario as a throwaway test (removed): default-gate 200s, gate-closed GET+POST byte-identical to both baselines, re-open 200. One nuance caught empirically: empty-body POST cluster-diff → **400**, so all three phases must send the `{"snapshot":...}` body.

**Material citation error.** `platform/configaudit/mount.go:MountRoutes` has **zero callers** — dead code. The real gated mount is `interfaces/sso/server_routes_admin.go:48-56` → `server_backup.go:50-60` on `core.NewGatedRouter(..., s.adminAPIGateOn)`. R2 is unaffected (real server, real mount); the design's failure-mode reasoning should cite the right file. The requirements' "mount.go:35-41 — Confirmed" was a shape-only false confirmation.

**Gate-default flip — covered** (phase 1 is default-based; phase 3 explicit; redundant backstops exist). **Method fidelity — confirmed** (GET running / POST cluster-diff with body).

**R1 CI-only boundary — real, precedented.** Root gates and `modules check` never run nested-module tests; R1 detects only via `make ci` → ci-modules (Makefile:263). This is a genuine local-dev bypass for exactly the drift class R1 guards — but identical to every nested module's posture and `make ci` is the mandatory handoff gate. Design should state the boundary explicitly.

**Acceptance mapping: 6/9 machine-checked.** Cases 1,2,4,5,6,7 fail on regression (6 and 7 are net-new byte-identity coverage for these routes; 4,5 partially redundant with the existing literal-path test). Case 3's go.mod-minimality, case 8 (const-derived compile break), and case 9's rg sweep are review-time checks, not failing tests — case 8 should be demoted from "testable acceptance" to review invariant.

Recommendations (non-blocking, folded into the audit doc): fix the mount citation, use `fghrNeverMountedBaseline` instead of the history baseline (immune to future store-coupling churn), pin the POST body in all phases, name R1's gate command in cases 1-2, and re-grade cases 3/8/9 in the mapping.
