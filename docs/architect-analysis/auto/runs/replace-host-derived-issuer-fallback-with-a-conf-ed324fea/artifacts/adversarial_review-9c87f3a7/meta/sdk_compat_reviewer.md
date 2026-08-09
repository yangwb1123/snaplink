**Pre-existing gate failure confirmed at HEAD** (file unmodified in worktree; 539 lines committed) — reported separately as required. The audit is complete.

---

# Audit verdict: 6/7 claim groups verified; placement claim is half-wrong (BLOCKING)

Audit written to `docs/architect-analysis/auto/runs/replace-host-derived-issuer-fallback-with-a-conf-ed324fea/artifacts/audit-7d1f9c02/task-1-audit.md`.

## Verified claims (evidence-backed)

| Claim | Result |
|---|---|
| 60-file ceiling, option in existing file | ✅ 60/60 non-test files; exemption `"interfaces/sso": 60` frozen (`directory_fanout_test.go:51`); 61st file = hard regression |
| Sentinel duplication; `configuredIssuer()` identity | ✅ Byte-identical at `server_discovery.go:252` + `server_discovery_config.go:264`; helper is behavior-identical; raw consumers (`accessors.go:130`, `handlers.go:415`) correctly excluded |
| Discovery ≡ resolveIssuer, zero wire changes | ✅ `buildBaseMetadata` (`:144`) + same-condition override (`:264-265`) ⇒ identity holds in mode-off; cache keyed by base is safe (server-level state) |
| Key pinning + inert key | ✅ No `IssuerAllowlist` field ⇒ `issuer_allowlist` is WARN-and-dropped (`config/source.go:260-276`); all 5 shipped YAMLs use exactly that key with `issuer ∈ allowlist` byte-equal ⇒ zero YAML edits needed |
| applyDefaults-before-validate | ✅ `source.go:143-144` exact; omitted issuer → `"sso-server"` (`config_load.go:70-72`) ⇒ deterministic F1 |
| Zero billing impact | ✅ `cmd/snaplink-billing` imports only `ssoclient/{remote,rs,quotaprojection}`; own `Issuer` for inbound validation; commerce/metering zero coupling |

## Blocking corrections

1. **The named files violate the 500-line budget.** `maxFileLines=500`, `fileSizeExemptions` empty and frozen (`maintainability_budget_test.go:34-40`). `options.go`=499, `sso_protocol.go`=500, `config_load.go`=497 — all three cross 500 with the design's additions, and new files are blocked in **both** `interfaces/sso` (60/60) **and** `config` (26/26). Fix: option → `options_passwd.go` (464, real margin) or net-zero edit of `options.go`; field → `sso_wiring.go` (462); membership check → method in `config_server.go` (225) with ≤3 net lines in `config_load.go`; `server_discovery*.go` changes land at ~495 — tight.
2. **State the empty-allowlist carve-out explicitly.** Mode-off byte-identity requires `len(allowlist)==0 → legacy path`; otherwise a bare `NewServer` returns `""` in mode-off and breaks the hard gate. Also: discovery must **SET** `cfg.Issuer=""` in the disallowed case, not skip the override — or it re-advertises host-derived `base` while `resolveIssuer` returns `""` (the RFC 9207 divergence this change exists to kill).

## Pre-existing failure (separate, not induced)

`go test -run 'TestMaintainability_FileSizeBudget' .` **fails on committed HEAD**: `infrastructure/defaultimpl/ed25519_jwt_issuer.go` is 539 lines (>500), unmodified in this worktree, no exemption entry. Introduced by commit 7586c6b3 (signing-key persistence). `make ci` will fail until it's split — unrelated to this design but must be fixed or tracked before handoff.
