Reconciliation complete. The artifact at `docs/architect-analysis/auto/runs/replace-the-host-derived-resolveissuer-fallback--6a26a2b3/artifacts/design-a77de8a6/task-1-design.md` now carries the definitive acceptance mapping (docs-only change — no Go edits, so no gate run is triggered; every code fact cited below was re-verified against the tree).

## What was wrong

1. **Arithmetic**: the summary claimed 21 GWT cases but named buckets A-startup ×11 + T-9 ×7 + T-2 ×3 + regression ×3 = **24**. The bucket sizes were correct; the total was the miscount.
2. **FM-3/FM-10 omitted**: the summary enumerated FM-1, 2, 4, 5/6, 7, 8, 9, 11 only. Reconstructed from the sibling configcmd spec's own failure set (R2-2/R2-3 and R2-5): **FM-3 = empty/malformed allowlist**, **FM-10 = issuer↔`base_url` origin coherence** (mismatch rejects; `base_url` unset ⇒ skip, documented limitation).

## What the artifact now contains

- **Definitive GWT enumeration — 24 cases** (grep-verified: 24 rows), each with Given/When/Then and placement: A-1…A-11 (config `Load` validation + `NewServer` panic per the `WithCustomGrant` precedent at `options_grants.go:78`), T9-1…T9-7 (discovery issuer **and endpoints** pinned under spoofed/absent/forwarded Host, cache-key pin), T2-1…T2-3 (minted `iss` pinned across code/refresh/token-exchange/client-credentials grants), R-1…R-3 (byte-identical legacy).
- **FM→test matrix, all 11 mapped**: FM-1 (A-5, T9-1/7, cmd reference-config), FM-2 (A-6, cmd), FM-3 (A-3/A-4), FM-4 (A-11), FM-5 (A-7), FM-6 (A-8), FM-7 (A-10, T9-5), FM-8 (T9-2/3), FM-9 (T9-6, T2-1…3), FM-10 (A-9), FM-11 (structural — committed `TestMaintainability_*`/`TestArchitecture_*` gates + R-3 pin; `interfaces/sso` confirmed at exactly 60 non-test files, `config` at 26, `sso.go` 499).
- **Placement**: `interfaces/sso/issuer_allowlist_test.go` (new; test files don't count toward the ceiling) = A-11, T9-1…7, T2-1…3, R-1; `config/issuer_allowlist_test.go` (new) = A-1…A-10, R-2; `cmd/sso-server/issuer_test.go` (extend; 116/500 today) = R-3 + deploy-tree membership assertions.

## Byte-identical regression proof (the confirm you asked for)

The artifact specifies three committed mechanisms, not an assertion: **(1)** R-1 is a differential control-server test — a legacy server built exactly as HEAD vs. the candidate, same request matrix, asserting raw `bytes.Equal` on discovery bodies plus `resolveIssuer` equality, with an allowlist-on positive control that must differ; **(2)** R-2 pins the nil short-circuit (`issuerAllowlist == nil` before any normalization) and nil-after-`Load`; **(3)** R-3 requires the existing suites — including all four tests in `cmd/sso-server/issuer_test.go` and the discovery/authz-error suites — to pass unmodified, which is this repo's own byte-identity convention (`server_discovery_config.go:100`: "byte-identical… the existing discovery + signed_metadata tests are the proof").
