Design complete: `docs/architect-analysis/cmd-sso-ctl-b4-1-claims-gate-design.md`.

## Verification verdict

All evidence claims were re-checked against the worktree and are **accurate** — including the evidence's own corrections, which I re-verified: `check.go:77-78/116-117` flags+wiring, `token.go:187-188` discovery-only issuer oracle, the cc-path structural roles impossibility (`token_client_credentials.go:51-57` Subject has no `Roles`/`Claims`), `resolveIssuer`'s `requestBaseURL` fallback (`server_discovery.go:251-256`), the `"sso-server"` non-sentinel cmd default (`config_load.go`), the device mint's bag-carrying shape (`token_device.go:92-105`), the `ext` nesting, and the harness defect — confirmed both by reading and by running the suite (11 red tests, all seven live rows failing with `iss "snaplink-sso" != discovery issuer`).

**Five material corrections** the evidence missed:

1. **C1 (load-bearing)** — `TestMaintainability_` is already red at HEAD on the WIP files: `verifyClaims` is 58 lines / cyclo 19 and `CheckRun` is 66 lines, both over budget. The spec's "functions all under the 50-line budget after the additions" is false. The design's refactor (`parseCheckFlags`, `verifyClaims` split along the unconditional/declared seam) is therefore required, not optional — it absorbs R1/R3 and repairs the pre-existing gate violation in the same two functions.
2. **C2** — R1.2's "no flag value echoed verbatim" is over-strict; the correct property is the existing `redactURL` discipline (the declared issuer is config, not a secret).
3. **C3** — the variance token's lifecycle was unspecified; the design revokes it (new `revokeToken` helper, no duplicated post-revoke introspection) so no valid probe token outlives the run.
4. **C4/D4** — the variance probe is strictly opt-in under `--expect-issuer`, preserving the byte-identical-when-unset rollout property.
5. **C5/C6** — `SSO_EXPECT_ISSUER` env parity explicitly not implemented; and the regression fixture must share one Ed25519 key across per-request issuer instances (verified feasible: `WithEd25519Key` exists and `Validate` never compares `iss`).

## Design highlights

- **API**: one new CLI flag `--expect-issuer string`; no server-side, no `apiclient.go` changes; exit codes and golden stdout untouched.
- **R2 mechanism**: a second mint to the same advertised `token_endpoint` with `req.Host = "sweep-host-variance.invalid"` (RFC 2606 reserved) via a new single transport point `mintPost` — the B4-4 form-campaign coupling lands in exactly one function.
- **Failure modes**: 7 enumerated (F1-F7), including the middlebox-Host-rejection false-positive risk with the `.invalid`-TLD and opt-in mitigations, and the verified probe polarity (green on any stock deployment — minted `iss` is a fixed string; red only under Host-derived minting).
- **Migration**: 6 ordered steps ending in a pure flag-flip rollout; the fixture (`hostDerivedIssuer`, shared-key, ctx-stashed Host) reproduces the lockstep blind spot with everything else green.
- **Acceptance mapping**: every R1-R5 row maps to a named test, including the three new posture/dedup/ext-only rows.
