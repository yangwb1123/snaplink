Design complete. Summary of the verification and design work:

## Evidence verification — all claims confirmed at HEAD (`374f9890`)

Every claim in the evidence was re-checked against the repository, plus 9 supporting claims. All **confirmed**, including the ones I checked independently rather than trusting the spec:

- **`platform_token.go:17-18`** — scope constants, boot-pinned scope, one space-joined `scope` param in `platformTokenRequest` ✓
- **`Matrix()` = 9 rows**, only `audit:event:write` among audit ✓
- **`RejectUnregistered`** — 400 plain `{"error":"invalid_scope"}`, nil-registry no-op ✓
- **`validateScopeRegistry`** — membership only when enabled, exact error string, wired at `config_load.go:220` ✓
- **compose `config.yaml:62-67`** — `enabled: true` with no audit scopes in `extra_scopes`; the three compose clients are all registered today ✓
- **`buildApp` does NOT validate** (zero references in `cmd/sso-server/`; construction at `build_stores.go:305-312`) — the Leg-A split into wiring + config-gate is faithful ✓
- **Gap is live**: measured `go run ./cmd/sso-server --config=ops/deploy/compose/config.yaml --validate-only` exits 0 today, so the enabled registry accepts the file while an operator-registered provisioner client would 400 forever ✓

**Baselines**: `go build ./...` clean; all three touched test suites pass. **Three pre-existing root-gate failures** (directory depth/fanout from `docs/architect-analysis/auto` batch artifacts, root fanout 24>21, `ed25519_jwt_issuer.go` 539 lines) — unrelated, reported separately per AGENTS.md.

## Nuances found that the spec glossed over (resolved in the design)

1. `ClientConfig` has **no `GrantTypes` field** — R1's client can't express one (nil = unrestricted per `server_token.go:111`); R4's `sso.Client` seed sets `["client_credentials"]` per the T-C invariant.
2. R1's negative control can only assert registration absence, never boot failure — R2 owns the boot-closed half.
3. R5 parity must read the compose file's **provisioned 8-row matrix** (`MatrixOrDefault` is bypassed when `matrix` is present) and use `scoperegistry.ProtocolScopes()` for the protocol set.
4. R4's negative control reuses the existing `srClientAny` + matrix-only harness — no new client needed.
5. Layer legality confirmed: `config`/`cmd/sso-server`/`test` (composition, layer 6) → `infrastructure` (layer 4) is a legal downward edge with precedent.

## Deliverable

`docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-2-scope-registry-design.md` following the accepted sibling format, covering the requested sections:

- **API changes** (§3): none to production APIs — one additive YAML entry in an existing key; test-only surface; the only behavioral delta is in the compose tree.
- **Compatibility constraints** (§5): frozen 9-row matrix, default-off byte-compat, pinned wire shapes, no `interfaces/sso` touch (60-file ceiling), no new deps.
- **Failure modes** (§6): 7-row table — boot-closed gate, live mint-400 gap, parity drift, construction fail-closed, seam bypass, config-validate, pre-existing gate failures.
- **Migration steps** (§7): land R3+R1/R2/R4/R5 together; G5 operator order (scopes → registry → client); exact rollback.
- **Testable acceptance mapping** (§8): 7/7 machine-checked Given/When/Then items mapped to concrete test functions and commands, each seam verified against real code.

No Go files were modified, so the mandatory post-edit gates don't apply to new work; the verification commands in the design were run as baselines during evidence gathering.
