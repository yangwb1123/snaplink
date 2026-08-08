Runbook delivered and verified. Every line reference was re-checked against the tree before writing.

**Deliverable:** `docs/architect-analysis/auto/runs/make-iss-a-configurable-allowlist-and-stop-host--d9077730/artifacts/design-a77de8a6/migration-rollback-runbook.md`

**What it covers, per the ask:**

1. **The wire-breaking step is named and isolated.** §1 classifies each change: landing enforcement code, adding allowlists with the *existing* issuer, and mixed old/new binaries are all wire-neutral (cmd path never Host-falls-back; discovery override uses the same config value). Only the issuer **value** change breaks the wire. §2.1 inventories the four forced configs — `cmd/sso-server/config.yaml:19`, `bin/config.yaml:17`, `ops/deploy/k8s/config.yaml:11`, `ops/deploy/helm/sso-server/values.yaml:162` — with verified per-file migration targets, and flags a finding the prior reviews left open: two of them (plus `kustomize/base`) target **http non-loopback** cluster URLs that are *illegal* allowlist entries under R5 and would panic at boot, so §2.3 forces the decision (external https URL / stay out of strict / documented limitation).

2. **Fleet-atomic rollout + pin coordination + canary semantics.** §6/§7 split the rollout: Phase C (enforcement, fleet-rolling, safe) vs Phase D (value change, fleet-atomic only — blue-green LB flip recommended, wave-atomic orchestration as alternative, rolling deploy explicitly banned). §7.2 gives the ordered pin graph (helm billing/stripe values with verified line refs, prod SSO configs, RPs, audit relay) and the no-dual-accept constraint in billing/stripe. §7.4 quantifies the stale-token window: `token_ttl` = 1h (`core.DefaultTokenTTL`), with the shrink lever (5m TTL 1h lead) and its mandatory lead-time math. §5 pins canary semantics: boot-panic + logs + byte-diff are the *only* evidence; traffic metrics are explicitly not; and it records the two canary truths from the reviews (require-on is redundant on the cmd path; inert-allowlist corner must be pinned first).

3. **Key-removal disambiguation + rollback gating.** §8 defines three named operations — R1 (revert keys, allowed only with value-change flag false), R1′ (value revert, must be a second Phase-D flip, never an emergency action), C1 (cleanup, forbidden as an implicit migration step because it silently restores Host-fallback capability). The rollback gate is the value-change flag, with a decision table.

4. **Landing-order hazards closed.** §3 requires co-landing the `kustomize/base` remediation with the enforcement code (it panics the moment the code lands — verified `overlays/dev` inherits base at `kustomization.yaml:14`), wires presence-guarded `ValidateIssuerConfig` into `config.validate()` so `--validate-only`/`make config-validate-all` preflight isn't a silent no-op (reconciling the sibling spec's non-goal), and extends the CI list with the three allowlist-carrying configs that today fail `validate-schema` invisibly.

No production code touched.
