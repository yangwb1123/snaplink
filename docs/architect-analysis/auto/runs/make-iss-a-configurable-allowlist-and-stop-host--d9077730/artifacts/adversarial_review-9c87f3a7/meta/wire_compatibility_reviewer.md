I've completed the review against the tree at HEAD `81d42e12` (plus the dirty worktree), running the relevant gates (`sso-ctl config validate-schema` on the deploy configs, greps over config/options/docs/openapi, route/flow tracing for every RFC 9207 emission site). Findings below, per thread.

## 1. Shared key with the unlanded configcmd sibling — landing-order risk: **REAL, but not where the design thinks**

**Confirmed safe by construction**: both the campaign design and the sibling spec (`docs/architect-analysis/cmd-sso-ctl-configcmd-b4-1-issuer-allowlist-requirements.md`, unlanded — `cmd/sso-ctl/configcmd` has zero allowlist code today) use `server.issuer_allowlist`, and both `configcmd validate-schema` and the server loader consume the same reflection-generated `config.Schema()` (`config/source.go:230`). Schema drift between the two is impossible; the worktree's in-flight `cmd/sso-ctl/configcmd/main_test.go` change doesn't touch this.

**Three genuine risks the design must resolve:**

- **Preflight blindness until the sibling lands.** `--validate-only` (`cmd/sso-server/main.go:96-101`) never constructs `sso.NewServer`, so `s.validateIssuerConfig()` (design: `sso.go:499→500`) is *not* exercised by `make config-validate-all` (Makefile:400-410, the CI gate, server loader only). And `configcmd validate` today is just `config.Load`. So if the server change lands first and migration step 2 ("preflight via sibling config validate") runs before the sibling lands, preflight is a silent no-op and the first signal of a bad allowlist is a boot panic at fleet rollout. The design's "(landing-order dependency)" acknowledgment doesn't resolve this. Two ways out: (a) land the sibling first; or (b) wire `core.ValidateIssuerConfig` into `config.validate()` with the presence-guarded semantics (allowlist present ⇒ membership; `require` on ⇒ non-empty; empty/off ⇒ no-op) — this makes `--validate-only`, `configcmd validate`, and boot agree by construction and kills the dependency. Note (b) directly contradicts the sibling spec's explicit non-goal ("No enforcement inside `config.Load`/`validate()`"), a non-goal written when the sibling was the *only* enforcer; the two specs need deliberate reconciliation.
- **The sibling's gate is unconditional; the server's is opt-in.** The sibling spec refuses a `require_configured` toggle and mandates "omitted `server.issuer` ⇒ exit 1" always. After both land, `config validate` exit 0 ≠ server strict mode and exit 1 ≠ server boot failure. Preflight must be documented as a *target-state* gate, not a *current-state* check, or operators will believe `validate` green means enforcement is live.
- **Preflight will force wire-breaking changes (see §5)**: the sibling gate requires an absolute-URL issuer, and four configs today use the literal `issuer: sso-server` (`cmd/sso-server/config.yaml:19`, `bin/config.yaml:17`, `ops/deploy/k8s/config.yaml:11`, plus the sibling spec's own correction for `bin/config.yaml`'s `localhost:28898` base). Their remediation is an issuer *value* change, which is the one partial-deploy state that breaks token discovery.

## 2. `ops/deploy/*` warn-and-ignored state: **CONFIRMED, plus two findings the design missed**

Confirmed: `ops/deploy/k8s-distributed/config.yaml:4`, `ops/deploy/kustomize/base/config.yaml:12`, `ops/deploy/kustomize/overlays/prod/config.yaml:13` (and rendered `bin/k8s-rendered/prod/all.yaml:35`, `bin/k8s-rendered/dev/all.yaml:22`) carry `issuer_allowlist`; the loader warns and ignores them via `decodeStrictWithFallback` (`config/source.go:264-280`, "unknown keys … will become errors in a future version"). All five have `issuer` ∈ allowlist, so post-landing enforcement activates with zero behavior change.

Missed findings:
- **The hard gate already fails today**: `sso-ctl config validate-schema --file ops/deploy/k8s-distributed/config.yaml` exits 1 ("`server.issuer_allowlist: unknown field`") — I ran it. The shipped deploy configs fail the schema's hard gate while the server boots them with a warning. Any CI wiring of `validate-schema` over `ops/deploy/**` would be red at HEAD.
- None of the three allowlist-carrying files is in `make config-validate-all`'s list (7 configs, Makefile:400-410), so nothing in CI observes either the warning or the schema failure today.

## 3. Strict-mode transition semantics: **mostly coherent; three sharp edges**

- Coverage claim verified: the "8 RFC 9207 sites" are `server_finish_login.go:191/456/461/469`, `origin_validation.go:163/176`, `server_discovery.go:343`, `server_mfa.go:139` — and all are reachable only through `handleLogin` or `handleMFAComplete` (`issueMFAChallenge` callers: `server_finish_login.go:173`, `server_login_client.go:185/259`; trusted-device paths `server_mfa_trust.go:181/230` ride `resumeLoginAfterMFA`). G2+G3 do cover all 8 without touching `server_finish_login.go`. G1 placement before the body-cache lookup is structurally available (`server_discovery_config.go:62-70`); G4 after `tokenNoStoreHeaders` (`server_token.go:22`) keeps the 503 no-store.
- **Edge 1 — residual Host-derived emissions on the SDK path**: under strict-on + issuer-unset (SDK only), five+ non-RFC-9207 sites still emit `resolveIssuer` (Host-derived): native-SSO device exchange (`server_native_sso.go:225`), logout (`server_logout.go:259`), and every bearer-challenge realm (`mesh_authz.go:179/217/253`, `server_userinfo.go:135/137`, `server_me.go:43/49`, `server_resource.go:182`). "Never Host-derived" is therefore not absolute on the SDK path; either scope the claim to cmd-path + the gated endpoints, or route `denyUnconfiguredIssuer` through `setBearerChallenge` too.
- **Edge 2 — allowlist presence is the enforcement switch, not `require_configured_issuer`**: on the cmd path the issuer is always non-empty (default `"sso-server"`), so "allowlist present ⇒ panic on non-member" makes `require_configured_issuer` behaviorally redundant except for (a) empty-allowlist + require-on panic and (b) SDK 503s. The canary step ("flip require on") is a no-op on the cmd path once allowlists are deployed — the design should say so, or the canary will look like it "proved" nothing.
- **Edge 3 — the inert-allowlist corner**: allowlist present + issuer *unset* (SDK) + require off ⇒ no panic (empty isn't a member check), no 503 (require off) ⇒ the Host fallback continues and the allowlist is decorative. The design must pin this explicitly (either presence triggers the runtime 503s too, or this deferral is documented intent).

## 4. Byte-identity when mode off: **holds, with four things to pin**

Mode off (no allowlist, require off): gates are conjunctive on require, `validateIssuerConfig` no-ops, options inert — response bytes are unchanged. Traps to pin in A-12/A-13:
- `core.NormalizeIssuer` must be scoped to allowlist *comparison* only — the stamped `iss` stays the raw configured literal (`Ed25519JWTIssuer` stamps literally; a trailing-slash trim at boot would silently change every minted token and the discovery `issuer`).
- `configcmd validate --print` JSON gains two keys (additive; fine for tolerant consumers, but it is a byte change on that surface).
- The unknown-key WARN disappears for the three deploy configs at boot (log-line change only).
- `config.Schema()` output changes (additive).

## 5. Migration/rollback and partial-deploy states: **one hard break, currently unaddressed**

- **Safe partial states confirmed**: on the cmd path `resolveIssuer` never exercises the Host fallback (issuer is always defaulted/config-valued; discovery issuer override at `server_discovery_config.go:264-266`), so mixed old/new binaries with *identical* `server.issuer` values emit byte-identical discovery, minted `iss`, and RFC 9207 `iss`. Billing trust is pinned (`SNAPLINK_BILLING_ISSUER` mandatory, `config.go:292-325`; helm values pin `https://sso.example.com`) and billing never fetches discovery — unaffected by the 503 gates as long as the issuer value is unchanged.
- **The wire-breaking partial state is the issuer *value* change** — and the migration *forces* it for four configs, because a literal (`sso-server`) can never be a valid absolute-URL allowlist entry. Changing the issuer value: (a) must be fleet-atomic — a mixed fleet mints two `iss` values and RFC 9207 clients comparing authz `iss` against discovery fail on half the fleet; (b) ripples to billing/stripe adapter issuer pins and RPs; (c) leaves pre-flip tokens valid up to `token_ttl` (1h default) that new-issuer validators reject. The design summary's migration (switch-off → preflight → canary → fleet → key-removal) does not mention the issuer-value-change step, its atomicity, or the pin ripple. Recommendation: prefer allowlists containing the *existing* issuer; schedule any issuer-value change as a separate, explicitly breaking step.
- **"Key-removal" is ambiguous and dangerous either way it lands**: as rollback, config-diff revert (remove allowlist/require) restores legacy boot — safe only if no issuer value changed (otherwise a mixed-issuer rollback window); as a final cleanup step, removing the enforcement keys silently reverts the deployment to Host-fallback-capable mode. The plan should name which one it means and gate rollback on the value-change flag.
- Canary note: a correctly configured canary serves byte-identical responses — the only observable canary signal is boot-panic-on-misconfig and logs. Fine, but the plan shouldn't claim traffic-level canary evidence.

## 6. Contract-doc coverage: **NOT covered — verified absent at HEAD**

- `docs/config-reference.md`: only the `server.issuer` row exists (line 48). No `server.issuer_allowlist`, no `server.require_configured_issuer` rows.
- `docs/error-codes.md`: no `issuer_not_configured` / `ErrIssuerNotConfigured` anywhere (grep exit 1; the closest neighbor is `impersonation_unavailable` 500 at line 569). The design's 503 code is undocumented.
- `docs/openapi.yaml`: 36 documented 503 responses, none `issuer_not_configured`; no mention of the new gates.

Per AGENTS.md §5.6 (new `Err*` → `docs/error-codes.md`; endpoint → `docs/openapi.yaml`; config knob → `docs/config-reference.md`), the design's contract-doc story is incomplete — the artifacts claim doc updates, but neither the requirement nor the design summary itemizes the `issuer_not_configured` error-code row, the two config-reference rows, or the openapi 503 response additions on `/token`, discovery, `/auth/login`, `/auth/mfa`. None of this can be "confirmed" from the deliverables; it must be added to the change scope with the acceptance pins.

## Verdict summary

| Thread | Verdict |
|---|---|
| Shared key / configcmd landing order | Key naming safe (single reflection schema); preflight blindness + gate-posture mismatch unresolved |
| ops/deploy warn-and-ignored | Confirmed; plus validate-schema already hard-fails those 3 configs at HEAD; excluded from CI list |
| Strict-mode transition | Gates cover all 8 RFC 9207 sites (verified via flow); residual SDK leaks (native SSO, logout, bearer realms); allowlist-presence ≠ require semantics need explicit pinning |
| Byte-identity (mode off) | Holds; pin normalization-scope, `--print` JSON, and the 4 edge cases |
| Migration/rollback | Issuer-value change is the single wire-breaking step; it is forced for 4 configs and missing from the plan; "key-removal" ambiguous |
| Contract docs | `ErrIssuerNotConfigured`/`issuer_not_configured` and both config keys absent from docs — AGENTS §5.6 not satisfied by the deliverable |

The highest-severity item is the combination of §5 and §1: the preflight gate that forces issuer-value changes can be landed blind (no-op sibling) and the change it forces is the one partial-deploy state that breaks token discovery and billing trust. The design should (1) put `ValidateIssuerConfig` in `config.validate()` (presence-guarded) so `--validate-only`/CI preflight works without the sibling, (2) schedule issuer-value changes as an explicit fleet-atomic step with downstream-pin coordination, and (3) add the three contract-doc updates to the change scope.
