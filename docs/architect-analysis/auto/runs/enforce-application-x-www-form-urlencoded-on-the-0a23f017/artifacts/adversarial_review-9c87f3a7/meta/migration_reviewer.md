All four claims verified against the working tree (HEAD `3ef27fa5`). Report follows.

# Verification: migration and rollback path vs real deploy trees

## 1. Single-flip point in `ops/deploy/compose/config.yaml` — VERIFIED (cosmetic line drift)

- `server:` block is lines **9–15** (six keys: `issuer`, `base_url`, `listen`, `session_ttl`, `token_ttl`, `default_token_strategy`); line 16 is blank. The design's "(:9-16)" is the block + trailing blank — cosmetic.
- **Key naming consistent**: all existing `server:` keys are snake_case, matching the proposed `require_form_content_type`. In `config/config_server.go` the closest analog is `oauth_21_strict_mode` (also a strict-mode bool under `server:`); pointer-opt-in matches the `HTTP2 *HTTP2Config` (`yaml:"http2,omitempty"`) precedent.
- **Compose has exactly one sso-server config source**: the mounted file plus the etcd prefix `/snaplink/config` (empty by default; README's etcdctl recipes only show `logging.level` / `audit.memory_capacity` overrides). No `environment:` block on the sso-server service. So the committed tree has one flip point — an operator could also set it via an etcd/env override, same as every other knob (not a flaw).
- Append-only-when-set: `ServerOptions()` (config_load.go:301) with the `anySet()` precedent at :345 — the design cites :301 for the append site (function start; substance right, the `anySet` call is at :345).

## 2. Boot-time rollback-by-key-removal — VERIFIED, with one precision

- `config.LoadFromSources` runs once at boot (cmd/sso-server/main.go:88); `ServerOptions()` is called once (build_app_core.go:154). Rollback = delete key / set `false` + restart; mode-off dispatch is a transparent pass-through and `NewServer` seeds `credentialFormOnly = false` (sso.go:58-80 assignment pattern verified). No state, store, or rotation side effects to unwind.
- **The precision**: a SIGHUP `config/reload.Reloader` **exists** (main.go:113) but is allowlist-only — `safeReloadPaths` = `/logging/level` + `/feature_gates/*`; `safeReloadPrefixes` = `/security/rate_limit`. A `server.require_form_content_type` change would be diffed, reported as `ignored_requires_restart`, and left untouched (default bucket). So "no hot-reload" is substantively accurate — the key is boot-only by default — but the field doc should note it must never be added to the reload allowlist, or the rollback claim silently dies. docs/config-reference.md's "Hot Reload (SIGHUP)" section (:453-468) documents exactly this class.

## 3. helm/baremetal/k8s stay default-off — VERIFIED

- `grep -rn require_form_content_type ops/deploy/` → **zero hits** (exit 1); no `SSO_SERVER__REQUIRE_FORM_CONTENT_TYPE` env override anywhere in the trees (k8s deployment.yaml and kustomize base only show commented `SSO_LOGGING__LEVEL` / `SSO_AUDIT__MEMORY_CAPACITY` examples; baremetal `sso.env.example` is issuer/base_url/postgres/redis only; helm renders `values.yaml config:` via `toYaml` with no such key; k8s-distributed envs are cluster-bus/keys only).
- `server:` blocks inspected in every tree: baremetal-ha/sso/config.yaml:16, k8s/config.yaml:10, k8s-distributed/config.yaml:1, kustomize/base/config.yaml:10 + overlays/prod/config.yaml, helm values.yaml `config.server:` :161-164 — none carry the knob.
- **Nothing in those trees breaks under strict mode**: they stay default-off, and their `/token` consumers are the same form-minting binaries already verified. Bonus check beyond the design: the k6 loadtest scripts under `ops/deploy/loadtest/` also already speak form on all four flipped endpoints (`par.js:48/:79` form, JSON only at `/auth/login` :63; `authcode.js:84` form, JSON only at `/auth/login` :67; `token.js:50`, `introspect.js:45/61/73` form), and `baremetal-ha/smoke.sh` uses `--data-urlencode` (form). The flip is a no-op for every in-tree consumer under `ops/deploy/`.

## 4. Sweep assertions vs actual layout — VERIFIED (two constraints to pin)

- **(a) existence-once**: layout supports it — `server:` at column 0, flat 2-space-indented keys; the file is the only config mounted. "Stdlib-only" means a line-based scan (no YAML parser in stdlib), which works for this flat block.
- **(b) absence-everywhere**: zero hits today across all ~80 files under `ops/deploy/`; the design's Modify list adds the literal only to compose/config.yaml — consistent. Constraint to pin: the literal must never appear in `ops/deploy/compose/README.md` (design correctly does not touch it) or any other tree's env examples/comments. One implementation gap: **no existing test in `test/` walks `ops/deploy/`** (test/ha skips rather than walking), so the sweep needs a root-resolution mechanism (e.g. `../ops/deploy` relative to the package dir or `runtime.Caller`) — a detail the design does not cover.
- **(c) docs**: `docs/config-reference.md` has a `## Server` table at :36 (Key/Effect, no Default column — "default off" goes in prose, matching `security.client_registration_rate_limit` style). Zero hits for the key today → RED pre-change, confirming the triple-RED claim.

## Drifts to report (pre-existing, not blockers)

1. **`docs/config-reference.md` Server section is thin**: it documents only `server.http2`, `server.topology`, `hosted_login` — `oauth_21_strict_mode`, `signed_metadata`, and `discovery_doc_cache_ttl` are absent. Adding the new row is still correct per AGENTS.md §5.6, but the doc already under-covers server bools.
2. Cosmetic: "config.yaml:9-16" (block is 9-15), "config_load.go:301" (`anySet` precedent actually at :345).
3. The rollback claim's "no hot-reload" should be read as "not in the reload allowlist" — the SIGHUP reloader exists and will report the key under `ignored_requires_restart`.

**Verdict**: migration (single flip, default-off everywhere else) and rollback (delete key + restart, byte-identical baseline) both hold against the real trees; the sweep test's three assertions match the actual layout of `ops/deploy/` and `docs/config-reference.md`, with the two implementation notes above (repo-root resolution in the sweep; reload-allowlist exclusion must be pinned in the config field doc).
