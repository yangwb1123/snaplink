Design doc written to `docs/auto/interfaces-cors-direction2-design.md`. Every claim was re-verified against source before writing; the doc also resolves four ambiguities the spec left open.

## What the design covers

**Decision 1 — `security.cors.path_overrides` YAML mapping**
- API surface: `CORSConfig.PathOverrides map[string]CORSConfig` + extracted mapping helper in `toPolicy()`, `/`-prefix validation at `LoadFromSources`, gate widening at **both** sites (`config_load.go:315`, `build_app_security.go:170`), inline struct → `toPolicy()` call, boot-log override count
- Storage model: pure in-memory chain (YAML → `CORSConfig` → `cors.Policy` → precomputed `corsConfig`); no persistence, no cross-replica state; the pointer-overwrite hazard collapses to two calls of the same function
- Failure modes: non-`/` prefix, empty-origins override (preflight falls through to router — no short-circuit), `enabled:false` ignored by construction, `/token` vs `/tokenizer` prefix bleed, and a **pre-existing nondeterminism I verified in `buildOverrideConfigs`** (equal-length prefix ties depend on map iteration order — now operator-reachable, recommended 4-line deterministic tie-break)

**Decision 2 — contract docs**
- API surface: one Security-table row naming every leaf incl. new D1/D3 fields, three pinned semantics (empty-origins disables, credentials+`*` echo-origin, restart-required), example drift fix in `cors.go:44` + `cors_test.go:193`
- Key ruling: the spec's "zero occurrences repo-wide" grep is **unsatisfiable as written** — `X-RateLimit-Remaining` survives in historical analysis/results docs that document the drift itself; I scoped the enforceable grep to code + contract docs and recorded the ruling

**Decision 3 — append semantics + constants**
- API surface: `AllowedHeadersExclusive` escape hatch, defaults-first case-insensitive order-preserving dedup, `cors` → `shared/core` import (verified acyclic via `go list`: core imports only stdlib), optional `DefaultAllowedHeaders` built from core constants
- **Explicitly flagged as the direction's only behavior change**: `buildConfig` is shared by config and direct SDK paths, so SDK callers with non-empty `AllowedHeaders` switch from replacement to merge — deliberate and documented, with the escape hatch
- Critical find: `cors_test.go:140` is the one existing test encoding the old replacement contract (`"X-Custom, Authorization"`) and **must** change in the same commit

Cross-cutting: gates sequence, budgets (zero new files in `config/`, zero production changes in `interfaces/sso`, `test/` integration file exempt), and non-goals restated.
