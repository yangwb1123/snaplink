// Package configaudit records runtime-configuration changes (a JSON Patch
// per admin mutation), serves a running-vs-applied config comparison, and
// detects cross-replica configuration drift.
//
// The configuration pipeline (YAML + env + etcd + flags -> deepMerge ->
// validate -> *Config) ends at startup: once the server is running, an
// admin API mutation, a hand-edited config file, or a config-drifted peer
// replica all change what is EFFECTIVELY running without leaving a trail.
// This package is that trail:
//
//   - Store + MemoryStore (+ configaudit/sqlite) persist a config_history
//     of {actor, resource, resource_id, patch, reason} entries — see
//     docs/expansion-volume2-2026-07-01.md §3 — and versioned applied-config
//     baselines (Store.Apply/Applied/Rollback, the declared peer-config
//     baseline write path behind POST /api/v1/admin/config/apply and
//     .../rollback; see docs/design/config-apply-mode.md).
//   - Diff computes a minimal RFC 6902 JSON Patch (add/replace/remove only)
//     between two config snapshots for the running-vs-applied admin
//     endpoint. See Diff's doc for the documented array/type-change limits.
//   - Redact / RedactOps replace secret-shaped values ("***") before a
//     snapshot or patch reaches a Store or an HTTP response.
//   - Digest + DriftDetector let replicas compare a sha256 of their running
//     config over the cluster Bus WITHOUT shipping the (possibly
//     secret-bearing) config itself — report-only, never blocks a request.
//
// Every concern here is an interface + a real memory implementation
// (AGENTS.md §0.6) — no mocks. *sso.Server wires this package's
// HandlerDeps via its own accessor methods, exactly like platform/audit's
// HandlerDeps.
package configaudit
