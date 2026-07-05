# Wave 2 — Tranche 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. One implementer + one reviewer per task; the per-task detailed spec (files, interfaces, verified code sketches, gate risks, and CONTROLLER-ADJUDICATED DECISIONS) lives in `.superpowers/sdd/<key>-brief.md` — that brief is the source of truth, this file is the index + shared constraints.

**Goal:** Ship the four top-value Wave 2 items — all "wire code that is defined but dead/unused today" — from the roadmap ([2026-07-02-implementation-roadmap.md](2026-07-02-implementation-roadmap.md)). Grounded against merged-main HEAD `8e2a58b` (post-Wave-1).

**Tasks (value order; mutually independent — any order):**

| Key | Task | Brief | Core change |
|---|---|---|---|
| W2.1 | Admin list API pagination/filter/sort | `.superpowers/sdd/w2.1-admin-pagination-brief.md` | in-memory shim in `grpcadmin` List for users+clients |
| W2.2 | MFA recovery codes + admin reset | `.superpowers/sdd/w2.2-mfa-recovery-brief.md` | `RecoveryMFAProvider` composed via `NewMultiMFAProvider`; `/me/mfa/recovery-codes` + admin reset |
| W2.3 | Built-in SMTP sender + templates | `.superpowers/sdd/w2.3-smtp-sender-brief.md` | new leaf pkg `infrastructure/defaultimpl/emailsmtp`; `smtp:` config |
| W2.4 | Tenant quota enforcement (DCR client-create) | `.superpowers/sdd/w2.4-tenant-quota-brief.md` | retire dead `checkQuotaBeforeCreate` via DCR hook |

Each brief opens with a **CONTROLLER-ADJUDICATED DECISIONS** block that resolves every open question and locks scope (notably: W2.4 = DCR client-create only; W2.3 = async fire-and-forget + net/smtp; W2.2 = memory store only, new provider composed; W2.1 = option-(b) shim). Those decisions override any conflicting grounding text.

## Global Constraints (bind every task)

- File ≤ 500 lines; function ≤ 50 lines (incl. comments/blanks); cyclomatic ≤ 15; **exemption lists frozen — never add one**.
- **Directory fanout ceilings are frozen/shrink-only.** Confirmed at-cap dirs (NO new non-test file): `interfaces/sso` (57), `config/` (26), `infrastructure/defaultimpl` root (26), `infrastructure/defaultimpl/sqlite` (36), `domains/authenticators` (18), `cmd/sso-server` root. Where a new file is unavoidable it goes in a NEW leaf sub-package (W2.3 → `emailsmtp`) or an under-cap dir (`grpcadmin` 8/10 → one new file OK; `defaultmfa` 8/10). Test files (`*_test.go`) are NOT counted.
- Imports point DOWN toward `shared/core` only (`architecture_layer_test.go`).
- No literal leaks: paths/headers/error-codes/event-names as consts in `shared/core/consts*.go` / `platform/audit/auditspi`, re-exported via the established alias files.
- Docs same commit: new `Err*` → `docs/error-codes.md`; API change → `docs/openapi.yaml`; new config key → `docs/config-reference.md`.
- **Anti-enumeration / oracle-leak invariants (AGENTS.md §3) bind W2.2, W2.3, W2.4** — the brief states the exact status codes and uniform-error behavior each must preserve. Credential/token material is never logged.
- Tests use real `Memory*`/sqlite stores and real transports-behind-a-seam — no mocks. Unit tests beside code; cross-server tests in `test/` (`package ssotest`).
- Post-edit after every `.go` change: `go build ./... && go vet ./...` then `go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`. Do NOT run `make ci`.
- Known-environment notes (from Wave 1): remove `docs/skills/**/__pycache__` before running the depth gate; the untracked local `bin/` trips the root-subdir fanout gate on this machine only (leave it — it is the user's runtime env); `test/` under `-race` needs `-timeout 20m`; config-package `-race` has a pre-existing slog data race (verify config changes without `-race`).
- Commits: conventional (`feat(area):`/`fix(area):`/`docs:`), imperative subject, body explains why + notes any deferred scope, trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`, no emojis.

## Sequencing

All four are independent and may execute in any order. Recommended order = value: W2.1 → W2.2 → W2.3 → W2.4 (execute smallest-risk W2.4 first if de-risking is preferred). A tranche-wide whole-branch review + fix wave follows, then finishing-a-development-branch.

## Deferred to follow-up (recorded so they are not lost)

- W2.4: user-create quota (needs `User.TenantID` data-model change), `token_rate` windowed dimension, admin gRPC quota rejection path, admin `SetQuota/GetQuota/GetUsage` REST API.
- W2.3: implicit-TLS port 465; SMS OTP transport.
- W2.2: durable (sqlite/postgres) `RecoveryCodeStore` (dir frozen — needs a package split first); `config.MFAConfig` `recovery` provider kind.
- W2.1: the real >10K-record OOM fix — an optional store extension (`ListPage`) type-asserted at the gRPC layer, mirroring `core.TenantScopedClientStore`.
