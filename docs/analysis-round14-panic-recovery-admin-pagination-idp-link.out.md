Based on my codebase investigation, here's the validation of each direction:

## Validation Results

| # | Direction | Verdict | Evidence |
|---|-----------|---------|----------|
| 1 | Panic Recovery | ⚠️ **Partial** | Code exists (`middleware.Recover()`, `WithPanicRecovery`), but `panicRecovery` bool defaults to `false` and `cmd/sso-server/` never calls `WithPanicRecovery(true)`. Comment says "Enabled by default" — **gap is that it's not wired ON in the binary**. |
| 2 | Account Linking | ✅ **Confirmed missing** | Zero matches for `IdentityLink*`, `AccountLink*` across entire codebase. No store SPI, no endpoints. |
| 3 | Admin Pagination | ✅ **Confirmed missing** | `ListClientsRequest {}` is empty in `proto/admin/v1/clients.proto`. Same for users, tokens, tenants, permissions, releases, snapshots — zero pagination/filter/sort fields. |
| 4 | gRPC Server Config | ❌ **False positive** | Already fully implemented in `cmd/sso-server/main_servers.go:128-172` with `MaxRecvMsgSize(16MB)`, `KeepaliveParams`, `KeepaliveEnforcementPolicy`, `ConnectionTimeout(5s)`, `MaxConcurrentStreams(100)`, `InitialWindowSize(256KB)`, `InitialConnWindowSize(512KB)`. |
| 5 | Authorization Timeout | ⚠️ **Partial** | `WithAuthorizeRequestTimeout()` option + `authzRequestTimeout` field exist, and `sso_selfservice.go` documents the mechanism. But defaults to `0` (disabled) and `cmd/sso-server/` never sets a default. |

---

## Corrected Priority

| # | Direction | Real Gap | Impact | Work | ROI |
|---|-----------|----------|--------|------|-----|
| **1** | **Enable Panic Recovery by default** | `panicRecovery` bool defaults `false`; `cmd/` doesn't opt in. Comment says "Enabled by default" — code disagrees. | **High** (single handler panic kills process) | **XS** (~2 lines: set default `true` in `sso_newserver.go` or call `WithPanicRecovery(true)` in `cmd/`) | 🏆 Best ROI |
| **2** | Admin API pagination/sort/filter | `ListClientsRequest {}` empty — 10K clients = OOM | **High** (>10K deployments broken) | **L** (proto + storage + gRPC + UI) | High |
| **3** | Cross-IdP Account Linking | No `IdentityLinkStore`, no endpoints, no duplicate detection | **High** (top user complaint) | **L** (SPI + store + 3 endpoints + login flow) | High |
| **4** | gRPC production config | ~~Missing~~ Already done | ~~Medium~~ N/A | ~~S~~ N/A | ~~Skip~~ |
| **5** | Enable Authorization Timeout by default | `authzRequestTimeout` defaults `0`; `cmd/` doesn't set it. Mechanism exists but is inert. | **Medium** (hung IdP = hung goroutine) | **XS** (~2 lines: set default e.g. 5min in config) | Good |

---

## Recommended Actions (by ROI)

### 🏆 Action 1: Enable Panic Recovery by default (XS — 2 lines)

In `interfaces/sso/sso_newserver.go:28`, after `s := &Server{}`, add `s.panicRecovery = true`. This makes the comment accurate and prevents any handler panic from crashing the process.

### Action 2: Enable Authorization Timeout by default (XS — ~5 lines)

In `cmd/sso-server/build_app_*.go` or `config/config.go`, add a default `authorize_request_timeout: 5m` so the existing `WithAuthorizeRequestTimeout` mechanism is active. Alternatively, change the default in `sso_newserver.go` to `s.authzRequestTimeout = 5 * time.Minute`.

### Action 3: Admin API Pagination (L — but P0 for production >10K)

This is a real gap. Every `List*Request` message in `proto/admin/v1/*.proto` needs `page_size`, `page_token`, `filter`, `order_by` fields. Backend stores need cursor-based pagination. The gRPC gateway + admin UI need updating.

### Action 4: Cross-IdP Account Linking (L — major feature)

Requires: `IdentityLinkStore` SPI in `shared/core/`, memory + sqlite implementations, `POST /me/identities/link`, `POST /me/identities/unlink`, `GET /me/identities`, login-time duplicate detection (match on `email` claim → prompt to link).

---

Would you like me to implement **Action 1 + Action 2** (the XS fixes) now? Or would you prefer to tackle the larger pagination or account linking work?
