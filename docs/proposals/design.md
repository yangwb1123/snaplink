Design doc complete: `docs/auto/interfaces-grpcserver-transport-governance-design.md`

## What was produced

A design doc decomposing the spec's 3 improvements into 4 decisions, each with API surface, storage model, failure modes, and "what could break":

**D1 — One shared two-phase governance gate.** Rather than the spec's minimal call-site (gate after `authorizeGRPC`), the design splits into `preAuthGRPC` (IP policy → rate limit → confirm — no claims needed) and `postAuthGRPC` (idle → quota), which preserves the documented HTTP chain order **exactly** and keeps the "disallowed network never reaches auth machinery" property on both transports. HTTP checks become pure predicates with thin wrappers (byte-identical HTTP). Error mapping: `ResourceExhausted`/`PermissionDenied`/`FailedPrecondition`/`Unauthenticated` with constant strings; no `Retry-After` on gRPC (trailers rejected as oracle).

**D2 — Destructive confirmation via canonical RPC→(method, path) map.** The proto `google.api.http` annotations are the authoritative mapping (~50 entries), mirrored into a static table; a conformance test re-derives the table from `proto/admin/v1/*.proto` so drift is a test failure, not a silent guard gap. `grpc-metadata-x-confirm` → server key `x-confirm` (gRPC lower-cases).

**D3 — Idle timeout + Touch on gRPC**, fail-open on store error (mirroring HTTP), touch at stream open+close (bounded), with the mid-stream-expiry limitation explicitly documented.

**D4 — TLS never silently plaintext** (`admin.grpc_tls: required|ephemeral|plaintext`, default `required` = startup refusal) plus a fail-closed arming guard (`GRPCGovernanceArmed()` set only by the gated interceptor construction path) that converts future wiring drift into a startup error naming the control.

## Critical constraint discovered

`interfaces/admin` is at its 10-file fan-out ceiling and both `middleware.go` (492) and `governance.go` (483) are within 17 lines of the 500-line cap. The design's load-bearing rebalance: move the ~200-line change-approval HTTP handler block (`governance.go:30-228`) into `deps.go` (177 → ~375), freeing space for the ~155–190 lines of gate code — the only relocation that fits the frozen budgets.

All cited lines were re-verified (`authorizeGRPC` :220, HTTP chain :317-345, `checkWriteQuota` :408, TLS condition `main_servers.go:172`, `-grpc-listen` default `main_wiring.go:59`), and the session-TTL detail was corrected to the actual `WithAdminSessionTTL` sso.Option rather than a YAML key.
