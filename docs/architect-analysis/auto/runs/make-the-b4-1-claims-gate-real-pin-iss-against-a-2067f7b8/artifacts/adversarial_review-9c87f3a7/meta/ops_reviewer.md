All four areas are assessed, verified against the worktree, and hardened into the design doc. Summary:

## (1) Crash window mint → revoke — TTL bounds it; decision: documented residual, no defer

**Verified.** `defaultTokenTTL` = 1h (`infrastructure/defaultimpl/issue_payload.go:19`), per-client override via `access_token_ttl` honored (`effectiveAccessTTL`, `ed25519_issue.go:27`; `token_client_credentials.go:51-57` sets `Subject.TTL`), `Validate` rejects after `exp`. The token exists only in sweep process memory; the design already minimizes the window (rows 2–4 are in-memory claim comparisons — no I/O between mint and revoke).

**Decision: documented residual, defer-revoke rejected.** (a) `cmd/sso-ctl/main.go:75` does `os.Exit(run(args))` — `CheckRun`'s defers run on every normal return anyway, so a defer adds only panic-unwinding coverage, never SIGKILL/OOM/CI-kill (the dominant kill modes). (b) The identical window exists **today** for mint-1's token — R2 adds a second instance of a pre-existing, bounded residual. (c) On Host-derived deployments the phantom-iss token is strictly *less* useful downstream (B4-1-configured validators reject it). Strengthenings recorded: implement the revoke immediately after the mint response; runbook: short `access_token_ttl` on the sweep client.

## (2) Phantom-Host audit records — phantom base never lands in audit; one real divergence

The audit `Event` carries **no** Host/issuer field (`platform/audit/auditspi/event.go`), so `http://sweep-host-variance.invalid` never appears in records. The real effects, all verified:

- **Tenant divergence**: on tenant-wired deployments the tenant middleware silently no-ops on the phantom host (`domains/tenant/middleware.go` — `ErrDomainNotFound` non-fatal; `tenant.ClientOK` passes with no tenant context), so mint-2's `token_issued` has **empty `TenantID`** while mint-1's carries the client's tenant — the token's own client-bound `tenant_id` claim disagrees with audit attribution for exactly one record.
- **Metering**: `domains/metering` counts `token_issued` per `tenant_id` → client's tenant view undercounts by 1/run; empty-tenant bucket +1. **SOC2 report cardinality unaffected** (fixed enum buckets; actors unchanged).
- **Anomaly detection**: `domains/tokenanomaly` keys per thumbprint (SHA-256 of jti) — fresh jti → multi_geo/velocity never fire; rate_spike is per-client with a 20/min floor → constant +1 never spikes. The preflight's 401 emits **no** audit record at all (token client-auth failures are unrecorded by design — `server_token_clientauth.go` has no audit calls).

## (3) Signing usage and RPS — real, bounded, and NOT rate-limit-exempt

- `sso_signing_key_usage_total{alg="EdDSA",kid}` +1 per run (same kid); a KMS-backed signer pays one real `Sign` op.
- +3 POSTs/run (preflight, variance mint, variance revoke); today's run is 5.
- **The "probes outside rate limiting" carve-out (AGENTS.md) covers only /metrics /livez /readyz** (`options_httpstack.go` — the middleware sits between /metrics and the metrics recorder). The sweep is ordinary client traffic: global IP-keyed bucket **+2** (the preflight's 401 still consumes it — middleware runs pre-auth), per-grant-type `client_credentials` bucket **+1** (only the credentialed mint reaches `checkGrantRateLimit` post-auth; the dummy-secret preflight dies at `authenticateTokenClient` first). A 429 on either leg is red — covered by the F3 rejection shapes.

## (4) Runbook verification — feasible; concrete safe step now written into §5 step 4

Two credential-free/dummy-secret steps (from the sweep's network vantage; SNI stays the canonical host, so TLS is unaffected):

1. **Identity check**: `curl -sS -H 'Host: sweep-host-variance.invalid' https://<canonical>/.well-known/openid-configuration` — a 200 discovery doc proves an OIDC-shaped server answers unknown Hosts; anything else → do NOT enable. On a server *without* a configured issuer, the doc's `issuer` field is the pass-through oracle (phantom host ⇒ probe works; upstream host ⇒ F3b rewrite).
2. **Preflight rehearsal** (dummy secret only): expect `401 {"error":"invalid_client"}` from the token endpoint.

**Trust-zone alternative is coherent with the preflight**: direct-to-server makes F3a/F3b/F3c moot — the preflight still runs and passes (real server answers 401; no middlebox to abort on), and the credentialed mint can't be misrouted. Preconditions: server-side `WithIssuer` (already required by §4 F3b) so the minted `iss` equals the external canonical, and the honest caveat that the trust zone validates the server only — the production edge path is what B4-1 guards.

## Doc edits applied (`docs/architect-analysis/cmd-sso-ctl-b4-1-claims-gate-design.md`)

- §1 C3: revoke is best-effort against crash; residual cross-referenced to F5.
- §2.5 row 0: cost line sharpened (global slot only; grant bucket untouched).
- §4 F5: rewritten with the crash-window decision (TTL bound, defer rejected, revoke-immediately note, sweep-client TTL note).
- §4: new F8 row + **§4.1 Operational footprint table** (audit/metering/anomaly/signing/RPS-rate-limit rows).
- §5 step 4: the two-step verification procedure + trust-zone coherence paragraph.

No production code touched — no `.go` edits, so no build gates required; the design's own verification plan is unchanged.
