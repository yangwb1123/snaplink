# Gatekeeper report — direction 3, cross-check of review findings vs design + implementation plan

I re-verified the plan's load-bearing claims against the tree at HEAD `ff690260` (source reads + a fresh goccy probe), then traced every review finding to a plan disposition.

## Verified by inspection (all hold)

- **Budgets**: `server_token.go` exactly 500, `server_helpers.go` 493, `server_oauth.go` 481, `server_login.go` 499, `token_refresh.go` 430, `token_exchange_stages.go` 495; scope-combo call at `server_token.go:168`; `createSession(..., tenantID, ...)` at `server_logout.go:345`, seam call at `:357` without tenant; `sessionPolicyCapExceeded(ctx, userID, clientID)` at `server_oauth.go:162`.
- **Census**: `core.Subject{`/aliased `Subject{` mints confirmed at `handle_silent_renewal.go:210`, `agentidentity/grant.go:185`, `accessors_feature_gates.go:257` (`issuerForClient(nil)` — structurally unstampable, confirmed), `server_login.go:112`, `server_native_sso.go:190`, plus the codegen template — the alias at `aliases.go:132` explains why both reviews' counts of 12 were each incomplete. **13 + 1 is ground truth.**
- **Wiring**: zero hits for `WithTenantUserStore` / `WithAgentDelegationGrant` / `WithSAML2BearerGrant` in `cmd/` — SRE F1 and the checklist's reachability corrections hold; `decodeStrictWithFallback` at `config/source.go:260`.
- **SRE F2 fix re-probed**: the plan's type-alias `Policy.UnmarshalYAML` + `DisallowUnknownField` errors on a misspelled item field under **both** the strict pass and the lenient fallback re-decode (my probe on goccy v1.19.2: all 3 cases pass) — the inline-path hazard the design's 3c claimed but couldn't deliver is genuinely closed at decode time.

## Finding dispositions

**Resolved with concrete plan items**: Security F1 (13+1 census, per-site stamps + `expires_in == 300` tests), F2 (introspection seam named, liveness matrix §9, no-op pins), F3 (bounded counter + `ObserveTokenPolicyRoleResolutionError`), F4 (`tenant_id` `Validate` rules), F5 (481→495 exact); SRE F1 (boot warning + config-reference; sqlite builder deferred with zero-new-storage reason, recorded follow-up), F2 (§4.2 — stronger than the checklist's accept-warn adjudication), F3 (binary-first ordering, deployment.md, release notes), F4 (counter), F5 (route_contract.py schema assertion), F6 (federated matrix row); QA H1/H2, M1–M5, L1; Protocol F1 (stamp alternative, which the review itself sanctioned, + static tripwire), F2, F4 (cite corrected to `:6868-6884`), F6.

**Dismissed with reasons**: SRE F7 (495, not 497 — both signatures are 103/129 chars, single-line, gofmt doesn't wrap; verified), SRE F8 (no SLO framework; measurement noted), QA L2 (6th non-test file; verified 5 exist), Protocol F1's structural-wrapper preference (superseded by the review-sanctioned stamp alternative + tripwire).

**Neither resolved nor dismissed — three residual gaps (non-blocking, must be folded into the planned work)**:

1. **Protocol F3 (Medium)** — the ID-token/access-token exp asymmetry: the plan's claim-surface pin covers only "no `tenant_id` claim"; the "paired ID-token TTL unchanged" assertion and the config-reference sentence are absent from both the plan and the checklist. Same files the plan already touches.
2. **Protocol F5 (Info)** — temp-token governance-invisibility declaration sentence absent (the break-glass half is covered by the EXEMPT decision + pin).
3. **Checklist G11's E2E gate** (`go test ./test/ -run TestE2E -v`) is not carried into the plan's §11 gate sequence; the checklist's H2/H3 arithmetic (497/~491) also still diverges from the plan's simulated 495/495 — implementers must treat the plan as authoritative.

No High finding and no enforcement-affecting finding is unaddressed; the remaining items are documentation/pin/gate-list completeness in files the plan already edits.

VERDICT: PASS
