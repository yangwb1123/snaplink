All key facts independently verified. Here is my gatekeeper ruling.

## Cross-check: review findings vs. the design

**Resolved in the design (verified in text + tree):**
- **Spec corrections 1–3** — ceiling-aware placement (8 of 13 packages at cap, `interfaces/admin` has no exemption entry — confirmed absent from `directory_fanout_test.go:51-61`), the anchored acceptance grep (I re-ran: 234 anchored vs 254 literal — confirmed), and `deps.go` (177 lines) as the only admin placement option. All three fixes are real and inline.
- **D3 gate-closure rule** — "pass method values, never `.Load()`" is verified correct and load-bearing (`GatedRouter.live` consulted per request at `router.go:267`; 7 hot-reload tests pin it).
- **Placement table, 174-delegate census, ratchet mechanics** — independently reproduced by all four reviewers; I confirm the map values and gate semantics.
- **Protocol F1–F6** — the protocol review itself certifies them non-blocking for the refactor; the design's wire-invisible claim holds (paths are `core.Path*` re-exports).

**NOT resolved, and NOT dismissed with reasons (the design predates all reviews, 13:31 vs 13:38–13:50, and has no revision):**

| Sev | Finding | Status in design |
|---|---|---|
| **Critical** | Decision 3's `Mount()` sketch passes `nil` for 10 of 13 mounts (design:248–259) while Decision 1 declares nil a panic — literal implementation panics at boot | Unaddressed; the "// or the area's gate closure" comment is a hedge, not a decision |
| **Critical** | Same sketch silently drops 3 live gates — verified: `oidcGateOn` gates `/userinfo`/`/end_session`/`/check_session_iframe` (`server_userinfo.go:33`), `cibaGateOn` gates `/backchannel-authentication` (`server_routes.go:239`), `federationGateOn` gates the federation surface (`server_federation.go:197`) | Absent from FM1–FM7 and the risk register; Decision 4 names only 4 of 7 atomics (omits exactly the dropped `oidcLive`/`cibaLive`/`federationLive`) |
| **High** | `check-routes` goes vacuous on the move — verified `ROUTE_DIR = interfaces/sso` + receiver whitelist `{s.router, api, gr, ssf, selfServiceGR}` (`route_contract.py:18,21`), while the design's own signature uses receiver `r`; one-directional (zero discovered = PASS) | Acceptance demands it stay "unchanged" while FM4/FM5/FM7 and risk 7 lean on it — self-contradictory, unaddressed |
| **High** | FM4 misdescribes the router — verified append-only, first-match-wins (`router.go:223-267`); no duplicate detection exists anywhere; "exactly one registration" is an uncommitted aspiration | FM4 text wrong, mitigation inert |
| **High** | Sketch omits `mountAdminTokenExchangeChainRoutes` — documented admin route silently disappears; cannot fold into `MountAdminSurface` (package cycle) | Unaddressed |
| Medium | ≤52 target not derived (only 1 of ≥8 deletions enumerated); FM6 cites a phantom `TestArchitecture_` middleware-order test (verified absent); FM5/FM7 overclaim (no test boots every config; no store-unwired route-set test); `sdk-surface` never scans `aliases.go`; "419 re-exports" not reproducible | All unaddressed |
| Low | Stale numbers in the design's own text: "40 mounts across 16 files" (→14), "11 sub-mounts" (→12), adminuser bodies in "users.go 464 lines" (→ `internal/adminuser/handlers.go` 239), "off by 20–29" (→20) | Still present in design:16, :150, :202 |
| Pre-existing | 4 maintainability + 1 vet + 5 `interfaces/sso` failures in the worktree (pi-batch stage work, none in target packages) | Correctly reported separately per AGENTS.md §5.7 — not the design's fault, but the design's acceptance ("gates green") cannot be demonstrated until baselined (QA F6) |

**Consensus:** all four reviews converge — the census, placement table, and ratchet architecture are sound and gate-consistent, but the design is not implementable as written: the `Mount()` sketch contradicts its own Decision 1, drops three hot-reload gates (an AGENTS.md §3 invariant break), and relies on a regression net that stops measuring exactly when the code moves. None of these are resolved or dismissed in the design text; they are open.

VERDICT: FAIL - the design's own Mount() sketch passes nil for 10 of 13 mounts while Decision 1 declares nil a panic (boot-time panic or contradiction, unresolved); the same sketch drops three live hot-reload gates (oidcGateOn, cibaGateOn, federationGateOn — fail-open wire change, absent from FM1-FM7 and the risk register, Decision 4 omits 3 of 7 atomics); check-routes goes vacuous when routes move (ROUTE_DIR/receiver whitelist hardcoded to interfaces/sso, one-directional) while the acceptance demands it stay "unchanged"; FM4 misdescribes the router (no duplicate detection exists); the sketch omits mountAdminTokenExchangeChainRoutes (documented route disappears); plus unaddressed Mediums (≤52 not derived, phantom FM6 test, overclaimed FM5/FM7 mitigations) and stale numbers (16→14 files, 11→12 sub-mounts, adminuser bodies in internal/adminuser/handlers.go). All four reviews converge on these; the design has not been revised since they were written.
