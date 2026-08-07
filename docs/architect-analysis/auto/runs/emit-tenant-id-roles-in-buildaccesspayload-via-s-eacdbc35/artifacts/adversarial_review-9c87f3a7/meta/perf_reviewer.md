Analysis complete. Deliverable: `docs/architect-analysis/auto/runs/emit-tenant-id-roles-in-buildaccesspayload-via-s-eacdbc35/artifacts/design-a77de8a6/task-2-token-size-risk.md` (no `.go` edits, so no repo gates triggered; measurements were run against the real issuers from a throwaway module in `/tmp`).

## Quantified risk

Measured against the real shared `buildAccessPayload` path (Ed25519/ECDSA/RSA) with a realistic subject: base tokens are 677 B (Ed25519/P-256) and 933 B (RSA). The projected `roles` claim:

| Shape | Per-role cost (JWS) | Break points |
|---|---|---|
| Full `Role` objects (R2 as designed: code+name+description+permissions[]) | **≈ 340 B/role** (256.5 B JSON) | OpenResty edge 8 KB field default at **≈22 roles**; 64 KiB house cap at ≈190; Envoy 60 KB at ≈178 |
| Codes-only array | **≈ 25 B/role** (19.2 B JSON) | same edge budget at ≈300 roles; 64 KiB at ≈2,600 |

So at 100 roles, the R2 shape yields a 34.5 KB token — 51× the 677 B baseline; at 500 roles, 172 KB. **The SSO server is never the first to fail** (Go `MaxHeaderBytes` 1 MB, `security.max_token_bytes` opt-in default unbounded, no mint-side cap) — the breakage surfaces as HTTP 400/414 at the OpenResty edge and silent drops at resource servers, while introspection echoes the uncapped set into mesh caches. The `X-Auth-Roles` mesh header (`mesh_authz.go:423`) is a pre-existing sibling exposure. Inputs are provably unbounded: `AssignRoles`/`AddRole` have no count or length caps in `memory.go` or the SQLite backend.

## Proposed policy (bounds, caps, omission — never truncation)

- **P1 — codes-only claim**, sorted (≈13× smaller; permission detail stays in `/roles/me` + policy bundle; fixes the stale-policy copy problem too)
- **P2 — count cap with whole-claim omission**, default 128, `security.max_roles_in_token` → `WithMaxRolesInToken(n)` mirroring the `WithMaxScopeCount` house pattern → worst case ≈3.9 KB, 2× under the tightest edge default; overflow omitted in sorted order, never truncated mid-code
- **P3 — mint-side byte backstop** (16 KiB payload JSON → omit claim entirely) for pathological single-role bloat
- **P4–P6 — single choke point** in `permissions.RolesForSubject` (all 9 user-bound sites and 3 issuers inherit it; client_credentials excluded), introspection echoes only what the token carries, fail-open outage stays observable via audit + counter
- **P7–P8 — same cap on the mesh header; contract docs** (openapi.yaml/config-reference/feature matrix; log/metric only, no new error code — the token stays valid)

Plus six new acceptance tests (A-new-1…6) mapped to the design's existing test homes. Key finding for the design: the risk is driven by **wire shape, not role count** — the R2 "element-for-element equality" objective survives as element-wise code equality at 1/13th the size.
