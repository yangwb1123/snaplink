OK so now I have a very clear picture. Let me summarize my findings:

**Direction 1 - OIDC Conformance**: 
- ✅ VERIFIED: `claims_parameter_supported: true` is hardcoded (line 224)
- ✅ VERIFIED: ClaimsSupported only includes basic OIDC claims (lines 378-381), NOT email/phone/address as report claims
- ✅ VERIFIED: id_token path doesn't project claims - `ProjectIDTokenClaims` function exists but is NEVER CALLED

**Direction 3 - Cross-replica coherence**:
- ❌ WRONG: The report claims JTI replay, refresh family, and session are per-replica
- BUT: Redis implementations exist for ALL THREE:
  - `infrastructure/redis/jti_replay.go` - shared JTI replay
  - `infrastructure/redis/session.go` - shared session manager  
  - `infrastructure/redis/refresh_token.go` - shared refresh token with DeleteFamily
- The ROADMAP.md explicitly states Redis backend is done (Direction ⑤)

**Consent Store**:
- ✅ VERIFIED: Consent store exists in multiple backends (memory, sqlite, redis, postgres)

So the report has at least one MAJOR ERROR - Direction 3 is completely wrong because it ignores the existing Redis implementations.

Let me provide a comprehensive analysis to the user. This is an exceptionally thorough analysis report. I've verified the key claims against the actual codebase and found a **critical error in Direction 3**. Let me present my findings:

---

## Verification Results: Report vs Codebase Reality

### Direction ① OIDC Conformance — ✅ MOSTLY ACCURATE

| Report Claim | Verification | Status |
|---|---|---|
| `claims_parameter_supported: true` hardcoded (line 224) | **Confirmed** at `server_discovery_config.go:224` | ✅ Correct |
| id_token path doesn't project `RequestedClaims` — carries raw JSON as `_claims_` (line 77) | **Confirmed**: `issue_payload.go:77` does `payload.RequestedClaims = append(json.RawMessage(nil), subject.RequestedClaims...)` — raw passthrough, no projection | ✅ Correct |
| userinfo path **can** project (line 159) | **Confirmed**: `oidcsupport/userinfo.go:159` → `projectRequestedClaims()` calls `core.ParseRequestedClaims` and filters claims | ✅ Correct |
| `ProjectIDTokenClaims` exists but unused | **Verified**: function exists at `protocols/oidc/oidcsupport/idtoken_claims.go:17` but is **never called anywhere in the codebase** (zero references outside its own file) | ✅ Correct — dead code |
| `ClaimsSupported` declares `email`, `phone`, `address` | **Refuted**: `server_discovery_config.go:378-381` only declares `sub, iss, aud, exp, iat, nbf, scope, nonce, auth_time, amr, acr, azp` — no email/phone/address | ❌ Wrong claim |

**Verdict**: Direction ①'s core finding is real — the `ProjectIDTokenClaims` function exists but is dead code, and the id_token path does not project claims per OIDC §5.5. However, the `ClaimsSupported` finding (#3) is wrong — the discovery document does NOT declare email/phone/address.

---

### Direction ③ Cross-Replica Coherence — ❌ FUNDAMENTALLY WRONG

The report claims these are **per-replica, non-shared** and calls this "the only real security gap." This is **factually incorrect** — Redis shared backends already exist for all three:

| Report Claim | Actual Codebase | Status |
|---|---|---|
| JTI replay: "每个副本独立（memory / SQLite / Redis）" | `infrastructure/redis/jti_replay.go` — `redis.JTIReplayStore` uses `SetNX` (atomic test-and-set) on shared Redis, `sso:jti:<jti>` key with TTL. Wired via `WithJTIReplayStore()` | ❌ Already shared |
| Refresh family: "每个副本独立 `DeleteFamily`" | `infrastructure/redis/refresh_token.go` — `redis.RefreshTokenStore.DeleteFamily()` uses shared Redis `SMEMBERS` + `DEL` on `sso:rt:family:<fid>`. Cross-replica atomic. | ❌ Already shared |
| Session state: "30s TTL + 尽力而为总线" | `infrastructure/redis/session.go` — `redis.SessionManager` stores sessions in shared Redis hash (`sso:session:<id>`), with Lua atomic refresh script. Wired via `WithSessionManager()`. | ❌ Already shared |

The ROADMAP.md itself confirms this was delivered:
> **方向⑤ Redis 后端**：`redis/` 子模块覆盖全 ephemeral 热路径（session/refresh+family/authcode/par/jti/ratelimit/device/mfa/ciba）。

**Verdict**: Direction ③ as described does not exist. The Redis backends provide exactly the cross-replica coherence the report proposes building. The report appears to have been written before the Redis direction was completed, or the analysis missed the `infrastructure/redis/` package entirely.

The only remaining gap is **operator guidance** — documenting that production multi-replica deployments MUST use Redis backends (not memory/sqlite) for JTI/session/refresh stores. That's a docs/config issue, not a code gap.

---

### Direction ② Compliance Reporting — ✅ ACCURATE GAP

Verified that:
- `ConsentStore` exists (memory/sqlite/redis/postgres) — so the raw data is there
- `audit.Query` does have tenant-scoped queries, but there are no pre-built compliance report endpoints
- No `/api/v1/admin/reports/*` endpoints exist

This direction's analysis is sound — the building blocks exist, but the packaged compliance reports do not.

---

### Directions ④⑤ — Plausible but not deeply verified

---

## Corrected Priority Matrix

| Priority | Direction | Original Assessment | Corrected Assessment |
|---|---|---|---|
| **P0** | ① OIDC claim projection | S effort | **Still S** — wire `ProjectIDTokenClaims` into the id_token issuance path. Dead code exists, just needs to be called. |
| **P1** | ③ Cross-replica coherence | M effort, security gap | **Does not exist** — Redis backends already solve this. Downgrade to **docs/config guidance** (S, trivial). |
| **P1** | ② Compliance reporting | L effort | **Still L** — genuine gap, real value. |
| **P2** | ⑤ SLO framework | L effort | Plausible, not disputed. |
| **P3** | ④ Change management | XL effort | Plausible, not disputed. |

---

## Recommended Immediate Actions

**Phase 1 (this sprint)**: Fix Direction ① — wire `oidcsupport.ProjectIDTokenClaims()` into the id_token build path in `infrastructure/defaultimpl/`. The function already exists and is tested-ready; it just needs to be called before building the ID token claim set. This is a ~20-line change.

**Phase 2**: Skip Direction ③ (already solved) and move to Direction ② compliance reports, or Direction ⑤ SLO framework.

Would you like me to proceed with implementing the id_token claim projection fix (Direction ①)?
