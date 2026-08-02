Design doc written to `docs/auto/interfaces-ssoclient-direction2-design.md`. I re-verified every claim against the code before writing, including a few facts that shape the design:

**Verified constraints that drove decisions:**
- `remote` cannot import `rs` (rs imports remote for `JWKSCache` — cycle), so the iss/aud gates are duplicated with comments pinning `rs/claims.go` as the reference, and parity is test-enforced, not shared-code-enforced.
- The current `WithLogoutURL` wire shape (JSON `session_id` + bearer) actually *matches* the server's `POST /logout` handler (`server_logout.go` binds exactly that) — so the fix is a routing split (`SessionID` → `/logout`, `AccessToken` → `/token/revoke` via new `WithRevokeURL`), not a rewrite of the session path.
- The server stamps `aud` as client ID on the login path but RFC 8707 resource indicators on the token path, and `defaultimpl` issuers stamp `aud` only from `Subject.Resources` — so `WithExpectedAud` must be documented as a *claim expectation*, not a client-registry lookup. The example fix mints `aud` via `Resources: []string{appClientID}` (compact-string form, covered by `aud_claim_fuzz_test`).
- Two real callers break at runtime under fail-closed issuer: `cmd/sso-mcp` (nested module, own `go.mod`) and `docs/examples/remote-app`. Both are trivially migrated — sso-mcp already has a `Config.Issuer` field (and a `ResourceURI` field that is the correct aud pin for token-path tokens). Zero non-test callers of `Logout` exist, so the behavior change is safe.

**Doc structure** (`##` per decision): API surface for issuer pinning / audience enforcement / logout contract / error taxonomy with gate ordering (mirrors rs's iss→time→aud and its error priorities), storage model (none — in-memory option fields, no config schema, no server stores), a 10-row failure-mode table, caller migration, and 9 "what could break" risks (runtime break for bare constructors, aud-pin false denials, single-issuer-per-client limit, rs parity drift, budget ceilings, etc.), plus a verification plan.

No code was modified — spec and design only, per the request.
