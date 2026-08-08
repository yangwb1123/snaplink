Verification complete. Report written to `docs/architect-analysis/auto/runs/enforce-form-urlencoded-credential-strict-mode-0a8df02f/artifacts/verify-amendments/verification.md`.

## End-state verification verdict: **PASS** — implementation-ready, no open questions

The amended design (251 lines; the amendment pass landed while I was mid-verification, so I re-ran every check against the final text) was verified from scratch against the tree — no claim taken on trust.

**Engineering-gate re-check (all measured live):**
- **`sso_protocol.go`** — exactly 500 lines (newline-terminated; `oauth21Strict bool` at :184). The amended §2.4/§4.4 correctly pins the load-bearing fix: combine as `oauth21Strict, strictCredentialContentType bool` on one line (net +0; 501 fails `TestMaintainability_FileSizeBudget`). S-F1 applied.
- **`options_security.go` / options.go pin** — options_security.go exactly 500 (with `WithJTIReplayFailClosed` at :39); option pinned to options.go next to `WithOAuth21StrictMode` (:194), 490+8=498; misleading parenthetical deleted. S-F2 applied.
- **`protocols/oauth` fan-out** — 12/12 non-test files (frozen ceiling, `directory_fanout_test.go:59-61`); helper correctly placed in `aliases.go` (125→~150) with the alias next to `BindParams` at :97.
- **Deps growth** — `IntrospectDeps` (:29)/`RevokeDeps` (:16)/`PARDeps` (:18) gain one accessor; `*sso.Server` is the sole production implementer (`handlers.go:35,99` pass `s` directly); the three test structs (:28/:17/:19) are the only other in-repo implementers; `RoutesDeps` (grant_handler.go:36-42) inherits transparently. Compile impact exactly as scoped.
- All other line budgets (bind.go 185, build_app_oidc.go 492, server_jar.go 438, server_token.go 496, accessors.go 495) and fan-out ceilings (60/60, 26/26, 24/24, oauthwire 6) measure out.

**Amendment application** — all 17 findings (P-F1..P-extra, T-A1..T-B2, S-F1..S-F6) are **applied and independently re-verified**: RFC 9126 §2.1 fix (design + requirements.md:62), postRevoke OpenAPI 400 (verified only 200/401 today while the other three ops document 400), Security-table row with "Maps to" convention (verified at config-reference.md:69-77), `nbf` in the exclusion set (`Nbf==Iat==now`, issue_payload.go:32-33), `"{}\n"` revoke body (`json.Encoder.Encode`, router.go:141-146), 28-byte goldens, discriminating payload pins, header subset, pre-built secrets + round-robin (AC-5), RAR RawMessage drop caveat (`rar.go:154-156` returns `(nil,nil)`), AC-6 bypass-edge matrix, trace-context rule (`WithTracingMiddleware` opt-in, not default). The residual-contradiction check holds.

**AC-1..AC-6** are concretely assertable from the amended text alone — every criterion now carries its endpoints, payloads, byte-exact goldens, exclusion sets, construction pins, and harness specification.

**Reported separately (pre-existing, unrelated):** the dirty tree fails FileSizeBudget (`ed25519_jwt_issuer.go` 539 lines) and FunctionLength/Complexity/Directory gates on `cmd/sso-ctl` files outside this design's footprint; `go build`/`go vet` are clean. Not introduced by, and not blocking, this design.
