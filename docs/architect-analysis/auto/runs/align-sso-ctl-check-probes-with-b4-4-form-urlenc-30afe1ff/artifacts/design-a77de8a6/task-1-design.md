Design complete: `docs/architect-analysis/cmd-sso-ctl-b4-4-check-probes-form-design.md` (330 lines).

## Verification verdict

**Every citation in the evidence was independently re-checked against HEAD — all confirmed.** No material defects found; two nuances recorded (D1, D2).

| Evidence claim | Verdict |
|---|---|
| `Do` JSON-encodes all bodies (apiclient.go:98-123); no form transport exists | ✅ |
| mint :59-72 / revoke :244-261 / T-8d :286-336 / T-9 :338-362 JSON sends; T-8e rejection :96-99 | ✅ exact |
| `oauthwire/bind.go:28-46` — only exact form CT takes form branch; `default:` → JSON | ✅ exact |
| `handleToken` bind-fail → `400 invalid_request` (server_token.go:31-34) | ✅ |
| Byte-identical `{"error":"invalid_request"}\n` absent tracing: `errorBody`→`ErrorBodyWithTrace` omits empty `trace_id`; Tracing opt-in (`requestIDMW`) | ✅ |
| T-8b is the only trace-capable assertion path (`invalid_scope`/`invalid_client` use plain `core.ErrorBody`) | ✅ |
| Strict-mode server contract pins wrong/absent CT → 400 invalid_request (run `enforce-form-urlencoded-credential-strict-mode-0a8df02f` R3/R5/AC-1) | ✅ |
| Stub `handleIntrospect` JSON-only `"client_id"` discriminator (wire-coupled); `handleToken` `sweep-probe-` survives | ✅ |
| `goldenGreenStdout` :32; `TestSweep_GreenPath`/`TestStdoutDeterministic` compare to it | ✅ |
| sweep.go T-2 nil-body rows wire-neutral; deferred note at auto/…requirements.md:490 | ✅ |
| Budgets: 16-subdir ceiling, 4 non-test files in apiclient, token.go 413 lines | ✅ |
| `TestSweep_ContentTypeRowFailsToday` doesn't exist — new test (spec's finding-3 phrasing is forward-looking, consistent with its §8) | ✅ |

## Design highlights

- **API change**: one additive method `Client.PostForm(path, url.Values)` (REQ-1); `Do`/admin JSON surface byte-unchanged. Five probe call sites switch to the form wire; `runT8b` lives in a new `token_contenttype.go` with a canonical re-encode byte check (`{"error":"invalid_request"}\n` modulo exactly one top-level string `trace_id`), bare bearer-less client, both legs (text/plain + absent CT) carrying JSON credential bodies.
- **Compatibility**: RFC 6749/7009/7662 form wire; all byte-identical contracts preserved; no OpenAPI/error-code/config changes; no gate crossings.
- **Failure modes**: 11 documented (FM-1 unhardened-server detection is the point; FM-3 trace_id tolerance; FM-7 redirect pin; FM-9/FM-10 harness misrouting).
- **Migration**: sweep change lands alone (red-today by design, pinned by `TestSweep_ContentTypeRowFailsToday`); server strict-mode direction flips it green; rollout ships both together (stale toolbelt fails loudly — documented, not papered over); rollback is a 6-line revert.
- **Acceptance mapping**: 19-table mapping the supplied T-8a–T-8e criteria to 8 new named tests plus 20+ existing tests that must stay green, with the exact verification commands.
