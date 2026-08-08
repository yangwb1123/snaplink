All three checks completed against the working tree at HEAD `f9ceb251`.

## 1. Corrected OpenAPI sweep — ✅ CONFIRMED (8/8 paths, CIBA included)

Design §2 (C9) + §3.3 lists all eight paths; I verified each against `docs/openapi.yaml` HEAD — every credential path declares a form **and** a JSON requestBody variant (the sweep target):

| Path | form | JSON | Design cite | Verdict |
|---|---|---|---|---|
| `/auth/mfa` | 641 | 644 | :641/644 | exact |
| `/token` | 1100 | 1139 | :1100/1139 | exact |
| `/token/introspect` | 1278 | 1281 | :1278 | exact |
| `/token/revoke` | 1345 | 1348 | :1345 | exact |
| `/par` | 1475 | 1478 | :1475 | exact |
| `/device/code` | 1541 | 1544 | :1541 | exact |
| `/backchannel-authentication` | 1602 | **1605** | :1602/1610 | ✅ JSON variant exists; actual line 1605, design's "~1610" is a 5-line approximation |
| `/device/verify` | 1849 | 1852 | :1849 | form exact; JSON at 1852 (POST only — GET is `text/html`, correctly untouched) |

"Form + JSON" paragraph confirmed at :1061-1066. Note: the requirements doc's R5.5 still lists seven paths (CIBA omitted) — the correction lives in the design where §2 records it; that is the intended correction trail.

## 2. `docs/config-reference.md` — design mandates it; file does **not** yet contain the key (implementation pending)

- Current file: `## Server` table has only `server.http2.enabled`; zero matches for `require_form_content_type` anywhere in the file. No implementation exists in the tree either (`bind_strict.go`, `BindParamsFormOnly`, `WithCredentialFormOnly` all absent; `ServerConfig` at `config/config_server.go:16` confirmed, snake_case yaml tags → `require_form_content_type` fits the convention).
- The deliverable **does** pin the doc with default + migration window: §3.1 (`yaml:"require_form_content_type"`, nil→strict, false→legacy, true→explicit), §3.3 ("`server.require_form_content_type` (default true) is the operator escape hatch… the config key is the documented migration window; rollback is a one-line config flip"), and §3.5 step 7 ("`docs/config-reference.md`: the key (default true, legacy note)"). Requirements R6 makes it a same-change obligation ("registered in the same change").
- Verdict: the design obligation is complete and correctly specified; the file edit lands with implementation in step 7 — absent today only because nothing is implemented yet (per AGENTS.md §1, plans describe intent, not shipped state). Flagging explicitly so the gate isn't misread as a doc gap.

## 3. New Err* / error-code docs — ✅ NONE NEEDED

- All eight sites already collapse bind errors onto pre-existing codes: `core.ErrInvalidRequest` → `400 invalid_request` (`handle_introspect.go:120-123`, `server_token.go:30-33`) and `ErrMFAInvalid` → `400 mfa_invalid` with the verbatim collapse/no-audit envelope (`server_mfa.go:255-258`). The `errFormOnly` sentinel is unexported — handlers never see it, so the wire is byte-identical to today's malformed-body 400s; no new oracle.
- `docs/error-codes.md` already carries the covering rows: `invalid_request` at :81 ("Request body fails to parse, or required field absent") and `mfa_invalid` at :247. AGENTS.md §5.6 requires entries only for *new* `Err*`; there are none (F12's MFA `params` rejection also reuses `mfa_invalid`). The design's step 7 "note" is optional commentary, not a required entry.

**Overall**: the corrected sweep is complete and accurate (one trivial line-number approximation on CIBA), the config-key documentation obligation is fully specified with default and migration window (pending implementation), and the form-only error path introduces no new `Err*` or error-code documentation requirement.
