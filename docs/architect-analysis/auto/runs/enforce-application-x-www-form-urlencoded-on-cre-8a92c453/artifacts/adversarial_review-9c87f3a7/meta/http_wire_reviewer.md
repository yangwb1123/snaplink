Validation complete. All five semantic areas were tested against real Go 1.26.5 net/http (raw TCP into a live httptest server + `http.Client` + `ParseForm` probes), and the case-table gaps were closed in the design.

## Empirical results (all confirmed against real behavior)

| Semantic | Measured reality |
|---|---|
| Duplicate CT headers | `Header.Get` returns the **first** value only; duplicate lines stay separate slice values — json-then-form rejects, form-then-json binds (first wins, both raw-TCP and client-side) |
| Comma-joined CT | Never split — `application/json, application/x-www-form-urlencoded` is one value, rejects in **both** orders |
| Empty CT value | `Content-Type:` (raw line) and `Header.Set("","")` (client sends a *present* empty line) both → `Get`=`""` → rejects ≡ missing; param-only `; charset=UTF-8` normalizes to `""` → rejects |
| normalizedMediaType | Transport trims leading/trailing OWS and canonicalizes the key but **preserves value case** — normalize's `TrimSpace` is load-bearing at unit level (no wire), belt-and-suspenders at e2e; `Application/X-WWW-Form-Urlencoded`, space-before-`;`, quoted `; boundary="a;b"` all bind; malformed param `; charset="unterminated` → `mime: invalid media parameter` from `ParseForm` (400, not sentinel) |
| ParseForm + query | `r.PostForm` is **body-only** (`Form` has query+body) — URL query params never bind; legacy JSON path never consults the query at all |
| Malformed percent-encoding | `%zz`/`%`/`%2`/`%2G` → `invalid URL escape` error, no partial bind; `+`→space; `%00`→NUL without error; **malformed query `?x=%zz` rejects a valid form body** (same as today's form branch) |
| Chunked bodies | Transparent — server de-chunks before `r.Body`; `ParseForm` binds chunked form bodies (with/without charset); invisible at unit level, so the pin is e2e-only |

## Case-table verdict: gaps existed, now closed

Cases 4-8/20 covered only canonical shapes (charset params, absent CT, three unexpected types, malformed-encoding class). Missing: duplicate-header first-wins, comma-joined, present-but-empty, case/OWS variants, query-never-binds, chunked, reject-before-body-read.

**Deliverables:**
1. **Design doc** (`cmd-snaplink-billing-b4-4-credential-form-only-design.md`): §3.2 gained a validated-wire-semantics bullet; §3.6 rows 4/5-6/7/8/20/21 extended; new **§3.6a** with 24 concrete rows — **U1-U15** for `bind_strict_test.go` (package `oauthwire`, white-box, `errors.Is(err, errFormOnly)` assertable) and **E4b-E16** for `credential_content_type_test.go` (black-box strict harness; every 400 row also asserts no-store).
2. **Review artifact** `…/adversarial_review-9c87f3a7/meta/content_type_semantics_reviewer.md` with the evidence table, gap analysis, and findings: no mechanism change needed (the proposed binder matches every measured behavior), `errFormOnly` class taxonomy maps cleanly (empty/param-only → `missing`), chunked pin is e2e-only by construction, and the legacy escape hatch is byte-identical by construction.

Docs-only changes; no `.go` files touched, so no build gates apply.
