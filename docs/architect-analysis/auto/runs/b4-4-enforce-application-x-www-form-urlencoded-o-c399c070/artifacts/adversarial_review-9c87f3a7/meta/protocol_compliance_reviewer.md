All verification complete. Both HIGH decisions are resolved, validated, and documented.

## Summary

**Deliverables**
- `docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-decisions.md` — full decision record (new)
- `docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-design.md` — amended (§3.1 decoder extension, §3.4 F11/F12 rows, §3.5 steps 1/3/5, §3.6 acceptance rows, §4 audit)

**F1 — PAR `authorization_details`/`claims` (`json.RawMessage`): implement RFC 9396 §3 JSON-string form encoding, fail-loud on malformed.** The reviewer's "§7.2" citation was a misnumbering — RFC 9396 has no §7.2; the normative text is §3 ("encoded using the application/x-www-form-urlencoded format of the serialized JSON", Figure 8), and RFC 9126 §2.1 makes PAR a form-wire protocol that may carry any authorization-endpoint parameter. Fail-loud-only would make RAR-over-PAR non-compliant and turn the mandated test into a permanent negative. Decoded bytes flow through the existing pipeline unchanged (`ValidateAuthorizationDetails`/`RARLimits`/allowlist at PAR; `ValidateClaimsParameter` at login). **Remediation path**: migrate `parThenLogin` (handle_par_test.go:337) to a form POST with the JSON-string value — `TestPAR_AuthorizationDetailsSurvivesIntoAccessToken` (:391) and the four sibling tests pass with byte-identical assertions; `TestPAR_HappyPath_JSON` → `_Form`; new negatives for malformed/repeated values, new PAR-claims positive.

**F3 — MFA `params` map: fail loud at the handler.** No RFC defines map form encoding; silent drop is non-deterministic across providers (empty-params success possible for challenge-state providers). `parseMFACompleteRequest` rejects `PostForm.Has("params")` with the existing `400 mfa_invalid` envelope, no audit, no new `Err*` — oracle-safe per AGENTS.md. Flat `code`/`assertion` stay the documented form contract.

**Validation**: RFC 6749 §2.3.1/§3.2/§5.2, 7009 §2.1, 7662 §2.1, 8628 §3.1-3.2, 9126 §2.1, 9396 §2/§3, OIDC Core §5.5, CIBA — all consistent (table in the decision doc); device/CIBA-context RAR documented as non-goals (no fields exist). In-repo: zero tests use `params`; `rar_test.go`/`claims_param_test.go` hit only `/auth/login` (JSON, out of scope).

**Byte-identity**: the extension is a sub-branch inside the existing `case reflect.Slice` (bind.go:128) that today falls through for byte slices — all supported kinds (string/bool/int/*int/[]string), `formStringSlice`, `setFormInt`, JSON default branch untouched. Maps stay silent-skip in the shared decoder (would 400 admin/selfservice map-key form consumers); one disclosed additive collateral: `interfaces/admin/governance.go:61` `payload` gains decode instead of drop.

**Gates**: `go build ./... && go vet ./...` clean; maintainability gate red at HEAD for the pre-existing artifact-tree drift (`docs/architect-analysis/auto/runs` depth/fanout, root 24>21) — unchanged by this docs-only work, reported separately per AGENTS.md §5.7.
