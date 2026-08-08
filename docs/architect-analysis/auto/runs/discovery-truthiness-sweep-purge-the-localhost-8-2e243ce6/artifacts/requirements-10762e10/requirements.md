The spec is complete and self-consistent. Final summary of the deliverable:

## Deliverable

**`docs/architect-analysis/cmd-gensdk-b4-3-discovery-truthiness-requirements.md`** (211 lines) — evidence-backed requirements spec for the B4-3 direction, in the house style of the sibling `cmd-sso-operator-b4-3-deploy-tree-truthiness-requirements.md`.

## Verification results (every citation re-checked)

All 11 direction citations confirmed against HEAD, with two material findings:

1. **`"/authenticate"` is not 0-match in cmd/ as claimed** — it exists at `cmd/sso-ctl/generate/scaffold_contract_test.go:136` (`[]byte("/authenticate")`, the scaffold anti-pattern guard). The "0 matches today" claim holds **only for non-test Go sources**. The acceptance (b) guard is therefore scoped to non-test `*.go` files under `cmd/` — a naive full scan would fail on day one against a legitimate guard. Documented in the evidence table and R2.
2. **The port assertion in acceptance (a) is testable only because discovery is request-derived** — `handleOIDCDiscovery` computes `base := requestBaseURL(ctx.Request())` (`server_discovery_config.go:62`), so the httptest ephemeral port appears in served endpoints. Also pinned: prototype 404s OIDC discovery but serves the RFC 8414 alias (byte-identical handler); "standard" resolves to `editionMinimal` (`edition.go:18-22`); the generator does not consume `servers:` (`base_url` is a runtime ctor param), making "wire shape unchanged" a byte-stability assertion.

## Structure

- **R1–R5** map 1:1 to T-2 (a)–(e): edition discovery-truthiness sweep (const-derived `server.URL + core.Path*` equality + `/authenticate` + port checks), deploy-tree literal guard, `docs/openapi.yaml` servers purge + `parseSpec(docs.OpenAPISpec)` regression lock in `cmd/gensdk`, `sdk-surface generate && check` with zero diff on `docs/sdks/`, and existing `TestDiscovery_*` green / legacy defect tests absent.
- 12 Given/When/Then acceptance cases, graded 12/12 machine-checked except two explicitly-stated review-time invariants (guard self-exclusion design, legacy-test absence).
- No production Go changes anywhere; test-only additions in `cmd/sso-minimal` + `cmd/gensdk`, one spec edit; all engineering-gate constraints verified (budgets, `interfaces/sso` ceiling untouched, no new deps, no nested-module changes).
