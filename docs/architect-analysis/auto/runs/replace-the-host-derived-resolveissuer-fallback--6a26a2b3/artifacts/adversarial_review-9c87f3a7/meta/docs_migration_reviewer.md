Verification complete. I re-read the amended design artifact in full (109 lines, `design-a77de8a6/task-1-design.md` — the only design copy in the run), the sibling spec, `docs/config-reference.md`, and `ops/deploy/helm/sso-server/values.yaml` in the current worktree.

## Verdict: FAIL — the amendment covers none of the four config-contract gaps

The amended design added only the acceptance-mapping reconciliation (21→24 total, FM-3/FM-10 restored, GWT enumeration, FM→test matrix, byte-identity proof). Every config-contract gap flagged by the config-contract reviewer and re-flagged by the verify artifact remains open.

**1. `docs/config-reference.md` — not covered.**
- The design artifact contains **zero** occurrences of `config-reference` (grep across the file: only hit for `docs/` is the self-citation path at line 1). §4 "File placement summary" lists exactly 3 rows, all test files.
- The actual file: `server.issuer` row at **:48 is unamended** ("MUST differ from `sso.DefaultIssuer`; stamped into JWT `iss`, discovery `issuer`, every RFC 9207 `iss`"); **no `issuer_allowlist` row**; **no `server.base_url` row** (the only `base_url` hits are `smtp.link_base_url` :260, `phone.sms.base_url` :339, `magic_link.base_url` :385, `scim.push.base_url` :507). Its worktree diff contains only the unrelated B4-2 scope-registry row.
- The run's own requirements artifact (`requirements-10762e10/requirements.md:24`) lists the docs obligation ("docs in `config-reference.md` + `feature-matrix.md` per AGENTS.md §5.6") — the amended design still omits it.

**2. Deploy-tree migration table / 12th config — not covered.**
- The design has **no migration table**; the migration bullet defers to "the sibling configcmd spec's replacement table" — which has **11 rows only** (verified: §7 of `cmd-sso-ctl-configcmd-b4-1-issuer-allowlist-requirements.md` lists cmd/sso-server, bin, k8s, kustomize base, examples/basic, compose, baremetal-ha, k8s-prod, overlays/prod, conformance, k8s-distributed).
- `ops/deploy/helm/sso-server/values.yaml:162-163` confirmed unchanged: `issuer: sso-server`, `base_url: http://sso-server:8080` (rendered verbatim by `templates/configmap.yaml`). It fails the sibling gate today (non-URL issuer, R2-5 origin mismatch) and would fail the design's boot gate (sentinel is never a member). The needed row follows the table's own `issuer := base_url` rule: `issuer: http://sso-server:8080` + `issuer_allowlist: [http://sso-server:8080]` — nowhere in the design or sibling table.

**3. Sibling R1 comment — not amended.**
- `cmd-sso-ctl-configcmd-b4-1-issuer-allowlist-requirements.md:55` ("…the server itself is untouched, so boot behavior is byte-identical (the key is not read at boot)") and `:74` (the field doc comment, "the key is not read at boot (server-side enforcement is B4-1 server work)") are both verbatim. The design's own A-1…A-11 make the server read the key at boot (`config.Load` rejection, `NewServer` panic, `resolveIssuer` pin), so both statements are now false — the staleness the reviewers flagged is unfixed.

**4. Design file table lists the docs file — not covered.**
- §4 lists only `interfaces/sso/issuer_allowlist_test.go` (new), `config/issuer_allowlist_test.go` (new), `cmd/sso-server/issuer_test.go` (extend). No docs file, no sibling spec, and also no production files (`server_discovery_cache.go`/`config_server.go`/`sso.go` appear only in the verdict prose, not the table), no deploy-tree configs, no helm values.yaml.

**Carry-over drifts (unchanged by the amendment):** R-3's "reference + 12 deploy-tree configs" still double-counts `cmd/sso-server/config.yaml` (reference and table row 1); the design's migration bullet cites the sibling table's count "12" that the 11-row table cannot support.

No Go files were touched, so no gates were triggered. The amendment needs a second pass: add the docs file (+ `feature-matrix.md`) to §4, add the helm values.yaml row (issuer `http://sso-server:8080` + matching allowlist) to the migration table, amend the sibling R1 comments at :55/:74 in the same change, and fix the R-3 double-count.
