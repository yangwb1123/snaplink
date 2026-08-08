Resolution written to `docs/architect-analysis/auto/runs/b4-3-t-2-deploy-tree-discovery-truthiness-sweep--e344f596/artifacts/design-a77de8a6/task-1-cli-resolutions.md`. Every Go fact it rests on was re-probed on this checkout (throwaway probe, deleted). Decisions, with the tree conventions that ground them:

## 1. `--issuer-allowlist` parsing
**Grammar mirrors `config/config_load.go:356-364` (`validateAuthPipeline`)** — the tree's only validating list parser — not the lenient skip-empties `splitCSV` in `tui/fields.go` (a form-widget convention, not a gate convention):
- Split `","`, `TrimSpace` each entry, then **reject** (never skip): empty-after-trim → `--issuer-allowlist[%d] must not be empty` (0-based, byte-mirror of `required_profile_attributes[%d]`); duplicate → `--issuer-allowlist contains duplicate %q` (byte-mirror of config's duplicate message). So `"a, ,b"` → exit 2 `[1] must not be empty`; `"a,a"` → **reject** exit 2 (dedup would mask a copy-paste defect and make the gate pass while the operator's intent is wrong).
- `[%s]` renders **trimmed, order-preserving, `", "`-joined** — never sorted, never map iteration (design's own pin). Duplicates never reach the message because they're rejected; membership is exact string match (entries are not URL-parsed — `"sso-server"` is a legal issuer).
- Empty flag value via `fs.Visit` (auditverify's `--anchor-hash ""` precedent) → `--issuer-allowlist must not be empty` (`--file is required` style). Grammar fires before `config.Load`; membership (exit 1) after a successful load; loader errors always win (F9).

## 2. `--url` base validation
**Two-class boundary**: exit 2 = not interpretable as an http(s) URL (missing, `url.Parse` error, bad scheme, `Hostname()==""`), checked in flag validation before any network — the same class as Go flag errors and `--file is required`. Exit 1 = valid URL but not a bare base (path/query/fragment/userinfo/trailing slash), checked **pre-fetch as a short-circuit**: exactly **one** diagnostic line, **zero requests** (recording-handler pin), count 1 for both `http://host/` and `http://host/v1` — killing the cascading-4 risk unconditionally. This supersedes F6's "trimmed-base equality" language: no trimming anywhere (removes the auditverify-style silent `TrimRight` trap). Check order pinned: parse-grammar (2) → timeout (2) → base form (1, abort) → fetch → equality → shape → probe. Query/fragment join the exit-1 class (`Path != "" || RawQuery != "" || Fragment != "" || User != nil` — userinfo rejected per the security reviewer's credential-vector pin).

## 3. IPv6 literals
`url.URL.Hostname()`/`Port()` only, never manual colon splitting (`strings.Split("[::1]:8080", ":")` yields `["[", "", "1]", "8080"]`). Empty-host = `Hostname()==""`; trailing-slash variant caught by `Path=="/"` (probed: `http://[::1]:8080/` → Path `/`, `Port()` `8080`). Shape checks run only on `url.Parse`-verified URLs (parse failure = the legacy `host:8080:0` violation — the reviewer's silent mis-split is unreachable), port via `Port()` + `Atoi` where **Atoi error (overflow `18446744073709551616`) is a violation, not a skip**. Green test uses a real `[::1]` httptest listener (`t.Skip` only if IPv6 loopback absent).

## 4. `--print` + failing allowlist
Gate sits **between `config.Load` and the `config OK:` print** (main.go:104 — the flagged regression window): mismatch → stdout `""`, one stderr line, exit 1, **with and without `--print` byte-identical**. `config OK:` prints only after the gate passes; `--print` JSON never renders on failure. Loader failure with allowlist present → loader message, exit 1, gate unreachable by construction.

## 5. `--timeout <= 0`
`flag.Duration` accepts `0s`/`-1s` (probed) → post-parse check in flag validation (after `--url` grammar, before the base check): `sso-ctl config: --timeout must be greater than zero` + usage, exit 2 — decidable without network, so it can never degrade into the misleading exit-1 `timed out after 0s` runtime diagnostic.

**Key table rows** (full 25-row byte-exact table in the artifact; all failing rows have stdout `""`, usage rows append the configcmd banner):

| Invocation | stderr (exact) | exit |
|---|---|---|
| `--issuer-allowlist "a, ,b"` | `sso-ctl config: --issuer-allowlist[1] must not be empty` | 2 |
| `--issuer-allowlist "a,a"` | `sso-ctl config: --issuer-allowlist contains duplicate "a"` | 2 |
| mismatch (no/with `--print`) | `sso-ctl config: server.issuer "https://evil.example.com" is not in the operator allowlist [https://a.example.com, https://b.example.com]` | 1 |
| `--url http://host:8080/` or `/v1` | `sso-ctl config: check-discovery: --url: invalid base "<raw>": must be scheme://host[:port] with no path, query, fragment, userinfo, or trailing slash` | 1 |
| `--url http://[::1]:P/` (green: no slash) | same form / `discovery OK: http://[::1]:P` | 1 / 0 |
| `--timeout 0s` / `-1s` | `sso-ctl config: --timeout must be greater than zero` | 2 |

Section 7 lists the seven verbatim supersessions to the design text (allowlist grammar, two-class URL scheme, short-circuit, trimmed-base language removal, `Hostname()`/`Port()` rule, gate placement, and the 25 test pins A2–A10/B1–B15).
