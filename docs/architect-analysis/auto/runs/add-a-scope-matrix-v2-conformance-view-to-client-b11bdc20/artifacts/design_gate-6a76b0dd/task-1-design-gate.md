## Independent verification: blocking review findings vs. deliverable state

I verified each blocking finding against the current tree (HEAD `aa20656a`, deliverable untracked, 401 lines) and the run directory. **No revision artifact exists** — the run directory holds only requirements/design/adversarial-review outputs, no branch carries a revision, and the document contains zero references to any review finding (no resolution, no explicit rejection with evidence).

### Verified unresolved — with my own measurements

| # | Blocking finding | My evidence | Status |
|---|---|---|---|
| 1 | §2/§10.3 runtime-agreement overclaim (no registry-enabled qualifier) | §2 still unconditional: "a scope the CLI rejects is exactly a scope `/token` would 400 for". `build_stores.go` wires the registry only inside `if cfg.OAuth.ScopeRegistry.Enabled` (default-off → nil); `reject.go:31-42` `RejectUnregistered` no-ops on nil. Claim is false on the default deployment; 0 hits for pre-enablement/static-conformance language | **Unresolved** |
| 2 | FM table missing enabled-off + version-skew rows; FM-5 false-pass direction unlabeled | FM rows are exactly FM-1..FM-7 (lines 323-329); FM-5 Behavior covers only "false positives" — removals → CLI exit 0 while `/token` 400s, unlabeled | **Unresolved** |
| 3 | F1 env var | `apiclient.go:27` `EnvAddr = "SSO_ADMIN_ADDR"`; no `SSO_ADDR` anywhere in code; doc §3:84 and §7:289 still cite `SSO_ADDR` | **Unresolved** |
| 4 | F2 message shape undecided | R1.6 pins `sso-ctl clients: validate: scope "..."` while FM-1 uses `validate failed: <err>`; §7 Output row pins routing only | **Unresolved** |
| 5 | F3 `sso-ctl check` unreachable; mitigation guidance dishonest | `"check"` absent from main.go's 16-entry `subcommands` map (count 0); doc §3/FM-5/FM-6/FM-7/§9/§10.3 still direct operators to `sso-ctl check` T-8d, with no out-of-scope declaration | **Unresolved** |
| 6 | E3 broken client choice | E3 still `client-v` with no `--scope`; verified cc branch defaults empty request to allowlist-minus-openid then `RejectUnregistered` → `billing:typo` 400 → mint FAIL → sweep red; "invalid_scope: OK — keeps the live probe green" is false as written | **Unresolved** |
| 7 | FM-1/FM-3/FM-5/FM-7 test coverage missing | U-table is U1-U9 only; no closed-port, garbage-response, provisioned-matrix, or `extra_scopes` fixtures | **Unresolved** |
| 8 | stdout-empty-on-failure assertion missing | U4/U5/U6/E1a assert stderr content only; §7 script-safety half unpinned | **Unresolved** |
| 9 | consts.go placement decision absent | No statement where `validate: OK`/offender-template/exit literals live | **Unresolved** |
| 10 | §8.4 gate wording | Still "directory files 5 ≤ 15" (conflates file/subdir gates) | **Unresolved** |
| 11 | §8.5 version-skew note absent | Only wire-shape safety; matrix compiled into both binaries | **Unresolved** |
| 12 | FM-2 oracle sentence absent | No reasoning that inactive clients return 200, 401 precedes handler, same credential class holds `list`/`get` | **Unresolved** |
| 13 | U7b guard unspecified | R1 says "mirror `runGet`", but `runGet` ignores trailing args; exit 2 for `["validate","c1","--nope"]` needs a `len(args)>1` guard never specified | **Unresolved** |
| 14 | F4 arithmetic nit | §1 "8 structural aliases (commerce ×5...)" mislabels the const block (admin×2 + commerce×3 + metering×2 + wildcard×1) | **Unresolved** |

### Explicit rejections with evidence?

None. The document is the pre-review version; no finding is acknowledged, refuted, or scoped out. The findings are neither resolved nor rejected — they are absent.

VERDICT: FAIL - The deliverable is byte-identical to the pre-review version: none of the blocking findings (static-conformance reframe, enabled-off/version-skew/false-pass boundary rows, F1 env var, F2 message shape, F3 check-dispatch guidance, broken E3 client choice, missing FM-1/3/5/7 and stdout-empty tests, consts placement, §8.4 wording) is resolved or explicitly rejected with evidence, and the headline §2/§10.3 runtime-agreement contract remains false on the default registry-disabled deployment.
