Verification complete. Both temp probe files deleted; worktree clean of them (`git status` shows only the pre-existing untracked `test/scope_registry_test.go`).

## Independent verification results

**Timeline/state check:** the design (`cmd-sso-ctl-b4-3-t2-design.md`, mtime 15:53:35) predates all three review artifacts (15:59:55, 16:03:31); the last commit is the `adversarial_review` stage itself. No design revision or rejection memo exists after the reviews — the blocking must-pins were never folded back in.

**Must-pin #1 — violation ordering (not resolved).** Design §2.3 still specifies `checkDiscoveryDoc(doc map[string]any, base string) []violation` with no iteration-order mandate; §6 case 3 remains "table-driven, 3 sub-cases" (one violation per doc, exactly the case the reviewer said cannot catch ordering drift). The failure-mode table's claim "violation output is deterministic per run" has no mechanism behind it — Go map iteration is randomized, so multi-violation stderr is nondeterministic as designed. No multi-violation exact-bytes test anywhere in §6.

**Must-pin #2 — allowlist placement (not resolved as pinned).** Verified in `cmd/sso-ctl/configcmd/main.go:99-101`: `fmt.Printf("config OK: %s\n", *file)` prints to stdout *between* `config.Load` and the `--print` block. Design §2.2 only says the check runs "before `--print` rendering" — a placement between `config OK` and `--print` would satisfy that wording while violating the design's own "nothing is printed to stdout" invariant. The reviewer's explicit pin (immediately after `config.Load`, before the `config OK` print) is absent.

**Must-pin #3 — `--timeout <= 0` (not resolved).** Design §2.1/§4 only define "unparseable" timeout → exit 2. `flag.Duration` accepts `0s`/`-1s`, so a ≤0 timeout passes parse and manifests as every probe failing → exit 1 "sweep timed out" — precisely the confusing failure the reviewer flagged. No `<= 0` rejection in the design.

**Non-blocking items:** (a) The C1a status-code "correction" is actually a request-construction artifact — my own probes confirm the design's numbers are right for the form-encoded empty POST it specifies (form-empty → 401 on `/token`, 415 on `/auth/login`) while no-content-type/JSON-empty → 400 (the reviewers' measurement); the load-bearing non-404-before-store-write claim holds under all constructions. (b) `test/zz_review_probe_test.go` does not exist in HEAD or the worktree — the reviewer's housekeeping item is already satisfied. (c) F1/F5 recommendations (mtls aliases, `mfa_endpoint`, doc-URI shape checks, query/fragment rejection) and the DirectoryDepth inventory gap are unaddressed but were non-blocking by the reviewers' own ratings.

**Verdict driver:** the three must-pins — the only items the reviewers rated blocking — are neither resolved in the deliverable nor explicitly rejected with evidence; the design was not touched after review.

VERDICT: FAIL - The design was never revised after adversarial review: canonical violation ordering with a multi-violation exact-bytes test (must-pin 1), allowlist placement before the `config OK` stdout print (must-pin 2), and `--timeout <= 0` rejection as exit-2 usage error (must-pin 3) are all absent or ambiguous, with no rejection memo, so the blocking findings remain open.
