# Re-review verdict: the "revised" design does not exist — none of the four fail-open gaps are closed

**Material finding first:** the deliverable `docs/architect-analysis/cmd-sso-ctl-configcmd-b4-1-issuer-allowlist-requirements.md` was last written `2026-08-06 19:16:37 -0800` = **2026-08-07 03:16:37 UTC**, i.e. *before* the security review completed (`gate_semantics_reviewer.md.meta.json` `created_at: 2026-08-07T03:29:01+00:00`). `find -newermt '2026-08-07 03:17'` returns only the three review artifacts and the `bin/k8s-rendered/*` regenerations (ops reviewer's `make k8s-render`, byte-identical per its own diff). The file is untracked, so there is no git history of a revision either. **I reviewed the current tree version against each requested confirmation; all seven fail.**

## Per-item verification against the current document

| Requested confirmation | Current document text | Verdict |
|---|---|---|
| 1. Query/fragment rejection | R2-1/R2-3: "must parse with `url.Parse`, have scheme `http` or `https`, and a non-empty host" — no `RawQuery`/`Fragment` rejection; R2-5 ignores only *path* | **NOT closed (HIGH-1 open)** — `issuer: https://sso.example.com?x=1` with a mirroring allowlist entry passes all five checks and exits 0; the RFC 8414-invalid string gets stamped verbatim |
| 2. Userinfo rejection | No `u.User != nil` check anywhere in the doc (only hit for "userinfo" is the OIDC userinfo *endpoint* in §1) | **NOT closed (HIGH-2 open)** — `https://user:pass@sso.example.com` is origin-equal to the clean URL under R2-5 and passes membership when the allowlist mirrors it; credential-bearing `iss` in every token/doc |
| 3. Empty-port suffix rejection | No `HasSuffix(u.Host, ":")`; acceptance 16 covers `:443`-vs-none (fail-closed) but not `https://sso.example.com:` (parses, `u.Port()==""`, origin-equal, mirrorable) | **NOT closed (MED-5 open)** |
| 4. Gate-before-print + honest output + CI hook | §7: "call the gate after `config.Load`" — insertion point relative to the `config OK: %s` print (verified at `main.go:59-60`, immediately after Load, before any gate) is unspecified; acceptance 1 pins stdout "`config OK: ...` (byte-identical shape to today)"; §4 explicitly keeps CI out ("the new configcmd gate does not move CI") | **NOT closed (HIGH-3 open)** — no "failing gate emits only stderr, never an OK line" rule, no success line naming the matched allowlist entry, no deploy-tree gate test/hook |
| 5. Origin canonical form pinned | R2-5: "its origin (scheme + host + port, lowercased host; path and trailing `/` ignored)" — string form unpinned; `u.Host` vs `Hostname()` IPv6-bracket trap unaddressed | **NOT pinned (MED-4 open)** — `ToLower(scheme)+"://"+ToLower(u.Host)` appears nowhere |
| 6. Membership case-sensitivity asymmetry stated | R2-4: "exact string match otherwise" — implies but never states the deliberate asymmetry (membership case-sensitive per RFC 8414; origin lowercased) | **NOT stated (MED-4 open)** — an implementer may "normalize" membership into a fail-open |
| 7. Unambiguous check-order wording | "Order of checks: 1 → 3 → 2 → 4 → 5, so the most specific message wins per violation set; all violations are collected (not first-wins)." | **NOT fixed** — the contradictory pair ("most specific wins" vs "all collected") survives verbatim, and 3-before-2 (entry-validity before presence) has no stated rationale |

## "No new oracle or fail-open path introduced"

Confirmable in the narrow sense: nothing was introduced since the review, because nothing changed. The gate remains a pure function over file-loaded config with operator-facing stderr (the security reviewer itself concluded "the gate itself is oracle-safe"; it is not a network surface, so the AGENTS.md oracle table does not apply). **But the four fail-open paths themselves remain open** — the design is unchanged in every respect the reviewer flagged.

## Secondary finding (also unaddressed)

The ops migration reviewer's three deploy-tree configs missing from §7 (kustomize base `ops/deploy/kustomize/base/config.yaml` — sentinel `issuer: sso-server`, feeds `bin/k8s-rendered/dev/all.yaml:21`; `ops/deploy/kustomize/overlays/prod/config.yaml:12`; `ops/deploy/k8s-distributed/config.yaml:3`) still have no table rows or scope note, so the documented migration leaves three gate-rejected configs, and the "regenerated" dev render would still embed the sentinel.

## What the revision must contain (mapped 1:1 to the reviewer's required changes)

1. R2-1/R2-3/R2-5: reject `u.RawQuery != ""`, `u.Fragment != ""`, `u.User != nil`, and `strings.HasSuffix(u.Host, ":")` on issuer, every allowlist entry, and `base_url`; add acceptance cases for each (userinfo issuer ⇒ 1, userinfo base_url ⇒ 1, `https://sso.example.com:` ⇒ 1, query/fragment ⇒ 1).
2. R2-5: pin canonical form to `strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)` (bracketed `u.Host`, mirroring pathless `middleware.BaseURL`); add IPv6-with/without-port and mixed-case host unit cases; state membership = exact string after one-slash trim (case-sensitive), origin = lowercased, deliberately asymmetric.
3. `runValidate`: gate runs **before** the `config OK` print; failing gate emits stderr violations only, exit 1, never an OK line; success line names resolved issuer + matched entry with "runtime enforcement pending B4-1 server work"; add a deploy-tree gate test/CI hook (re-scoping §4's non-goal explicitly).
4. Replace the check-order sentence with a single resolution rule — e.g. "checks run in order 1→2→3→4→5; every violation is collected and reported; no check short-circuits another" — no "most specific wins".
5. Add the three missing deploy-config rows (or an explicit scope note) and the MED-6 coupling note (origin-only equality is contingent on the pathless request-derived runtime; wiring `base_url` later mandates R2-5 string equality in the same change).

**Bottom line:** I cannot confirm any of the seven items — the file under review is the same pre-review version, and `go build`/gate runs are unaffected (no Go files touched). The design must be revised as above and re-reviewed before implementation; until then it ships all four fail-open gaps.
