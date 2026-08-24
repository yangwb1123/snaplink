# B13 documentation truthiness report

Status: complete. This report records the documentation sweep against the
current code and the B13 local evidence; it does not claim OpenID Foundation
certification.

## ROADMAP alignment

- P0 #2 now records both FAPI follow-ups: `07832dda` reached **12 SUCCESS + 1
  FAILURE**, and HTTPS run `1b2867c6` reached **156 SUCCESS + 1 FAILURE + 3
  WARNING** before the query-suffix callback case. The remaining local
  compatibility boundary is explicit: v1 `redirect_uri_patterns` permits a
  fixed HTTPS host and one interior path-segment wildcard, but rejects
  query-bearing candidates. External HTTPS execution, OIDF submission and
  archive publication remain open.
- P0 #5 now distinguishes the completed B9 nested-module physical split and
  completed LDAP/Kerberos/RADIUS/KMS host-API migration from the remaining
  hot lifecycle work; release archives now also receive hosted SLSA
  provenance attestations in the release workflow.
- P1 #7 now reports the verified SDK surface count of **316 operations**.
  P1 #8 remains truthful as the external-frontend release contract.

## Feature and deferred-state alignment

The specification table now has evidence-backed rows for:

- per-client `id_token_signed_response_alg` and issuer/discovery wiring;
- config baseline apply/rollback plus opt-in canary observation;
- `SSOConfigDrift` explicit apply and expected-version CAS rollback mode;
- structured access logging; and
- OTel request correlation with span-first audit fields.

The deferred backlog now lists canary and explicit operator rollback as
implemented within their stated Memory/SQLite, storage-health-probe, and CAS
boundaries. GitOps reconciliation remains explicitly uncommitted. The OIDC evidence kit and harness
README agree on archive `1b2867c6-fapi-https` and the query-suffix boundary.

The capability registry did not change: `python3 cli.py capabilities generate`
reported `capability registry valid; feature matrix already current`.

## Verification

- `python3 cli.py capabilities generate` — passed; no registry change.
- `python3 cli.py sdk-surface check` — passed: 13 groups, 316 operations,
  2 languages.
- `python3 cli.py check-routes` — passed: 243 runtime routes, 350 documented
  operations.
- `go build ./...` — passed.
- `git diff --check` — passed.

The worktree is intentionally not documented as “docs only”: it contains the
Canary implementation and tests from B13-R2-C, redirect-pattern/FAPI work,
and pre-existing user changes. No unrelated changes were reset or removed.

The broader `make ci` run remains blocked at its existing formatting gate by
the unrelated dirty file `shared/core/invitation.go`; that file was not
modified as part of this sweep.
