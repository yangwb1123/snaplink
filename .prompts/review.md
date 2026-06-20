# Prompt: review a change

Complements `docs/review-checklist.md` (printed by `python cli.py review`) with
the architecture lens. Report only issues you can ground in a rule or a test.

## Gate compliance (must all hold)
- [ ] `go build ./... && go vet ./...` clean.
- [ ] `go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`
      green — no new size/complexity/boundary violation, no stale exemption.
- [ ] `python cli.py check-root` clean — no business file or forbidden suffix in
      root (ADR-0001).
- [ ] No file > 500 lines, no function > 50 lines / cyclo > 15 / cognit > 20
      added (ADR-0005).
- [ ] Dependency direction intact; no upward import; `core` still leaf;
      `oauth ↮ oidc` (ADR-0002).

## Invariants (§3 of AGENTS.md — for security-touching changes)
- [ ] Oracle-leak collapse and anti-enumeration responses unchanged.
- [ ] Fail-open vs fail-closed classification preserved for the touched path.
- [ ] RFC 9068 claim stamping, refresh-family rotation, cache headers, `iss`,
      `setBearerChallenge` all correct where relevant.
- [ ] No mock where a `Memory*` impl exists; new shared type lives in `core`.

## Docs/contract coupling (same-commit requirement)
- [ ] New `Err*` → `docs/error-codes.md`. Endpoint change → `docs/openapi.yaml`.
- [ ] A rule change / new top-level dir / public import-path move → an ADR in
      `docs/adr/`.

## Output
Per finding: severity · file:line · the rule/test it violates · the fix.
Confirm which gate commands you ran and their results — evidence before claims.
