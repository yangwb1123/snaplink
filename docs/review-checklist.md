# Code review checklist

The engineering generator validates this source-controlled checklist but never
rewrites it. Apply the detailed rules in [`AGENTS.md`](../AGENTS.md).

## Scope and structure

- [ ] The change has one purpose and no unrelated cleanup.
- [ ] Code lives in the owning layer; imports point only to the same or a lower
      layer.
- [ ] No production business code was added at the repository root.
- [ ] No exemption or frozen directory ceiling grew.
- [ ] The API-only product boundary remains intact.

## Behavior and security

- [ ] Tests cover success, invalid, expired, replay, mismatch, and tenant
      isolation paths that apply.
- [ ] Credential errors preserve oracle-safe and anti-enumeration behavior.
- [ ] Credential endpoints set no-store headers and every 401 uses the standard
      challenge.
- [ ] Single-use state is consumed atomically; fail-open/fail-closed behavior
      matches `AGENTS.md`.
- [ ] Proxy input, audit metadata, key algorithms, and refresh-family behavior
      preserve their documented invariants.

## Verification and contracts

- [ ] Targeted tests and the post-edit build/vet/root gates pass.
- [ ] Race, backend, chaos, DR, load, or benchmark suites ran when risk requires
      them.
- [ ] `make ci` passes before handoff.
- [ ] HTTP, error-code, configuration, architecture, and release documentation
      changed with the corresponding contract.
- [ ] Tests use real `Memory*` implementations instead of mocks.

## Handoff

- [ ] The diff contains no secrets, binaries, stale generated output, or
      unrelated files.
- [ ] Commit subject is conventional and imperative; the body explains why.
- [ ] Required sign-off/trailers are present and no hook was bypassed.
