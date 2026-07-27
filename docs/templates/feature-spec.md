# Feature Spec: <name>

> This source-controlled template is canonical. The engineering generator
> validates that it exists; it does not rewrite its content.

## 1. Goal and user outcome

What user/operator/developer problem is solved? What observable result marks
completion?

## 2. Product boundary

- Surface: SDK / stock `sso-server` / nested module / external frontend
- Default: enabled / opt-in option / feature-gated / custom composition only
- Explicit non-goals:

## 3. Module classification

- [ ] OAuth/OIDC/protocol flow
- [ ] Store implementation
- [ ] Admin or self-service endpoint
- [ ] Authenticator
- [ ] Audit/observability
- [ ] Authorization/policy
- [ ] Infrastructure/config/deployment
- [ ] Refactoring only

Owning physical layer/package:

Dependency direction review:

## 4. Acceptance criteria

Use the applicable IDs in `docs/agent-os/EVALUATION.md`, plus concrete
feature-specific outcomes.

- [ ] Universal build/vet/committed architecture and maintainability gates
- [ ] Applicable O1–O11 / S1–S7 / A1–A4 / N1–N5 criteria
- [ ] Oracle-safe and anti-enumeration negative cases
- [ ] Tenant/client isolation cases
- [ ] Fail-open/fail-closed behavior
- [ ] HA/shared-state behavior where applicable
- [ ] Feature-off/unwired behavior

Feature-specific Given/When/Then criteria:

1. Given … when … then …
2. Given … when … then …

## 5. Files

### Create

```text
path/to/new_file.go — responsibility
```

### Modify

```text
path/to/existing.go — reason
```

### Do not modify

```text
path/to/boundary.go — invariant
```

Confirm file/function/directory frozen ceilings before implementation.

## 6. Dependencies and compatibility

- New/changed SPI:
- New option/store wiring:
- New YAML/env keys:
- Storage migration:
- HTTP/proto compatibility:
- Rollout/rollback:

## 7. Documentation

- [ ] `docs/openapi.yaml`
- [ ] `docs/error-codes.md`
- [ ] `docs/config-reference.md`
- [ ] Feature/deferred-backlog entry where scope changes
- [ ] ADR or migration guide for a public/breaking architecture change

## 8. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
make ci
```

Additional targeted, race, backend-semantics, chaos, DR, conformance, load, or
benchmark commands:
