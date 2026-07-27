# Example input: user administration change

> Pipeline seed only. This is not an open product requirement.

Use this shape for a proposal that extends the existing
`/api/v1/admin/users` surface:

## Problem

State the operator workflow the current list/get/create/update/delete API
cannot satisfy, including tenant and credential impact.

## Contract

- Reuse the existing admin resource unless a distinct resource is justified.
- Define scope, pagination, filtering, stable ordering, schemas, and
  oracle-safe errors.
- Exclude password hashes, MFA secrets, reset tokens, and other credential
  material.

## Acceptance

- Protobuf, REST mapping, OpenAPI, and error catalog change together.
- `admin:read`/`admin:write` and cross-tenant tests pass.
- Mutations emit audit events and invalidate relevant caches.
- Tests use real memory and affected durable backends.
- Applicable package tests and `make ci` pass.

For real work, copy [the feature-spec template](../templates/feature-spec.md)
outside this example directory and apply the
[admin evaluation criteria](../agent-os/EVALUATION.md).
