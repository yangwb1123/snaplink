# Stock password-policy configuration design

## Scope and current-code evidence

This slice wires the existing local password-policy SPI into the stock
`sso-server` configuration. The executable source is authoritative; the older
analysis material is not used as an implementation source.

Current code evidence before this change:

- `shared/spi/reg_gate.go` already defines `PasswordPolicyValidator`,
  `PasswordMaxAgeProvider`, `PasswordPolicyConfig`, and
  `NewPasswordPolicyValidator`. Its validator returns the generic
  `spi.ErrPasswordPolicyViolation` and performs only local synchronous checks.
- `protocols/selfservice` already calls the validator for signup,
  `/me/password`, and `/auth/reset-password`.
- `interfaces/sso` already owns `WithPasswordPolicy`,
  `passwordMaxAgeDays`, and `rejectExpiredPassword`.
- `config.PasswordConfig` had no policy projection, and the stock composition
  root did not append a policy option.
- `interfaces/admin` admin password reset and `internal/adminuser` local-user
  creation did not consult the optional validator. First-run setup in
  `interfaces/sso/server_setup.go` wrote the initial credential without that
  check.
- `core.PasswordAgeReader` is already an optional credential-store extension;
  `rejectExpiredPassword` uses it only after successful password
  authentication.

## Configuration projection

`authenticators.password.policy` is an optional YAML block projected by
`config.PasswordPolicyConfig` into the already-existing
`spi.PasswordPolicyConfig`:

| YAML | SPI | Meaning |
|---|---|---|
| `min_length` | `MinLength` | Minimum length; `0` disables the minimum |
| `require_upper` | `RequireUpper` | Require an uppercase rune |
| `require_lower` | `RequireLower` | Require a lowercase rune |
| `require_digit` | `RequireDigit` | Require a digit rune |
| `require_special` | `RequireSpecial` | Require a non-letter/digit/whitespace rune |
| `max_age_days` | `MaxAgeDays` | Login-time expiry; `0` disables it |

The config layer intentionally does not expose `max_history`. The existing
SPI's `MaxHistory` field is not a durable stock configuration: password history
is a separate `PasswordHistoryStore` concern and remains available only through
explicit `WithPasswordHistoryStore` wiring (or an equivalent embedding).

The config validator rejects `min_length` outside `0..1024` and
`max_age_days` outside `0..36500`, with the full YAML path in the diagnostic.
A missing policy block and an all-zero block remain valid and do not apply
configuration defaults. Neither case causes the composition root to append a
password-policy option.

## Runtime wiring and write paths

The stock composition root converts the configured block with
`spi.NewPasswordPolicyValidator` and appends `sso.WithPasswordPolicy` before
constructing the server. The option is independent of whether the
self-service password store is enabled; whenever a stock password store exists,
all of these plaintext-setting paths use the same validator:

1. self-service signup (including the plaintext capture before mandatory email
   verification),
2. authenticated `/me/password`,
3. `/auth/reset-password`,
4. `interfaces/admin` admin reset,
5. `internal/adminuser` local-user create, after its existing minimum rules,
6. first-run setup's initial admin password, before role, user, or credential
   persistence.

Recovery setup only authenticates an existing credential. It does not set a new
password and therefore does not run the policy. YAML-seeded bcrypt hashes and
other pre-hashed imports remain pre-hashed inputs; the plaintext policy cannot
be re-run against them and their existing startup semantics are unchanged.

## Failure, oracle, and side-effect semantics

A non-nil validator is a local synchronous, fail-closed gate for configured
password writes: any validator error rejects the write and is mapped to the
existing generic password-policy or invalid-request response for that surface.
Rule details, validator error text, and password material are never returned or
logged. No new endpoint, event, or error code is introduced.

- Self-service paths retain their existing `400 password_policy_violation`
  behavior.
- Admin reset retains its existing generic `400 password_policy_violation`.
- Local-user create retains its existing validation-error mapping to generic
  `400 invalid_request`.
- First-run setup maps policy rejection to its existing generic `400
  invalid_request`, rather than the setup provisioning `500` path.

The setup check is before any role assignment, user write, credential write, or
role assignment side effect. The other paths preserve their existing ordering
and rollback behavior. The default (no policy option) has no new validation,
response, logging, network, or persistence behavior.

`max_age_days` is not a write-time rule. The existing login gate remains
fail-open when the login is not a password authentication, no
`PasswordAgeReader` is implemented, the age read fails, or no policy/max-age is
configured. It remains a post-success-password check, so it does not create a
credential-validity oracle. WebAuthn and federation logins are unaffected, and
successful password writes retain their existing credential timestamp updates.

## Deliberately excluded work

This slice does not add a durable password-history backend or YAML history
settings: `max_history` needs the separate per-user `PasswordHistoryStore`, and
stock has no durable history backend to configure. It does not add HIBP or any
other network dependency, or a setting-time HIBP block: password writes remain
local and synchronous, while the existing health checker is a separate,
login-time, fail-open signal. It does not add automatic or forced migration of
existing credentials because pre-hashed YAML/imported values cannot be
revalidated as plaintext and forcing a migration would change startup/login
semantics. A frontend and any protocol surface are also out of scope.
Password health remains separate from password policy; password history remains
explicit SPI wiring.

## Rollback

Rollback is configuration-safe: remove `authenticators.password.policy` or set
all policy fields to their zero values, then restart. Removing the block means
no `WithPasswordPolicy` option is appended and restores the prior stock
composition behavior. Code rollback requires no data migration because the
slice changes no stored credential format, schema, timestamp behavior, endpoint,
or event.
