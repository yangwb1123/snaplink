All assertions verified. The requirements spec is complete.

## Deliverable

**`docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-requirements.md`**

## Evidence verification summary (all 5 direction citations checked against HEAD `4ba36040`)

| Citation | Verdict |
|---|---|
| `oauthwire/bind.go:28-58` JSON/missing-CT→JSON default | ✅ Confirmed exact (func :28, default→`decodeSingleJSON` :43-45, backward-compat comments :15-26) |
| `server_jar.go:301-304` `bindOAuthParams` | ✅ Confirmed (alias :304 → `aliases.go:97` → `oauthwire.BindParams`) |
| `server_token.go` no Content-Type gate | ✅ Confirmed (no-store :22, bind :30, zero CT checks) |
| `bind_extra_test.go:150` `TestBindParamsJSONDefault` | ✅ Confirmed (func :148, comment :150) |
| `bind_fuzz_test.go:28` fuzz harness | ✅ Confirmed (ctSelector cases 2/3 drive the JSON-default branch) |

## Drift reports that shaped the spec

- **C1 — `/register` premise is false**: it binds via `ctx.Bind` (`shared/core/router.go:137`, pure JSON), never `bindOAuthParams`; OpenAPI declares JSON-only; RFC 7591 §3.1 mandates JSON. Resolution D-1: excluded from the form-only flip; complementary JSON-CT gate carried as [PROPOSED] pending contract-owner sign-off.
- **C2 — blast radius**: 8 credential BindParams sites + non-credential consumers (`commerce/payment_ingest.go:99` requires JSON) → enforcement is a scoped strict binder, not a global default flip (R6).
- **C3 — T-9 precedence**: body-parse precedes client-auth today; under T-8(b) an unauthenticated JSON introspect must 400. Retained regression pinned as "every bindable (form) unauthenticated `/introspect` → `401 invalid_client`"; auth-before-parse rejected (kills body-credential auth).
- **C4 — mechanism [PROPOSED]**: "strict mode + config fallback" pinned as config-gated strict binder (default ON, legacy fallback key in `config/config_server.go:16`).
- **C5** — sweep: `TestFormEncoded_JSONStillWorks` (:272) inverts; E2E JSON→`/token` sites (auth_code_test.go:124,484; claims_param_test.go:352; handle_device_test.go:130,312,342); MFA JSON posts (mfa_test.go:175, credential_health_test.go:397).
- **C6** — OpenAPI declares form+JSON on all seven credential paths (1100/1139, 1275+, 1342+, 1472+, 1523+, 1820+, 641/644) — same-change removal.
- **C8** — `cmd/snaplink-audit-provisioner` itself contains no credential code (health only); nominal owner, untouched.

Acceptance T-8(b)(c)(e) + T-9 preserved verbatim and made testable as 18 Given/When/Then cases (including the `/register` disposition check); one prior accepted sibling spec (`cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-requirements.md`) was used as alignment reference, with the two deltas (config knob, admin-endpoint exclusion) explicitly flagged.
