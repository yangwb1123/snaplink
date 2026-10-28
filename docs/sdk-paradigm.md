# SDK paradigm

Normative for every Snaplink client SDK. Read this before adding an SDK, adding a
capability to one, or changing a published package. The machine-readable form of
everything below is [`ops/build/sdk-paradigm.json`](../ops/build/sdk-paradigm.json);
`python cli.py sdk-paradigm check` is the gate that holds this document honest.

## 1. Two layers, both governed

`ops/build/sdk-surface.json` governs the generated operationId surface. It is
emitted for TypeScript and Python only, by `cmd/gensdk`, which carries no
allowlist of its own. Everything the generator never sees — the hand-written
transport, session, entitlement, preferences, and runtime behaviour of each SDK
— is governed here instead.

The generation allowlist remains solely `ops/build/sdk-surface.json`.
[`sdk-surface-coverage.json`](../ops/build/sdk-surface-coverage.json) records the
reasons and exposure/authentication/default/licensing boundaries for each selected
group and each explicitly unselected operation (operationId + method + path).
`python cli.py sdk-surface check` rejects unclassified operations, stale or
overlapping exclusions, duplicate operationIds/raw YAML keys and invalid local
references. `python cli.py sdk-surface coverage` emits a deterministic read-only
JSON report of every HTTP operation, its decision, media types and OpenAPI
security declaration/source (operation, inherited root, or unspecified).
An explicit empty security array stays distinct from inheritance. These are
**declarations, not verified runtime authentication or route exposure**.
Absence of bearer security does not establish anonymous access. Confidential CIBA
clients authenticate with a non-empty secret (Basic takes precedence over body
credentials) or a verified `private_key_jwt` assertion. Registered public CIBA
clients with `token_endpoint_auth_method="none"` may supply `client_id` without a
secret or assertion; this identifies the client, not proof of possession. Both
paths still enforce registered/active client, tenant, resource and scope checks in
[`protocols/oauth/handle_ciba.go`](../protocols/oauth/handle_ciba.go).
The current inventory is 366 documented / 321 selected / 45 unselected, not a
permanent quota or a claim of full-API SDK coverage. Exclusions distinguish
unmodeled SSE/text transport from existing JSON API coverage debt and separate
Billing/machine compositions. Already selected HTML/SSE methods are preserved;
selection alone does not prove their wire/runtime support.

| Layer | Scope | Registry | Languages | Gate |
|---|---|---|---|---|
| **L1 ApiClient** | 321 operations in 13 groups | `ops/build/sdk-surface.json` | TypeScript, Python | `cli.py sdk-surface check` |
| **L0–L3 hand-written** | transport, session, entitlement, preferences, runtime | `ops/build/sdk-paradigm.json` | five hosted-login SDKs; Kotlin and Swift are registered native SDKs still onboarding | `cli.py sdk-paradigm check` |

A language is released as a package only if it appears in
`ops/scripts/sdk_versions.py`; the paradigm gate requires every such package to
declare a language entry, so a new published SDK cannot ship ungoverned. Go is
a separate nested module at `sdks/go`, with `sdks/go/v...` release tags; its
`package: false` registry entry means the central manifest-version script does
not manage that Go module's release, not that the root module owns it.
Kotlin and Swift are registered native SDKs still onboarding to the
five-language full-SDK parity floor. Their source/registry entries do not prove
mobile platform or release acceptance; those contracts must be validated
before publication. See [`sdks/README.md`](../sdks/README.md).

## 2. Capability declaration

Each capability is a `layer.id` pair with a `parity` and one declaration per
language.

- `parity: "parity"` — every **onboarded** language must be `present`. A `missing`
  entry in that subset is a gate failure. This is the ratchet: the eight parity capabilities are the floor
  that must not erode.
- `parity: "divergent"` — gaps are permitted, but every `missing` entry must name
  the wave that closes it, so drift has an owner.

A `present` entry names the exact file and the exact symbol text that provides
it; the gate reads the file and fails if the symbol is not there. Renaming a
symbol without updating the registry fails the build, which is the intended
behaviour: it forces a deliberate edit. A `missing` entry must not name a file
or symbol, so a gap can never be half-declared. For a language still onboarding,
`missing` can record an implementation gap **or explicitly identified validation/
review debt for existing source**. Source/test-file presence does not prove public
consumer availability, fixture passage, native execution or package publication.

Adding a capability id is append-only. Changing the file or symbol behind a
`present` entry is reviewable. Dropping an id, or downgrading `parity` to
`divergent`, is a breaking change to the cross-language contract and requires a
minor version bump plus a CHANGELOG entry. Adding a language id is allowed and
must declare every existing capability.

## 3. Layers

### L0 Transport

One injectable seam per SDK, so retries, proxies, timeouts, and test doubles are
substituted in a single place and the session layer never performs I/O directly.
The seam is normalised by [`ops/build/sdk-conformance/transport.json`](../ops/build/sdk-conformance/transport.json):
header names are matched case-insensitively and serialized in a stable order, so
a request recorded against one SDK replays identically through another. A
transport double is therefore a valid conformance harness.

No transport implementation may log a header named `Authorization` or `DPoP`, or
a credential form field. `code_verifier`, `client_secret`, `license_key`, and
`invitation_code` never appear in a URL, a redirect, or an error message.

### L1 ApiClient

The generated layer. Method names are the spec `operationId` verbatim so a call
site is greppable back to `docs/openapi.yaml`.

### L2 Session

Explicit lifecycle: start, refresh, logout, and local clear. All five hosted-login
SDKs expose `refresh()` as a caller-controlled refresh-token grant; TypeScript
login-time renewal is disabled unless `autoRefresh: true` is requested. Kotlin
and Swift retain single-flight refresh from `accessToken()` and are documented as
the native-mobile interface divergence in the registry.

`logout` notifies the authorization server so refresh tokens and server-side
sessions are revoked, then clears local state even if the request fails. It is
distinct from `clear`, which only drops local tokens and account context. The
caller can therefore forget a local copy without claiming the server session
ended.

The short-lived login transaction is persisted through a caller-suppliable
state store. The shipped in-memory store is for development and single-process
examples only; a multi-worker deployment must supply a durable implementation
with atomic take semantics.

### L3 Entitlement

The commercial surface is a first-class citizen, not a raw JSON blob. See
section 4.

### Preferences

Presentation preferences such as locale and theme survive a handoff into and out
of hosted login.

## 4. Entitlement is a first-class citizen

A caller must never need to know the wire shape of a commercial entitlement to
decide whether a feature is available. Concretely:

1. **Three states, not two.** `not_activated`, `inactive`, and `active` are
   distinct. A presence check cannot tell them apart, so presence is not a
   licence.
2. **Time semantics belong in the SDK.** `commerce.EntitlementSnapshot.effective()`
   requires `Active && !before(EffectiveAt) && !after(ExpiresAt)`. An SDK that
   only reports "an entitlement exists" reports a lapsed subscription as
   available. The boundary is second-exact, and
   [`entitlement.json`](../ops/build/sdk-conformance/entitlement.json) pins
   `expires_at - 1`, `expires_at`, and `expires_at + 1` precisely because an
   off-by-one there silently grants a dead subscription.
3. **Typed keys.** `FeatureKey` and `LimitKey` ship as SDK constants generated
   from `commerce/models.go`. A caller never compares raw strings.
4. **`inactive_reason` is presentation-only.** It never drives retry or
   authorization behaviour, mirroring the oracle-safe discipline in AGENTS.md §3:
   distinct internal causes must not produce distinct client behaviour.
5. **Lookups on an inactive entitlement return not-granted**, never the stored
   value, and an absent entitlement is never treated as unlimited.

### The SDK is never the authority

The server evaluates entitlements independently and owns every authorization
decision. SDK-side entitlement data exists for experience only: hiding a control,
failing early with readable text, and telling the user what to upgrade to. A
client that ships an entitlement check as a security control has misread the
boundary.

A cached entitlement must not be reused for gating past its own `effective_at`.
`revision` is the invalidation key.

## 5. Commercial credentials are four distinct things

Conflating these is the most common integration error, so the SDK keeps them
separate and never reuses one for another.

| Credential | Gates | Lifetime | Storage |
|---|---|---|---|
| `license_key` | first product-to-tenant binding | **one-time** | caller input, never persisted |
| `invitation_code` | same, invitation channel | one-time | caller input, never persisted |
| `client_secret` | token issuance for one client | long-lived | KMS, env, or a secret manager |
| `entitlement_file` | paid features in an offline or air-gapped deployment | contract term | read-only mount |

`license_key` and `invitation_code` are bootstrap credentials. They are sent in
an HTTPS request body, never stored in login state, never placed in the state
store, and never included in a redirect. After the first claim the stored
binding is used and the credential is not requested again.

`client_secret` is supplied through a credential provider, not as a field on a
client or options struct, so it stays out of `Debug` output, out of configuration
snapshots, and can be rotated without a code change.

### The entitlement file is verified locally

`docs/commercial-model.md` requires that offline and private deployments gate
paid features from a signed file, and that authentication never calls a vendor
licensing service on a login path. That second clause is only satisfiable if the
SDK can verify the file itself: without a local verifier, an air-gapped
deployment has to call `/api/v1/me/account-context`, which puts the vendor on the
login path and violates the rule.

So the SDK verifies the file with **Ed25519** — the same algorithm family the
server signs tokens with, so there is no second cryptography to reason about.
`LicenseTrust::vendor_pinned` is the slot for Snaplink's own root. In the
current build it reports `TrustUnconfigured` rather than carrying a placeholder
key: a hardcoded constant that verifies nothing would read as vendor authority
while granting nothing. A release populates it from the real key.

`license_file.json` pins the verification contract. In particular a verification
failure is never downgraded to an active or free-tier entitlement, and an
unsupported algorithm is rejected before signature verification, so `alg=none`
and friends are refused rather than tolerated.

## 6. Errors

Every protocol failure carries the server error code verbatim in all five
hosted-login SDKs, so a caller can branch on `activation_invalid` or
`insufficient_scope` in any of them. A caller branches on `code`, never on
`description`, which is human-facing and may be reworded. Oracle-safe
collapsing is preserved end to end: one classification per wire code, not per
internal cause.

[`errors.json`](../ops/build/sdk-conformance/errors.json) pins that contract
and every SDK consumes it. A failure response that carried no usable code is
reported with the SDK-originated `sdk_response_unclassified` and the response's
own status: the SDK never invents a server code for such a response, and never
leaves the code empty, because an unreadable 500 that looked like a terminal
`invalid_grant` would be a retry decision made on a guess. A failure detected
before any request keeps the code `invalid_request` with status 0; it is
distinguishable from a server code by that zero status, and renaming it would
break every call site in every language, so the exception is recorded in the
fixture rather than tolerated silently.

The vocabulary is the controlled union of [`docs/error-codes.md`](../docs/error-codes.md)
plus the SDK-originated `license` and `sdk` classes. Adding a case to the
fixture is a contract change, not a test-data edit.

## 7. Conformance fixtures

[`ops/build/sdk-conformance/`](../ops/build/sdk-conformance) holds one fixture per
cross-language contract, consumed by every SDK:

| Fixture | Pins |
|---|---|
| `entitlement.json` | the three states and the second-exact expiry boundary |
| `errors.json` | the controlled error vocabulary, the unclassified-response fallback, and the pre-flight exception |
| `transport.json` | normalized request and response shape |
| `license_file.json` | signature verification outcomes and the no-downgrade rule |

A capability may only be declared `present` in a language once that language
passes the fixtures for the layers it claims. This is the only mechanism that
stops time semantics, error classification, and verification outcomes from
drifting apart silently between five implementations.

## 8. Interface conventions

Options are layered, not flat. Required identity sits at the top level;
presentation hints, protocol hints, and development escape hatches are separate
nested structures, and the last group is named so that enabling it is visible at
the call site. Secrets never live in an options struct.

Results prefer a single outcome type with convenience accessors over a closed
enum every call site must destructure, and login state lives on an explicit
session object rather than as hidden pending state on a long-lived client.

## 9. Versioning

| Change | Version |
|---|---|
| Generated operation or optional field added | additive, patch |
| Capability id added to the paradigm registry | additive, minor |
| Capability id dropped, or `parity` downgraded to `divergent` | **breaking**, minor (pre-1.0) |
| Paradigm-level API break, such as the Rust transport becoming a trait | **breaking**, minor (pre-1.0) |
| Symbol moved behind a present declaration | no version change; the gate forces the registry edit |

Package publication is an external boundary driven by the per-language SDK
workflows and that package's matching version tag. SDK package versions are
independent: this gate validates each manifest's SemVer and local lockfile
consistency without requiring a synchronized release train. They are separate
from the Snaplink server/module version and the OAuth/OIDC protocol version.
`cli.py sdk-surface versions` audits seven fixed SDK identities: TypeScript,
Python, Rust, PHP, Kotlin, Swift and Go. SwiftPM and Go derive release versions
from tags rather than manifest version fields. The Go SDK is the independent
`sdks/go` module, released through its own `sdks/go/v<version>` tag boundary;
central identity/directive validation does not transfer publication ownership to
the root module. The gate runs inside `sdk-surface check` and `make ci`.

## 10. Implementation waves

The registry's `missing` entries name the wave that closes each gap.

| Wave | Scope |
|---|---|
| W1 | this document, the registry, the parity gate, the four fixtures |
| W2 | L3 Entitlement: typed `LicenseState` and entitlement keys, local entitlement-file verification, preference handoff for the remaining SDKs |
| W3 | L2 Session: explicit `refresh` and `logout` across hosted-login SDKs; local-only `clear`; mobile refresh remains documented separately |
| W4 | L0 Transport: one injectable async-first seam, native async composition |
| W5 | L1 ApiClient: extend the generator to the remaining SDKs |

### Progress

| Capability | go | TypeScript | Python | Rust | PHP |
|---|---|---|---|---|---|
| `session.refresh` | done | done | done | done | done |
| `session.logout` | done | done | done | done | done |
| `session.clear` | done | done | done | done | done |
| `entitlement.typed_keys` | done | done | done | done | done |
| `entitlement.license_file` | done | done | done | done | done |
| `preferences.handoff` | done | done | done | done | done |
| `transport.injection` | done | done | done | done | done |
| `runtime.native_async` | done | done | done | n/a | done |

This progress table covers the five hosted-login SDKs (Go, TypeScript, Python,
Rust, and PHP). Kotlin and Swift are registered native SDKs still onboarding;
their refresh-on-access behavior is intentionally distinct for now.

`python cli.py sdk-paradigm list` is the live version of this table.

### Swift source/declaration audit (cycle-02, not native acceptance)

Swift stays `onboarded:false`; the eight parity capabilities and all shared
fixture assertions are unchanged. The two internal-only injection seams are now
`missing`, correcting declaration coverage from 102/112 to 100/112 across all
languages. This is a claim correction, not removed Swift functionality.
All 16 Swift dispositions below are source audit only; **native/Apple, Keychain,
browser, external-consumer and package acceptance were not executed this cycle**.
Paths below are under `sdks/swift/`; registry notes name exact full paths.

| Capability | Declaration | Actual source and remaining boundary |
|---|---|---|
| `transport.injection` | missing | `Sources/Errors.swift` has internal `OAuthTransport`; injecting initializers in `Sources/SnaplinkAuthClient.swift` are not public. A reviewed public seam/consumer validation is future work. |
| `session.start` | present, unchanged | Public begin/callback source in `SnaplinkAuthClient.swift`; `Tests/SnaplinkAuthClientTests.swift` exists, not execution proof. |
| `session.state_store` | missing | `Errors.swift` protocol and injecting initializers are internal; only the configuration initializer is public. `@testable` is not caller injection. |
| `session.memory_state_store` | missing | Keychain ships; private `MemorySecureStore` is test-only, not a public store. |
| `session.access_token` | present, unchanged | Public async `accessToken()` can refresh near expiry; not an unconditional local query. |
| `session.is_logged_in` | missing | No dedicated local/no-network query; `accessToken()`/`currentSession()` may refresh. |
| `session.clear` | missing, validation debt | Public `clear()` source exists; `SnaplinkAuthClientTests.testClearDropsLocalSessionAndPendingTransactionWithoutRevocation` exists. Native lifecycle/security review remains. |
| `session.logout` | present, unchanged | Source clears locally first, then attempts server revocation; adjacent failure tests exist. |
| `session.refresh` | present, unchanged | Implicit refresh through `accessToken()` and a per-instance single-flight task; not explicit hosted-login refresh. |
| `entitlement.setup` | missing, validation debt | Public setup/pending-ticket claim exists; `SnaplinkAuthClientTests` and `CommerceTransportTests` contain cases. |
| `entitlement.account_context` | missing, validation debt | Public bearer-bound account read exists with adjacent client/wire test source. |
| `entitlement.typed_keys` | missing, validation debt | `Sources/Entitlement.swift` has public typed models; `Tests/EntitlementConformanceTests.swift` references fixtures, not a native PASS. |
| `entitlement.license_file` | missing, validation debt | `Sources/LicenseFile.swift` has local CryptoKit verification and caller trust; `Tests/LicenseFileConformanceTests.swift` exists. No vendor network requirement is inferred. |
| `preferences.handoff` | missing | `PresentationPreferences.swift` has `buildLoginHandoff` and adjacent tests; it is **not wired** into actual authorization URL construction. |
| `runtime.native_async` | present, unchanged | Public actor/async source exists; no native runtime acceptance this cycle. |
| `session.authorization` | missing | No assembled typed identity/permissions/roles/menu API; commerce/preferences helpers are not authorization aggregation. |

Python declaration/source regression tests check these specific boundaries only;
they are not a Swift parser or execution of Swift conformance fixtures.

The whole L3 entitlement layer is complete across all five hosted-login SDKs and verified
against one shared fixture per contract, so the expiry boundary, the
inactive-lookups-grant-nothing rule, and the never-downgrade-a-rejected-file
rule cannot drift between implementations.

Signature checking is the one primitive each language takes differently, and
each takes it the way its ecosystem allows:

| SDK | How it verifies | Why |
|---|---|---|
| Go | directly, `crypto/ed25519` | stdlib, no reason to abstract |
| Rust | directly, `ed25519-dalek` | the crate already depends on RustCrypto-adjacent crates |
| Python | injected `LicenseVerifier` callable | the package is stdlib-only by design and the stdlib has no Ed25519 |
| TypeScript | injected `LicenseVerifier`, `verifyLicenseFile` is async | WebCrypto Ed25519 is still unevenly deployed; async allows it or `@noble/curves` with no dependency |
| PHP | injected callable, with `sodiumVerifier()` when `ext-sodium` is loaded | no hard extension requirement |

The envelope, the algorithm and version gate, the key-id lookup, the
no-downgrade policy, and the three-state classification are identical everywhere
and are what the fixtures pin.

The presentation handoff is complete across all five hosted-login SDKs. Each one
builds the same `presentation_locale` / `presentation_theme_mode` pair from an
explicitly changed patch, and each hosted-login builder accepts that pair on the
login request while replacing a stale value inherited from the login-page URL.
An omitted field stays omitted, so a handoff never clears a stored preference the
application did not mean to touch.

The W2 wave is therefore closed for the five hosted-login SDKs, and every one of
them now has a single injectable transport seam. Python's seam is emitted by
`cmd/gensdk` so the generated client and the hosted-login facade share it, and
its default implementation refuses to follow redirects.

The remaining declared gap is `runtime.native_async` for PHP, and it is a
reviewed decision rather than an oversight. PHP has no native concurrency in the
language: a fiber is cooperative and adds no I/O concurrency, so an async
surface would mean taking an event-loop dependency this package deliberately
does not take. `transport.injection` already lets a caller on ReactPHP or Amp
supply their own transport; claiming async on that basis would advertise a
synchronous facade as an asynchronous one, which is the exact defect the
capability exists to prevent.
