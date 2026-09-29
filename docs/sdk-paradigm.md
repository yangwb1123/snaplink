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

| Layer | Scope | Registry | Languages | Gate |
|---|---|---|---|---|
| **L1 ApiClient** | 321 operations in 13 groups | `ops/build/sdk-surface.json` | TypeScript, Python | `cli.py sdk-surface check` |
| **L0–L3 hand-written** | transport, session, entitlement, preferences, runtime | `ops/build/sdk-paradigm.json` | all five | `cli.py sdk-paradigm check` |

A language is released as a package only if it appears in
`ops/scripts/sdk_versions.py`; the paradigm gate requires every such package to
declare a language entry, so a new published SDK cannot ship ungoverned. Go is
declared with `package: false` because it is versioned by the root module.

## 2. Capability declaration

Each capability is a `layer.id` pair with a `parity` and one declaration per
language.

- `parity: "parity"` — every language must be `present`. A `missing` entry is a
  gate failure. This is the ratchet: the six parity capabilities are the floor
  that must not erode.
- `parity: "divergent"` — gaps are permitted, but every `missing` entry must name
  the wave that closes it, so drift has an owner.

A `present` entry names the exact file and the exact symbol text that provides
it; the gate reads the file and fails if the symbol is not there. Renaming a
symbol without updating the registry fails the build, which is the intended
behaviour: it forces a deliberate edit. A `missing` entry must not name a file
or symbol, so a gap can never be half-declared.

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

Explicit lifecycle: start, refresh, logout. `refresh` is a first-class operation
in every SDK, because an access token that cannot be renewed forces a full
re-login on expiry. Automatic renewal is an opt-in decorator, never the default:
an implicit refresh makes "which request fired, and when" unobservable, which
costs both test determinism and debuggability.

`logout` notifies the authorization server so refresh tokens and server-side
sessions are revoked. It is distinct from `clear`, which only drops local state.
An SDK that offers only one of the two is a defect: the caller must be able to
forget a token locally without pretending the server session ended.

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

Every protocol failure carries the server error code verbatim. Only TypeScript
and Python currently do this; a caller in Go, Rust, or PHP cannot branch on
`activation_invalid` or `insufficient_scope` at all, which is a defect and not a
simplification.

The vocabulary is the controlled union of `docs/error-codes.md` and the
SDK-originated `license` class, pinned by
[`errors.json`](../ops/build/sdk-conformance/errors.json). A caller branches on
`code`, never on `description`, which is human-facing and may be reworded. Codes
the SDK originates are namespaced by class so they are never confused with server
codes. Oracle-safe collapsing is preserved end to end: one classification per wire
code, not per internal cause.

## 7. Conformance fixtures

[`ops/build/sdk-conformance/`](../ops/build/sdk-conformance) holds one fixture per
cross-language contract, consumed by every SDK:

| Fixture | Pins |
|---|---|
| `entitlement.json` | the three states and the second-exact expiry boundary |
| `errors.json` | the controlled error vocabulary and its classification |
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
workflows and a matching version tag. `cli.py sdk-surface versions` reads the
four package manifests and runs inside `sdk-surface check` and `make ci`.

## 10. Implementation waves

The registry's `missing` entries name the wave that closes each gap.

| Wave | Scope |
|---|---|
| W1 | this document, the registry, the parity gate, the four fixtures |
| W2 | L3 Entitlement: typed `LicenseState` and entitlement keys, local entitlement-file verification, preference handoff for the remaining SDKs |
| W3 | L2 Session: `refresh` and `logout` in every SDK, explicit session objects, layered options |
| W4 | L0 Transport: one injectable async-first seam, native async composition |
| W5 | L1 ApiClient: extend the generator to the remaining SDKs |

### Progress

| Capability | go | TypeScript | Python | Rust | PHP |
|---|---|---|---|---|---|
| `entitlement.typed_keys` | done | done | done | done | done |
| `entitlement.license_file` | done | done | done | done | done |
| `preferences.handoff` | missing | done | done | done | missing |

`python cli.py sdk-paradigm list` is the live version of this table.

The whole L3 entitlement layer is complete across all five SDKs and verified
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

The remaining W2 gap is `preferences.handoff` in Go and PHP, which is cosmetic
next to the session work.
