# Protocol Review — Token-Exchange Hop-Policy Operational Loop (RFC 8693 conformance trace)

**Review basis:** `docs/auto/domains-tokenexchange-design.md` against current code
at HEAD `9606997b` (design stage — no implementation landed). Claims labeled
**Verified** (confirmed in the tree this revision), **Proposed** (design intent,
not yet implemented), **Missing** (design does not address it), or **Unknown**.
Checks actually run: source inspection and targeted greps of
`internal/handler/tokengrant/`, `interfaces/sso/server_token.go`,
`interfaces/sso/server_discovery_{config,cache}.go`, `domains/tokenpolicy/`,
`protocols/oauth/{txntoken,oauthwire}/`, `shared/core/`, `docs/openapi.yaml`,
`docs/error-codes.md`, `docs/feature-matrix.md`, and the `test/` token-exchange
suites. No `go test` run this revision (nothing to build yet); the QA review's
PASS results for the existing suites are cited as supplementary.

The design's own scope statement is accurate: it introduces **no new
OAuth/OIDC wire surface** — the `/token` exchange behavior, error collapse, and
response shape stay byte-identical; the new surface is the admin-management
plane (`GET/PUT /api/v1/admin/tokenexchange/policies`), which is outside the
RFC 8693 wire contract but is reviewed here for its *interaction with* that
contract (what the policy can see and block, and whether it can be silently
evaded or inert).

---

## 1. Protocol/profile scope and authoritative references

| Surface in design | Standard in scope | Governing reference | Reference points in tree |
|---|---|---|---|
| Token-exchange grant at `/token` | OAuth 2.0 Token Exchange | RFC 8693 §2.1 (request), §2.2.1 (response), §3 (token-type URIs), §4.1/§4.1.1 (`act` chain), §4.4 (`may_act`), §4.5 (errors) | `internal/handler/tokengrant/token_exchange.go`, `token_exchange_stages.go` |
| Base token endpoint | OAuth 2.0 | RFC 6749 §2.3.1 (client auth), §3.3 (scope), §5.1 (no-store), §5.2 (errors) | `interfaces/sso/server_token.go` |
| Resource indicators | OAuth 2.0 Resource Indicators | RFC 8707 §2 | `protocols/oauth/oauthwire/token_exchange_helpers.go` (`MergeTargets`) |
| JWT-Profile access tokens | JWT Profile for OAuth 2.0 Access Tokens | RFC 9068 §2.2 | `shared/core/types_token.go` (`Subject`), `domains/tokenexchange/chainstore.go` (`jti`) |
| Sender-constrained tokens | DPoP / mTLS | RFC 9449 §5, RFC 8705 §2 | `tokExResolveSubject` cnf-continuation, `captureSenderConstraint` |
| Step-up authentication | OAuth 2.0 Step-Up | RFC 9470 §3 | `tokExStepUp` (`acr_values`) |
| Rich authorization requests | OAuth 2.0 RAR | RFC 9396 §3/§5 | `tokExSubject` (`AuthorizationDetails` propagation) |
| Transaction Tokens | RFC 9321 (reuses the token-exchange grant) | §2.1/§3 | `protocols/oauth/txntoken/`, `dispatchTokenExchangeOrTxnToken` |
| Authentication Method Reference | RFC 8176 | AMR values | `tokExResolveSubject` (SPIFFE `amr=spiffe`), `tokExIssueRefresh` |
| Discovery | OIDC Discovery / RFC 8414 | `grant_types_supported` | `server_discovery_cache.go:47` (`baseAdvertisedGrants`), `TestTokenExchange_DiscoveryAdvertisesGrant` |
| New admin endpoints (design) | None (management plane) | Internal contract: AGENTS.md §3, admin middleware | `interfaces/admin/middleware.go`; proposed `tokenexchange_policies.go` |
| New matching dimensions (design) | None (operator DSL over RFC 8693 request values) | Internal contract; `tokenpolicy` selector precedent | `domains/tokenpolicy/evaluate.go` (`scopePresent`) |

Profile posture: the server implements the token-exchange grant as a
confidential-client, server-to-server profile with the RFC 8693 mandatory
parameters plus deliberate extensions (RFC 8707 `resource` merged with
`audience`; RFC 9470 `acr_values`; RFC 9321 txn-token over the same
`grant_type`). The design adds an operator policy layer that observes **resolved
request dimensions only** and never alters the wire contract.

---

## 2. Compliance matrix

Status: **V** = Verified in tree this revision · **P** = Partial (verified with
caveat) · **D** = Deviation (deliberate, documented) · **M** = Missing ·
**Proposed** = design intent, not implemented.

### 2.1 Current wire behavior (baseline the design must not change)

| § | Requirement (level) | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| RFC 8693 §2.1 | `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` routed to the exchange handler | `dispatchTokenGrant` switch (`server_token.go:190`) | V | — | `handle_token_exchange_test.go` |
| RFC 8693 §2.1 | `subject_token` + `subject_token_type` REQUIRED; missing → error | `tokExValidateRequestTypes` → `400 invalid_request` | V | — | `TestTokenExchange_MissingSubjectTokenIsInvalidRequest` |
| RFC 8693 §3 | `subject_token_type` restricted to supported URIs | accepts `access_token`, `jwt`, `id_token` only; `refresh_token`, SAML1/SAML2 → `400 invalid_request` | V | `refresh_token` listed in OpenAPI enum but **rejected** (finding F3) | `TestTokenExchange_BadSubjectTokenRejected` |
| RFC 8693 §2.1 | `actor_token`/`actor_token_type` both-or-neither | `tokExResolveActor` → `400 invalid_request` | V | — | `TestTokenExchange_ActorTokenWithoutTypeRejected` |
| RFC 8693 §2.1 | `requested_token_type` restricted to supported URIs; unsupported → error | `tokExValidateRequestTypes`: `access_token`, `refresh_token`, `id_token` accepted; SAML1/2 → `400 invalid_request` | V | `id_token` accepted but **omitted** from OpenAPI enum (F3); txn-token intercepted before this gate | `TestTokenExchange_UnsupportedRequestedTokenTypeRejected`, `TestTokenExchange_IDTokenOutput` |
| RFC 8693 §2.1 | `scope` MUST NOT expand beyond the subject_token's scope | `tokExResolveScope`: non-subset → `400 invalid_scope` | V | Stricter-than-`SHOULD` posture, safe direction | `TestTokenExchange_ScopeExpansionRejected`, `TestTokenExchange_ScopeNarrowing` |
| RFC 8693 §2.1 | Empty requested scope on a scope-less subject must not inherit the client's allowlist | `tokExResolveScope` returns nil scopes | V | Anti-escalation hardening | `TestTokenExchange_EmptyScopeDoesNotWidenToAllowlist` |
| RFC 8693 §2.1 / RFC 8707 | `audience` / `resource` targets validated against client allowlist | `MergeTargets` + `AreResourcesAllowed` → `400 invalid_target` | V | D: `resource`+`audience` merged (documented in OpenAPI) | `TestTokenExchange_ResourceAllowlistEnforced`, `TestTokenExchange_MergesResourceAndAudience` |
| RFC 8693 §2.2.1 | Response carries `access_token`, `issued_token_type`, `token_type`; `expires_in` | `st.resp` assembly in `HandleTokenExchangeGrant` | V | — | `TestTokenExchange_HappyPath` |
| RFC 8693 §2.2.1 | `issued_token_type` reports the effective requested type | access default; overridden to `refresh_token` / `id_token` | V | id_token output is non-exclusive (access token still returned) — pinned, documented interpretation (F8) | `TestTokenExchange_IDTokenOutput` |
| RFC 8693 §2.2.1 | `requested_token_type=refresh_token` mints a refresh token | `tokExIssueRefresh` (fail-open; access token always returned) | V | — | `TestTokenExchange_ReturnsRefreshTokenWhenRequested` |
| RFC 8693 §4.1 | `act` claim stamped on the issued token when an actor_token is presented | `tokExSubject` (`Actor`) | V | — | `TestTokenExchange_ActorTokenStampsActClaim`, `TestTokenExchange_NoActorTokenNoActClaim` |
| RFC 8693 §4.1.1 | `act` chain nesting preserved/prepended across hops | `tokExResolveActor` prepend + `tokExActorChainHasCycle` | V | D: depth capped at 10 (`MaxActChainDepth`) — hardening beyond the RFC (F6) | `TestTokenExchange_ActorChainNestsAcrossMultipleHops`, `TestTokenExchange_ActorChainCycleRejected` |
| RFC 8693 §4.4 | `may_act` constraint from the subject_token | `tokExValidateActor` → `400 invalid_grant` | V | Oracle-safe collapse | `TestTokenExchange_ActorChainSurvivesValidate` |
| RFC 8693 §4.5 | Client's registered `grant_types` restriction | `rejectDisallowedGrantType` → `400 unauthorized_client` | V | — | `admin_http_clients_test.go` family |
| RFC 6749 §2.3.1 | Client auth: Basic beats body; private_key_jwt; mTLS; public `client_id` | `authenticateTokenClient` | V | — | `handle_token_exchange_test.go` harness |
| RFC 6749 §5.1 | Credential endpoint no-store headers | `tokenNoStoreHeaders` set before any body | V | — | `bearer_challenge_test.go` |
| RFC 9449 §5 / RFC 8705 | Exchanged token MUST NOT drop the subject's sender constraint | `tokExResolveSubject` cnf-continuation (presence-only guard) → `400 invalid_grant` | V | — | `TestTokenExchange_DPoPBoundSubject_NoProofRejected` |
| RFC 9470 §3 | `acr_values` step-up demand | `tokExStepUp` → `400 insufficient_user_authentication` | V | Distinct code, uniform across grants | `acr_test.go` |
| RFC 9396 §3/§5 | `authorization_details` preserved across the exchange | `tokExSubject` (`CloneRawJSON`) | V | — | `token_exchange_rar_test.go` |
| RFC 9068 §2.2 | `jti`/auth-context propagation on issued JWT access tokens | `Subject` claim sources; `ChainHop.JTI` | V | — | `token_exchange_chain_store_test.go` |
| OIDC §8 | Pairwise subject resolution/re-application on exchange | `tokExResolveSubjectAndIssue` | V | — | pairwise suite |
| RFC 8414 §2 | Discovery advertises only supported grants | `grant_types_supported` always includes token-exchange; device_code/CIBA conditional | V | RFC 8693 defines **no** discovery extension, so nothing further is required | `TestTokenExchange_DiscoveryAdvertisesGrant` |

### 2.2 Design deltas (Proposed)

| § | Requirement (level) | Design behavior | Status | Deviation / note |
|---|---|---|---|---|
| Policy gate position | Internal invariant: last gate before minting, after scopes/resources resolution | `tokExEnforcePolicy` unchanged position (after `tokExResolveTargetsAndScopes`, before issuance) | V (position) / Proposed (dimensions) | Consistent with the design's oracle-safety claim |
| Oracle collapse | AGENTS.md §3: policy deny/error → identical `400 invalid_grant` | Unchanged | V | Deny-vs-error byte-identity already collapsed; no new wire code |
| Decision 3 `Scopes` | ALL-of + trailing-`"*"` wildcard, empty = wildcard | Proposed; matches `tokenpolicy.scopePresent` semantics exactly (V precedent) | Proposed | Matches the FINAL narrowed set only (F7); scope-less hops never match a scoped rule |
| Decision 3 `Resources` | ANY-of + wildcard over merged resource+audience | Proposed | Proposed | Rules cannot distinguish `resource` vs `audience` form, and only see allowlisted targets (F4) |
| Decision 3 `RequestedTokenType` | exact match, empty = wildcard | Proposed | Proposed | Raw request value, not the RFC 8693 §2.2.1 effective type (F2); rule URIs not validated at ingest (F5) |
| txn-token interaction | RFC 9321 hops reuse the token-exchange grant | **Missing** — design never states policy coverage; verified the txn-token path bypasses the policy entirely (F1) | M | `dispatchTokenExchangeOrTxnToken` routes to `txntoken.HandleGrant` before `HandleTokenExchangeGrant`; contrast: the tokenpolicy engine (`denyTokenScopeCombo`) runs at dispatch level and **does** cover txn-token |
| Admin API | New endpoints are management-plane, no RFC mapping | `GET/PUT /api/v1/admin/tokenexchange/policies` | Proposed | No /token wire impact; codes `invalid_request`/`internal_error` do not collide with RFC 8693 §4.5 codes |
| Enforcement continuity | Deny rules must survive restart (sqlite backend) | Boot load + E2E restart plan | Proposed | Protocol-relevant: enforcement is a property of the mint path, unchanged on the wire |
| OpenAPI/error-codes | Docs must match wire | Contract-updates list touches `openapi.yaml` + `error-codes.md` | Proposed | Must also fix the three pre-existing drifts in F3, or `make ci`'s kin-openapi step stays green but the docs lie |

---

## 3. Findings

### F1 — High · Requirement: RFC 8693 grant family coverage (design gap, "Missing") — txn-token hops bypass the policy entirely

**Evidence (Verified):** `dispatchTokenExchangeOrTxnToken`
(`interfaces/sso/server_token.go:211-219`) routes
`requested_token_type=urn:ietf:params:oauth:token-type:txn-token` to
`txntoken.HandleGrant` **before** `HandleTokenExchangeGrant` is ever called;
`protocols/oauth/txntoken/` contains no reference to `TokenExchangePolicy`
(grep'd). RFC 9321 mints txn-tokens under the **same** `grant_type` the design's
policy claims to govern, and the OpenAPI documents txn-token as "reus[ing] this
SAME token-exchange grant". The design's Decision 3 adds a `RequestedTokenType`
dimension and its failure-mode table but never states whether the policy covers
txn-token hops — the coverage is undefined, and the implemented reality is
"not covered".

**Impact:** an operator deny rule (subject/client/scope/resource based) that
appears to cover "all token exchanges" silently does not apply to txn-token
mints — the same class of silent gap the security review's F-2/F-5 flag for
config, but at the protocol layer. Conversely, an operator who *wants* to block
txn-token hops has no rule dimension that can. Note the inconsistency: the
tokenpolicy engine (`denyTokenScopeCombo`, `server_token.go:156`) runs at
dispatch level and **does** cover txn-token, so the two policy layers have
different coverage of the same grant family.

**Corrective behavior:** the design must pick one and say so explicitly:
(a) document "policy covers ordinary RFC 8693 exchanges only" in
`docs/config-reference.md` and the OpenAPI endpoint text, and reject
`requested_token_type: txn-token` rule values at ingest (see F5); or (b) invoke
the policy inside the txn-token grant path (or hoist the call to dispatch level,
matching `denyTokenScopeCombo`). Option (b) is the consistent one — the policy
is described as the hop-authorization gate for the grant.

**Validation:** unit test asserting a deny rule matching a txn-token request's
subject/client does not block (option a) or blocks (option b) a txn-token mint;
plus an ingest test that txn-token rule values are rejected under option (a).

### F2 — Medium · Requirement: RFC 8693 §2.2.1 effective-request semantics — `requested_token_type` rules match the raw value, not the effective type

**Evidence (Verified):** `tokExEnforcePolicy` passes `req.RequestedTokenType`
verbatim into `Hop.RequestedTokenType` (`token_exchange.go:373-401`); an empty
`requested_token_type` is legal and per RFC 8693 §2.2.1 the output is an
access token (`issued_token_type` defaults to access_token — verified in
`HandleTokenExchangeGrant`'s response assembly). Design Decision 3 matches
`RequestedTokenType` exactly with empty = wildcard, but does not normalize the
hop value.

**Impact:** with `default_allow: false`, an allow rule
`requested_token_type: urn:ietf:params:oauth:token-type:access_token` silently
denies requests that *omit* the parameter even though they produce exactly the
same access-token output; a deny rule on that URI silently misses the same
omitted-form requests. The rule DSL and the RFC's defaulting disagree, and the
operator has no way to express "any access-token-producing exchange".

**Corrective behavior:** normalize at the policy call site only —
`RequestedTokenType: req.RequestedTokenType`, or the access_token URI when
empty — before building the Hop. Wire-neutral (the /token request and response
are untouched); the matcher truth table must pin both the raw-empty and
normalized cases. If normalization is rejected, document the raw-value
semantics in the rule schema.

**Validation:** truth-table row: hop with empty `RequestedTokenType` matches a
rule naming the access_token URI iff normalization is applied; E2E:
`default_allow=false` + allow rule on access_token URI + omitted
`requested_token_type` → 200 (with normalization), 400 `invalid_grant` (without).

### F3 — Medium · Requirement: contract accuracy (OpenAPI/error-codes vs wire) — three pre-existing drifts the design's OpenAPI edit must fix

**Evidence (Verified):**
1. `subject_token_type` OpenAPI enum (`docs/openapi.yaml` TokenRequest) lists
   `urn:ietf:params:oauth:token-type:refresh_token`; `tokExValidateRequestTypes`
   rejects it (`400 invalid_request`).
2. `requested_token_type` OpenAPI enum lists `access_token`/`refresh_token`/
   `txn-token` but **omits** `urn:ietf:params:oauth:token-type:id_token`, which
   the handler accepts and `TestTokenExchange_IDTokenOutput` pins (200).
3. Refresh-output without a wired store: code emits **400
   `refresh_token_not_configured`** (`token_exchange_stages.go`, pinned by
   `TestTokenExchange_RejectsRefreshWithoutStore`), while
   `docs/error-codes.md:293` documents that code only as **501** for
   `grant_type=refresh_token`, and the OpenAPI `requested_token_type`
   description claims "else `invalid_request`".

**Impact:** doc-driven clients (SDKs generated from the OpenAPI, operators
reading the error table) encode behavior the server does not have; a generated
client that believes `refresh_token` is a valid subject type will always fail,
and one that believes id_token output is unsupported will never request it.
Interop-relevant only insofar as the docs are the certification-facing record.

**Corrective behavior:** in the same change that adds the admin endpoints to
`openapi.yaml`: drop `refresh_token` from `subject_token_type` (or implement it);
add the `id_token` URI to `requested_token_type`; add a 400
`refresh_token_not_configured` row for the token-exchange case in
`docs/error-codes.md` (the design's "no new error codes" claim stands — this is
an existing code, misdocumented).

**Validation:** extend the E2E refresh test's assertion to a docs-vs-wire check
or add a `TestOpenAPITokenRequestEnumsMatchHandler`-style consistency test;
`make ci` kin-openapi validation stays green.

### F4 — Medium · Requirement: RFC 8707/RFC 8693 target-vocabulary semantics — `Resources` ANY-of matches the merged set and only post-allowlist values

**Evidence (Verified):** the Hop's `Resources` is `st.resources` = the
`oauthwire.MergeTargets`-deduplicated union of `resource` and `audience`
(`token_exchange.go:197`), validated against `client.AreResourcesAllowed`
before the policy runs (`invalid_target` precedes `tokExEnforcePolicy`).
Design Decision 3's ANY-of semantics deliberately diverge from Scopes ALL-of
(defensive: exact equality would let a hop evade a deny by adding an unrelated
audience).

**Impact:** three consequences operators must be told, none of which the design
documents: (a) a rule naming an audience also matches the same value passed as
`resource` — the two vocabularies are indistinguishable in rules; (b) a resource
deny rule only ever fires for targets that already passed the client allowlist —
attempts against non-allowlisted targets die at `invalid_target` before the
policy, so the policy cannot be used as a detector for blocked attempts; (c)
ANY-of + merge means a deny on `[aud1]` also blocks hops carrying
`aud1` + unrelated audiences — the design's intended divergence, but the
"unrelated" set is only ever allowlisted values.

**Corrective behavior:** document all three in the rule schema
(`docs/config-reference.md` + OpenAPI admin schema description); the truth-table
tests must pin (a) resource-vs-audience equivalence and (c) the ANY-of
superset-match, so future "optimizations" cannot silently narrow the deny.

**Validation:** matcher truth table: rule `resources: [aud1]` matches hop with
`resources: [aud2, aud1]` and with `resource=aud1`-originated merge; E2E:
exchange with `audience=aud1` (denied) vs `resource=aud1` (denied) — identical
outcome.

### F5 — Low · Requirement: RFC 8693 §3 URI validation at ingest — typo'd `requested_token_type` rule values are inert

**Evidence (Verified design):** Decision 2/5 validation covers Name non-empty,
rule-count cap, and wildcard shape only; Decision 3 matches
`RequestedTokenType` exactly. Nothing validates a rule's `requested_token_type`
against the supported token-type URI set (access_token / refresh_token /
id_token; txn-token only under F1 option b).

**Impact:** a deny rule with a misspelled URI (`urn:...:token-type:access_tokne`)
never matches — a silently inert deny = widened allow, the same class the
security review's F-5 flags for boot-load rows, reachable through the *admin
API and YAML config* this design itself introduces.

**Corrective behavior:** in the shared `ValidateRules`, reject
`RequestedTokenType` values outside the server's supported set (constant list
in `consts.go`, same source of truth the handler's allowlist uses); apply to
PUT and YAML ingest; also reject txn-token under F1 option (a) with a message
pointing at the coverage decision.

**Validation:** PUT with `requested_token_type: "urn:ietf:params:oauth:token-type:access_tokne"` → 400, zero store mutation; config bundle with the same → boot error.

### F6 — Low · Requirement: deviation declaration — act-chain depth cap vs "arbitrary nesting" wording

**Evidence (Verified):** `MaxActChainDepth = 10` (`token_exchange_stages.go`),
enforced before prepend with `400 invalid_grant`; OpenAPI's
`issued_token_type` description says "RFC 8693 §4.1.1 permits arbitrary nesting
depth" without noting the server's cap. RFC 8693 leaves nesting unrestricted;
the cap is a hardening deviation (also bounds the policy-less hot path).

**Impact:** documentation accuracy only; a deep legitimate chain (>10 hops)
fails with the same `invalid_grant` as an invalid subject — oracle-safe, but an
operator debugging a refused 11-hop chain has no signal. (Pre-existing; the
design does not touch it, and does not need to beyond the OpenAPI edit.)

**Corrective behavior:** in the same OpenAPI edit, append "server-side cap: 10
hops" to the nesting note.

**Validation:** existing cycle/nesting tests already pin the cap behavior
(`token_exchange_chain_policy_test.go`).

### F7 — Info · Scope dimension observes the post-narrowing set only

**Evidence (Verified):** `tokExEnforcePolicy` runs after
`tokExResolveScope`; `st.scopes` is the final set (subject-subset +
client-allowlist narrowed), `nil` for scope-less subjects (id_token / SPIFFE /
scope-less access tokens). Design Decision 3's "hop set is a superset" is
accurate about *matching* but the docs must state the hop set is
post-narrowing, and that a scope-less hop can never match a scoped rule (empty
rule field = wildcard makes "match hops with no scopes" inexpressible).

**Impact:** operator surprise only; a deny rule on scope `admin:write` does not
and cannot detect a caller *attempting* scope expansion (that already dies at
`invalid_scope`). Consistent with the policy's second-layer role; document it.

### F8 — Info · id_token output interpretation is an implementation choice

**Evidence (Verified):** `tokExIssueIDToken` returns `issued_token_type=id_token`
while *also* returning the access token (non-exclusive output), pinned by
`TestTokenExchange_IDTokenOutput` with the comment "requested_token_type names
what issued_token_type reports, not the exclusive output". RFC 8693 §2.2.1's
member semantics for the id_token case are interpreted here deliberately.

**Impact:** interop with strict clients that treat `issued_token_type` as
exclusive could surprise; the OpenAPI documents the choice. Keep the
documentation and the test; list as an interpretation to re-verify against the
RFC text during any certification pass.

### F9 — Info · Discovery is complete for RFC 8693

**Evidence (Verified):** `grant_types_supported` always includes
`urn:ietf:params:oauth:grant-type:token-exchange`
(`server_discovery_cache.go:47`); RFC 8693 defines no discovery extension
(token-type capability advertisement is not specified), so no additional
metadata is required. The existing discovery test pins the advertisement.

---

## 4. Priority conformance tests, declared unsupported features, certification evidence

### Priority conformance tests (design stage — to land with the implementation)

1. **Matcher truth table** (`tokenexchange_test.go`): Scopes ALL-of +
   trailing-`"*"` hit/miss, partial-subset miss; Resources ANY-of superset hit
   (pin F4-c so a future ALL-of "optimization" fails); `RequestedTokenType`
   exact match **including the empty-vs-access_token-URI normalization row
   (F2)**; empty new fields ≡ old behavior; deny short-circuit.
2. **txn-token coverage test (F1)**: whichever decision lands, a test proving
   the policy's relationship to `requested_token_type=txn-token` mints, plus
   ingest rejection of txn-token rule values under option (a).
3. **`ValidateRules` URI validation (F5)**: bogus token-type URI → 400/boot
   error, store untouched.
4. **OpenAPI/wire consistency (F3)**: enums vs handler allowlists for
   `subject_token_type`/`requested_token_type`; 400 `refresh_token_not_configured`
   row in `error-codes.md`.
5. **E2E restart continuity**: admin PUT deny rule → exchange denied
   `invalid_grant` → close server → reboot same DSN → still denied (enforcement
   is a property of the mint path; the wire never changes).
6. **Oracle byte-identity**: deny-vs-eval-error byte-identical at `/token`
   (existing collapse, re-pinned).
7. **Discovery unchanged**: existing `TestTokenExchange_DiscoveryAdvertisesGrant`
   stays green.

### Declared unsupported (verified in code; document as such)

- `subject_token_type`: `refresh_token` (rejected; OpenAPI enum drift — F3),
  SAML1/SAML2 URIs (RFC 8693 §3), `txn-token` (only in the separate txn-token
  path), `device-secret` (actor-only).
- `actor_token_type`: only `access_token`, `jwt`, `device-secret`.
- `requested_token_type`: SAML1/SAML2 (`invalid_request`); `txn-token` only when
  `WithTransactionTokens` is wired.
- `may_act` chains deeper than 10 hops (hardening cap, F6).
- No RFC 8693 discovery extension (none is defined).

### Certification evidence

**None found — Unknown.** No OIDF certification result is published or cited
anywhere in the tree; `docs/feature-matrix.md` explicitly states "Implemented"
does not mean certified ("communication evidence is tracked" elsewhere, and the
tracking is not in this repository). This review claims no certification
status; the compliance matrix above is the current evidence base. The
implementation-specific interpretations flagged in F8 (id_token non-exclusive
output) are the items to re-verify against the RFC text before any
certification pass, alongside the F3 doc drifts.
