# Design: per-client redirect-URI patterns (`redirect_uri_patterns`)

Status: implemented in the current tree; this document remains the normative
grammar and security contract.

Scope: `shared/core` (the dependency-free leaf package — the pattern grammar,
validation, matching, normalization, Client field, and redirect allowlist gate),
`protocols/oauth` (+`oauthvalidate`, DCR wire + validation),
`config` + `cmd/sso-server` (static config), `infrastructure/defaultimpl/sqlite`
+ `infrastructure/postgres` (persistence), `docs/openapi.yaml` +
`docs/config-reference.md` (contracts), `docs/design/redirect-uri-patterns.md`
(this document), CHANGELOG.

Driver: the FAPI 2.0 conformance blocker recorded in
`docs/campaigns/reports/b12-fapi-conformance.md` + the archived
`test/oidc-conformance/results/07832dda-fapi/BLOCKER.md`. The OIDF FAPI2 SP
FINAL server tests hardcode a STATIC client (the plan exposes no
`client_registration` variant) whose callback redirect is generated per test
instance — `CreateRedirectUri` builds `base_url + /callback` over
`https://localhost:8443/test/{testId}` (observed in the archive:
`redirect_uri: https://localhost:8443/test/R7bzpU0mqX8Rghe/callback`). Snaplink's
`Client.IsRedirectURIValid` is an exact-match allowlist (`slices.Contains`), so
such a client can never be pre-registered. The product-level unblock chosen here
is opt-in per-client redirect-URI **patterns**: a client may register
`https://localhost:8443/test/*/callback` so the per-test callback validates
while the exact-match default stays byte-identical.

The six design questions the task demands adjudicated:

## Decision 1 — Data model

`core.Client.RedirectURIPatterns []string` (JSON/YAML `redirect_uri_patterns,
omitempty`), a **separate list, parallel to and independent of the exact
`RedirectURIs` allowlist**. A redirect_uri is valid when it exactly matches any
`RedirectURIs` entry **or** satisfies any `RedirectURIPatterns` entry
(OR-semantics, documented in the field comment + this design). **Zero patterns =
the exact-match allowlist only — byte-identical to the pre-feature behavior.**

| Surface | Field/key |
|---|---|
| `core.Client` | `RedirectURIPatterns` |
| DCR request (`DCRRequest`) | `redirect_uri_patterns` — **snaplink extension**: RFC 7591 §2 has no such attribute, so the name is explicitly non-standard and documented as such in the OpenAPI + config-reference rows |
| DCR response / GET / PUT echo (`DCRResponse`) | `redirect_uri_patterns` |
| DCR validation (`oauthvalidate.DCRMetadata`) | `RedirectURIPatterns` |
| Static config (`config.ClientConfig`) | `clients[].redirect_uri_patterns` → seeded into `core.Client` |
| Persistence | sqlite `clients.redirect_uri_patterns` (migration v8, JSON-array TEXT like `redirect_uris`), postgres `clientSchemaV6` `ADD COLUMN IF NOT EXISTS`; memory + redis round-trip the whole `Client` JSON so no change |

Relationship to RFC 7591's `redirect_uris` requirement: the wire contract is
unchanged — `redirect_uris` remains REQUIRED for `authorization_code` flow at
DCR (`validateRedirectURIs`), and patterns are strictly additive. A DCR client
therefore always carries at least one exact URI; static-config clients may be
patterns-only (config validation never required a non-empty exact list). This
keeps every existing DCR wire behavior byte-identical.

## Decision 2 — Pattern syntax (the security core)

The grammar lives in `shared/core` so every
provisioning surface (config boot, DCR register/update) and the runtime gate
(`core.Client.IsRedirectURIValid`) share **one canonical implementation**, and
it is fuzzable as a standalone unit.

### Accepted shape

```
pattern    = scheme "://" host [ ":" port ] path
scheme     = "https"                          (case-insensitive)
host       = hostname | IPv4 | "[" IPv6 "]"   (NO "*" — host wildcards rejected)
path       = "/" literal *( "/" segment )
segment    = literal | "*"                    ("*" = exactly ONE path segment)
```

Concrete rules (each is a validation error, fail-closed):

1. **Scheme is exactly `https`** (after lowercase). No `http`, even loopback —
   the loopback exception (`http://localhost`, `http://127.0.0.1`,
   `http://[::1]`) stays where it has always been: the **exact** `redirect_uris`
   allowlist, governed by the existing `safeRedirectURI` / `IsSecureRedirectURI`
   discipline. A pattern is a deliberately narrower, https-only affordance; a
   loopback pattern has no legitimate FAPI or production use.
2. **No userinfo** (`user:pass@host`), **no fragment**, **no query**. The
   FAPI callback is query-free, and forbidding query/fragment closes the
   encoding-bypass surface (a decoded `?`/`#` would otherwise change what the
   browser navigates to).
3. **No host wildcard.** Subdomain wildcards (`*.example.com`) are explicitly
   adjudicated OUT of scope for v1: host wildcards are where open-redirect
   blast radius explodes (any subdomain the operator happens to own becomes a
   valid redirect target, and squatting/typosquatting of near-hostnames is not
   a defense we can model). If a subdomain scenario is later needed it gets its
   own design review.
4. **`*` is a complete path segment only** — never partial (`cb*`, `*cb`,
   `a*b`) and never spanning (`**`, `a/*/b` is fine because `*` is exactly one
   segment). The candidate's matching segment must contain no `/` after
   percent-decoding (a decoded `/` would cross segment boundaries).
5. **Exactly one `*` per pattern** — the FAPI need is exactly one; a pattern
   with no wildcard is just an exact URI and belongs in `redirect_uris`, and
   more than one wildcard adds matching complexity with no product driver.
6. **`*` must be interior**: the FIRST path segment and the LAST path segment
   must be literals (this is the adjudication of "禁止无前缀裸 *" — a `*` with
   no literal path-segment prefix is rejected, and a trailing `*` that would
   match any suffix is rejected). The wildcard is therefore bounded by literals
   on both sides; the FAPI shape `https://localhost:8443/test/*/callback`
   satisfies this with literals `test` and `callback`.
7. **No percent-encoding in patterns**: a pattern containing `%` is rejected.
   Encoding belongs to the candidate side only, and the matcher handles it
   deterministically (Decision 2-Normalization). This keeps pattern literals
   unambiguous and closes `%2F`-style grammar smuggling.
8. **Literal segments use only RFC 3986 `pchar` characters**:
   `A-Z a-z 0-9 - . _ ~ : @ ! $ & ' ( ) * + , ; =` — plus the segment must be
   non-empty (no empty segments: no leading/trailing/double slashes) and must
   not be a dot segment (`.`, `..` — patterns must be written in canonical
   path form). Any other byte (whitespace, control chars, `%`, `?`, `#`, `/`,
   `\`) is rejected. (`*` as a whole segment is the wildcard; `*` inside a
   literal is a partial-wildcard and rejected.)
9. **No port ambiguity**: a port, when present, must parse as digits and must
   not be empty; `:443` on https is normalized away (equal to no port); any
   other explicit port must match the candidate's port exactly.

### Normalization (both sides, one function)

`Match(pattern, uri)` parses **both** the pattern and the candidate URI and
normalizes them identically before comparing:

1. `url.Parse` both; any parse failure, non-absolute result, userinfo,
   fragment, or (candidate only) query → **no match** (fail-closed).
2. Scheme lowercased; host lowercased (`u.Hostname()`); default port stripped
   (`https` + `:443` → none).
3. Path split on `/`; every segment percent-decoded (`PathUnescape`); a
   candidate segment whose decoded form contains `/`, `?`, `#`, `\`, or NUL is
   rejected (a decoded separator would change the browser-visible target);
   dot-segments (`.`, `..`) are removed AFTER decoding — the browser
   percent-decodes before resolving dot segments, so the normalized path is
   exactly what the user agent navigates to, and since dot-collapse can only
   REMOVE segments (an encoded `..` shrinks the count), a candidate that
   collapses below the pattern's segment count cannot match.
4. Compare: scheme equal, host equal, segment count equal, each literal
   position byte-equal, and the single `*` position accepts any one decoded
   segment.

Rationale for normalize-then-match: the candidate comes from the browser at
login time, where a case/encoding/port variant of the registered target is
common (case-insensitive hosts, `:443` vs default, percent-encoding). Matching
the normalized forms is exactly what the browser itself will navigate to, so a
normalized match is a real match — and the token exchange's existing exact-
string equality against the code-bound URI (`token_authcode.go`:
`info.RedirectURI != req.RedirectURI`) is the independent backstop that the
redirect target is bit-identical between login and exchange.

## Decision 3 — Validation timing

Every provisioning path rejects an invalid pattern at the earliest possible
moment (fail-closed, before any store write):

- **Static config (boot)**: `config.validateConfiguredClients` runs
  `core.ValidateRedirectURIPattern` on every `clients[].redirect_uri_patterns` entry →
  config validation failure (the same loud pre-deploy gate `sso-ctl config
  validate` enforces for every other client field). A malformed pattern never
  reaches the runtime matcher.
- **DCR `POST /register` and `PUT /register/:id`**: `validateRedirectURIs`
  (extended) validates every pattern entry → `400 invalid_client_metadata`
  (the existing DCR error envelope; the field name is named in the description).
- **Defense in depth**: `core.Client.IsRedirectURIValid` treats an unparseable
  pattern as never-matching (the matcher returns false) — a store row written
  by a pre-migration replica or a downstream fork can never widen the gate.

## Decision 4 — Security review

### Who may register a pattern (administration thresholds)

- **DCR**: patterns are accepted only on the RFC 7591 path — the endpoint is
  gated by the initial access token unless `allow_open_registration` is set.
  Open registration (the conformance harness's isolated-network setting) is
  the documented-unsafe exception; every production posture keeps DCR closed
  to the operator. A public registrant gaining `https://host/*`-shaped
  wildcards is not possible under the grammar anyway (no host wildcards, `*`
  bounded by literals) — the worst a malicious registrant can express is
  exactly what they already could with exact URIs, minus one path segment of
  variance on their own declared host.
- **Static config**: operator-edited YAML, validated at boot (Decision 3) —
  same trust domain as `redirect_uris` today.

### Post-match semantics (OAuth invariants preserved)

- A matched redirect_uri flows through the EXACT same pipeline as an exact
  match: it is bound to the issued auth code, the browser is redirected there,
  and `/token` re-checks byte-equality against the code-bound string — a
  pattern can never mint a code for a URI that was not validated at login.
- PKCE is orthogonal and untouched: `RequirePKCE` / challenge capture happen
  after redirect validation on the same request and are unaffected by how the
  URI matched.
- `oauth21Strict` https enforcement still applies after the allowlist check
  (`wrapAuthorizationResponse`, `finishLoginCodeFlow`) — a pattern is already
  https-only by grammar, and exact `http://localhost` entries continue to
  enjoy their documented loopback exception.

### Adversarial sample table (all covered in tests)

| Candidate | Pattern | Why no match |
|---|---|---|
| `https://evil.com/test/x/callback` | `https://app.example/test/*/callback` | host fixed — no host wildcard |
| `https://app.example/test/a/b/callback` | `https://app.example/test/*/callback` | `*` = exactly one segment |
| `https://app.example/test/x/evil/callback` | `https://app.example/test/*/callback` | segment count differs |
| `https://app.example/test/a%2Fb/callback` | `https://app.example/test/*/callback` | decoded segment contains `/` (segment-count attack) |
| `https://app.example/test/a?x=1/callback` | `https://app.example/test/*/callback` | candidate has a query — rejected outright |
| `https://app.example/test/A/callback#frag` | `https://app.example/test/*/callback` | fragment rejected |
| `https://app.example:8443/test/x/callback` | `https://app.example/test/*/callback` | port mismatch (8443 ≠ default) |
| `https://app.example/test/x/callback` | `https://app.example/test/x/callback` | exact entry absent, pattern absent — false |
| `http://app.example/test/x/callback` | `https://app.example/test/*/callback` | scheme mismatch |
| `https://APP.EXAMPLE/test/x/callback` | `https://app.example/test/*/callback` | MATCH (host normalized, case) |
| `https://app.example:443/test/x/callback` | `https://app.example/test/*/callback` | MATCH (default port normalized) |
| `https://app.example/test/%78/callback` | `https://app.example/test/*/callback` | MATCH (`%78` decodes to `x`, single segment) |

Illegal PATTERNS (rejected at provisioning): `https://*.example.com/cb`,
`https://app.example/*`, `https://app.example/callback/*`,
`https://app.example/test/*/cb/*/x`, `https://app.example/test/cb*`,
`https://app.example/test/*x/cb`, `https://app.example/test//cb`,
`https://app.example/test/%2F/cb`, `https://app.example/test/cb` (no
wildcard), `https://app.example/test/../*/cb` (dot segment),
`http://app.example/test/*/cb`, `https://user@app.example/test/*/cb`,
`https://app.example/test/*/cb?x=1`, `https://app.example/test/*/cb#f`,
`` (empty).

## Decision 5 — FAPI adaptation

**Pattern shape (from the archived module log, the authoritative source)**:
the FAPI2 SP FINAL module's `CreateRedirectUri` produced
`https://localhost:8443/test/R7bzpU0mqX8Rghe/callback` (testId = 16-char
base64url). The static-client pattern is therefore
`https://localhost:8443/test/*/callback` — the `*` segment matches the dynamic
testId, bounded by the literal `test` prefix and `callback` suffix.

**Harness supplement**: `test/oidc-conformance/config-fapi.yaml` seeds both
static FAPI clients with the pattern at boot (`bootstrap.disabled` does not
affect client seeding; `seedClients` runs unconditionally). The suite-side
client objects and private PS256 JWKS are checked in as the conformance
fixture `test/oidc-conformance/fapi-static-clients.json`; the runner supplies
those objects to the plan without putting private keys in server config. The
latest HTTPS run proves the first dynamic callback is accepted and reaches
the PAR/token/DPoP resource path. The same suite deliberately exercises a
second callback with a query suffix; it is rejected by Decision 2, as intended.
Supporting query-bearing patterns is a separate security design, not an
implicit relaxation of this grammar.

## Decision 6 — Acceptance assertions (all tested, none skipped)

1. **Exact-match default unchanged**: zero patterns → `IsRedirectURIValid` is
   byte-identical to today (all existing `shared/core/types_test.go` +
   `test/types_test.go` cases stay green; no existing test modified except the
   matcher additions).
2. **Match matrix**: the Decision 4 table (hits + misses + normalization) as a
   table-driven matcher test in `shared/core`.
3. **Illegal patterns rejected**: Decision 2 + Decision 4 illegal-PATTERN list
   through `core.ValidateRedirectURIPattern`.
4. **DCR round-trip**: `POST /register` with `redirect_uri_patterns` persists +
   echoes the field; `PUT` updates it; `GET` returns it; an illegal pattern →
   `400 invalid_client_metadata`; DCR clients keep requiring `redirect_uris`
   (code flow) — patterns are additive.
5. **FAPI static-client proof**: a config-seeded static client carrying
   `redirect_uri_patterns: ["https://localhost:8443/test/*/callback"]` accepts
   the archived per-test callback
   `https://localhost:8443/test/R7bzpU0mqX8Rghe/callback` at the login gate.
6. **Runtime gate**: integration test — DCR-register a client with a pattern,
   complete a login whose `redirect_uri` satisfies the pattern (not the exact
   list), and assert the callback/attestation path validates; a non-matching
   redirect still fails with `invalid_redirect_uri`.
7. **Fuzz**: `shared/core` fuzz test (repo precedent:
   `protocols/oauth/oauthvalidate/dcr_fuzz_test.go`, `shared/trust/fuzz_test.go`)
   — random patterns/URIs never panic Validate/Match and never return
   match=true for an invalid pattern.
8. **Gates**: `go build ./... && go vet ./...`; the package test set; the
   maintainability/architecture/directory gates; `cli.py check-routes` +
   `cli.py sdk-surface check`.

Persistence + contracts are updated in the same change: sqlite migration v8,
postgres `clientSchemaV6`, `docs/openapi.yaml` DCRRequest/DCRResponse schemas,
`docs/config-reference.md` `clients[]` row, CHANGELOG entry. The admin gRPC
surface (`adminv1.Client`) is explicitly OUT of scope (proto regeneration is a
separate surface; `applyProtoToExistingClient` already builds forward from the
existing record, so an admin update can never wipe `RedirectURIPatterns`).
