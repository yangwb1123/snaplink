All code facts verified. Here is the review.

## Review: RFC 9207/RFC 9068 issuer-pinning vs gates C3 and C4

**Verdict: both design claims hold, with the code evidence below. Two adjacent findings (F1 scoping gap, F2 Retry-After) and one nuance (discovery-503 cacheability) worth taking into the implementation.**

---

### C3 — Discovery gate before the body-cache lookup: no observable change for caching clients

Verified the full cache path in `interfaces/sso/server_discovery_config.go:61-91` and `protocols/oidc/oidcsupport/discovery_doc_cache.go`:

- `handleOIDCDiscovery` order today: `base := requestBaseURL(...)` → `lookupDiscoveryDocCache(base)` → hit: `writeDiscoveryDoc` (sets `Cache-Control: public, max-age=<ttl>`, `ETag`, honors `If-None-Match` → 304); miss: render → `storeDiscoveryDocCache` → write. The gate G1 sits above all of this.
- The cache has **exactly one writer and one reader in the entire package**: grep of `storeDiscoveryDocCache`/`lookupDiscoveryDocCache` yields only `server_discovery_config.go:68,89` (writer at :89, reader at :68). `invalidateDiscoveryCaches` only deletes. Options are immutable post-`NewServer` (`sso.go:67` seeds the sentinel; no runtime mode switch exists).
- Therefore, in strict-unconfigured mode — the only mode where G1 can fire — the body cache is **provably empty**: any entry would require a prior request that passed the gate. Gate-before vs gate-after lookup are observationally identical: every discovery request yields the same bare 503 (no ETag, no Cache-Control, no 304 handling), and configured-strict/mode-off are byte-identical to today (gate never fires).
- The ordering also forecloses the only *hypothetical* divergence: with the gate after the lookup, a caching client holding a valid ETag could get a 304/"still fresh" while a non-caching client gets 503 — a split-brain that would actively *lie* to the caching client. Gate-first makes the invariant local, exactly as the design claims.
- The `WithDiscoveryDocCacheTTL(0)` configuration skips the body cache entirely (no ETag/Cache-Control emitted), so the ordering is trivially unobservable there too.

**Nuance (deliberate, worth stating):** the discovery 503 carries no cache headers (verified: gate writes `ctx.JSON(503, errorBody(...))`, matching the `quota.go:205` precedent). The success path primes intermediaries to cache this URL (`public, max-age=5s` + strong ETag). A 503 without explicit freshness has no validator, so RFC 9111-compliant caches will not serve a stored copy — consistent 503s until recovery. Optional one-line hardening: stamp `Cache-Control: no-store` on the discovery 503 too, to guard against misconfigured CDNs that cache 503s with a default TTL; this would diverge from the quota.go pattern, so it is a judgment call, not a defect.

---

### C4 — 503 instead of 400 invalid_grant on credential endpoints: contract-compatible and retry-correct

Verified the placement mechanics in `server_token.go:20-22`, `server_login.go:21-23`, `server_mfa.go:193-195` (`tokenNoStoreHeaders` stamped before any branch; `middleware/no_store.go:22` sets both `Cache-Control: no-store` + `Pragma: no-cache` unconditionally, errors included). G4 sits before `requireDeps` → before bind, client authentication, `beginTokenIdempotency`, and the grant switch with atomic single-use consumption.

**OAuth error-contract compatibility:** RFC 6749 §5.2's 400 + registered codes describe *client-correctable* errors; `invalid_grant` specifically means the grant is invalid/expired/revoked/mismatched — none of which is true. Mislabeling a server-config state as a client error violates the contract's semantics; 503 (RFC 9110 §15.6.4) is the correct classification of a temporary server-side condition. The envelope shape is already established on `/token` itself: `requireDeps` failure returns 500 + `errorBody` (`server_token.go:27-30`), and `quota.go` returns 503 + `errorBody`. `issuer_not_configured` being outside the OAuth error registry is irrelevant on 5xx — clients key on status; the registry governs 4xx responses.

**Client retry behavior — the decisive argument:** 400 `invalid_grant` is terminal in client stacks (no HTTP client retries 4xx), and OAuth 2.0 Security BCP §4.14.2 requires clients to **revoke the refresh token and force re-authentication** on `invalid_grant`. The 400 alternative would therefore destroy valid credentials in response to a transient operator state. 503 is retryable by default (mesh/Envoy 5xx retry policies, client backoff), and because G4 fires *before* any consumption, the retry reuses the **same auth code / refresh token** — a fail-at-mint `invalid_grant` would have consumed the single-use code and made the retry genuinely fail. The header-first ordering additionally guarantees no intermediary can cache the 503 and mask recovery. Uniform 503-before-authentication is also strictly less oracle-y than today: no per-request distinction is made at all, so the AGENTS.md §3 table is untouched.

**Correctly ungated (rollout continuity):** `/token/introspect` and `/token/revoke` stay ungated — revoke must remain 200-with-valid-creds, introspect must keep answering `{"active":false}`, and a strict canary during migration step 3 must still validate tokens minted by non-strict peers. Only *minting* (and authorization responses) 503.

---

### Adjacent findings

**F1 (scoping gap, material to "issuer-pinning semantics"):** `handleFederationEntityConfig` (opt-in `WithFederationEntity`, `server_federation.go:387`) serves entity configuration via `BuildOPMetadata` ← `buildOIDCConfiguration` — the same un-gated projection with `Issuer: base` + `WithIssuer` override. In the strict-unconfigured SDK state, a federation resolver (RFC 9401 — resolvers cache entity config, the same caching-client class C3 protects) would still see a request-derived issuer, bypassing G1's purpose. The design's §4.5 non-goal list names "protected-resource metadata" but not federation entity config. Either add the one-line gate there or document it explicitly.

**F2 (minor recommendation):** the credential-endpoint 503s should carry `Retry-After` (RFC 9110 §15.6.4 "SHOULD"). The codebase has precedent: maintenance-mode 503 + Retry-After and rate-limit 503 + Retry-After (`options_httpstack.go:138`, `client_registration_ratelimit_test.go:98`); `quota.go`'s 503 does not, so it is optional but cheap.

**F3 (consistency note, verified end-to-end):** I re-derived the boot/request-time split with the actual sentinel values — cmd default `"sso-server"` (`config_load.go:60,70-71`) vs SDK sentinel `"snaplink-sso"` (`shared/core/consts_oauth.go:139`, seeded at `sso.go:67`). The design's step-4 "unreachable on the cmd path" is accurate: with the switch on, the cmd path either panics at boot (default `"sso-server"` can never be an allowlist member, since entries must be absolute URLs) or has an allowlisted URL (gate never fires). The request-time 503 state is reachable only via the SDK path (`s.issuer ∈ {"", sentinel}`). So 503s can never occur in a healthy cmd deployment — the loud-panic/soft-503 split is exactly as designed.

**Bottom line:** C3 and C4 are sound as specified; the acceptance cases A9/A9a assert the right observables, and the test homes (`interfaces/sso/issuer_allowlist_test.go`, `test/` extensions) can cover F1 with one extra case (strict-unconfigured + `WithFederationEntity` wired → entity-config endpoint 503s or the gap is documented). No design changes required before implementation.
