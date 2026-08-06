The spec is complete and verified. Here's a summary of the deliverable:

**`docs/architect-analysis/auto/runs/emit-tenant-id-roles-in-buildaccesspayload-via-s-eacdbc35/artifacts/design-a77de8a6/task-3-r4-issuer-strict-spec.md`** — every anchor verified against the current tree:

**1. Stamping surface (16 sites, exact call-site enumeration).** 15 direct `s.resolveIssuer` sites — the `authzErrorBody` envelope root (`server_discovery.go:268`, covering ~107 call sites via Desc/WithState + the `d.AuthzErrorBody` accessor), form_post, direct-mint, auth-code JSON, JARM success sign+render (`server_finish_login.go:456/461`), JARM error sign+render (`origin_validation.go:163/176`), step-up Realm, logout, MFA challenge, native-SSO mint, HR/providers login-gate, FCL iframes — plus 1 accessor-routed site: silent renewal (`handle_silent_renewal.go:369`). Key finding: the native-SSO mint rides the `/token` device-secret branch, making it the only surface outside `/auth/login`.

**2. Switch-over vs exclusions.** All 16 sites are governed through **five entry gates** (handleLogin, handleMFAComplete, handleDeviceSecretExchange, handleLogout, handleEndSession) placed before parameter binding — so the "28 callers untouched" and mode-off byte-identical claims hold mechanically (post-gate, legacy `resolveIssuer` provably returns the strict value). The four exclusion classes stay on legacy with their AGENTS.md-pinned codes: private_key_jwt (6 sites → 401), JAR (1 → 400), bearer challenges (20 → 401), authServers (1 → 200). Nine residual issuer consumers (discovery, `/me` branding, introspection JWT, selfservice, federation, SSF) are explicitly legacy with rationale; signed discovery under strict mode is flagged as a documented residual gap.

**3. 400/503 split pinned.** No inbound `iss` request parameter exists (`login.Request` verified field-less) and R4 adds none — RFC 9207 §4 stays client-side. Pre-existing 4xx codes are unchanged; the 503 is the *only* new response and **preempts** any would-be stamped response (success or 4xx), since an unstampable server can't emit a compliant RFC 9207 response.

**4. Reachability pinned.** The 503 is **live in exactly one configuration**: `WithIssuerAllowlist` without `WithIssuer`. Dead code everywhere else (mode-off; `WithIssuer` short-circuit; `WithRequireConfiguredIssuer` → boot panic in `NewServer` post-option-loop, matching the `WithCustomGrant` precedent).

**5. No Host leak.** 503 body = plain `errorBody` envelope (`{"error":"issuer_not_configured"}` + trace_id) — `iss`, `state`, `error_description` all forbidden; byte-identical across hosts; no-store headers; log-only details.

**6. Docs.** `docs/error-codes.md`: new row in the Authorization table + prose paragraph + optional `consent_required` touch-up. `docs/openapi.yaml`: extend `/auth/login:600` and `/token:1205` 503 blocks, add 503 blocks to `/auth/mfa:607`, `/logout:1877`, `/end_session:3818`; `ErrorResponse` schema needs no change (open string, no enum). No config-reference change (SDK options only).

Plus 8 acceptance tests (T-1…T-8) pinning liveness, host-leak, mode-off identity, configured-issuer precedence, boot panic, exclusion-code preservation, allowlist exactness, and preemption ordering.
