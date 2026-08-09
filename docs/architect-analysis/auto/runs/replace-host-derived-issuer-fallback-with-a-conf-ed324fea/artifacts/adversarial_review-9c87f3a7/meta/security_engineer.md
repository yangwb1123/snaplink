Review complete. Written to `docs/architect-analysis/auto/runs/replace-host-derived-issuer-fallback-with-a-conf-ed324fea/artifacts/adversarial_review-9c87f3a7/meta/review-trust-boundary.md`.

## Verdict: FAIL (blocking) — 4 findings

**B1 (blocking, new attack surface):** The `""` fail-closed sentinel activates two dormant skip-guards:
- `server_jar.go:248` — `len(p.Aud) > 0 && asIssuer != "" && ...` → JAR `aud` binding **skipped**
- `server_pairwise.go:343` — same guard → RFC 7523 `private_key_jwt` `aud` binding **skipped**

Today `asIssuer` (request base) is never empty, so these guards never fire. The design's strict mode is the first activator: on `/token`, `/par`, `/introspect`, `/revoke`, CIBA, assertions minted for a *different* AS pass the aud check. Workload identity already does it right (`workload_identity.go:235-237` rejects empty audience) — the design must specify reject-on-empty at those two guards.

**B2:** Discovery normalization must be **unconditional**. `buildBaseMetadata` stamps `cfg.Issuer = base` (`server_discovery_config.go:147`); the override at `:264-265` is sentinel-conditional. Keeping that condition means strict SDK mode without `WithIssuer` leaves discovery host-derived while auth responses emit `""` — the exact regression being chartered out, breaking RFC 9207 §2.

**B3:** Membership must be exact full-string equality emitting the matched entry. `ForwardedHeadersTrusted` defaults **true** at untrusted edges (`peertrust/request.go:37-39`), so Host/XFH/XFP are attacker inputs; only exact match fails safe in every direction (scheme/port/case/trailing-slash/comma-lists). Prefix/substring or one-sided normalization = bypass.

**B4:** Mode gate must be **option presence** (`WithAllowedIssuers` called = strict; absent = byte-identical legacy; explicit empty = deny-all + boot error when issuer set). cmd always wires it → unlisted request hosts now get `""` on discovery/auth responses; shipped YAMLs are aligned, custom multi-host YAMLs must extend the allowlist (the "no migration edits" claim holds only for the 5 shipped files).

## Verified sound
- **Q1 sweep:** all ~30 resolveIssuer sites + Deps consumers (introspect/revoke/register/CIBA) route through one seam; JWKS is issuer-free (no regression path); token `iss` is a signer literal (out of scope, pre-existing divergence).
- **Q2:** `""` is constant across discovery/authz/JARM/form_post/FCL/signed-introspection; challenges mask safely (`realm="sso"` fallback, step-up realm omitted). Hardening: ERROR log floods on public endpoints; NopLogger drops it in SDK mode; `/health` returns raw `s.issuer`.
- **Q3:** allowlist neutralizes legacy first-hop trust; key pinned by 5 YAMLs; `validate()` (incl. SIGHUP reload) is the right gate; key absent from all contract docs — must be added.
- **Q4:** F1 deterministic (source.go:143-144), F4 cmd-rejected, no 503/no new wire code confirmed; `issuer: ""` visible but constant (plus RFC 9728 `authorization_servers: [""]` — decide explicitly); B1 is the real new-surface counterexample.

Six test pins (strict-mode `""` uniformity, foreign-aud rejection at `""`, membership attack matrix, mode-off byte-identity + cache coherence, boot failures F1/F2/F6 incl. reload, discovery normalization incl. `BuildOPMetadata`) are in the artifact with exact file:line citations.
