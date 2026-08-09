Spec written. Summary of the deliverable:

**Output:** `docs/architect-analysis/auto/runs/replace-host-derived-issuer-fallback-with-a-conf-ed324fea/artifacts/requirements-10762e10/requirements.md` (the pipeline-configured path)

**Evidence verification — all four citations confirmed with corrections:**

| Citation | Result |
|---|---|
| `server_discovery.go:251-255` `resolveIssuer` Host fallback | Exact — `return requestBaseURL(ctx.Request())` at 255 |
| `server_discovery_config.go:146` `buildBaseMetadata` `cfg.Issuer = base` | 2-line drift (actual 144); override at 264-265 shares the same sentinel condition |
| `options.go:349` `WithIssuer` | 9-line drift (actual 358-359); sole identity option |
| `consts_oauth.go:139` `DefaultIssuer` | Exact; default wired in `NewServer` (sso.go:67) |
| "zero allowlist hits" | Confirmed — only unrelated SAML `AllowedIssuers` |

**Load-bearing discoveries beyond the citations:**
1. **Deploy-tree drift:** `server.issuer_allowlist` is already set in 5 shipped YAML files (`ops/deploy/kustomize/{base,overlays/prod}`, `k8s-distributed`, both `bin/k8s-rendered`), but `decodeStrictWithFallback` (config/source.go:264) silently ignores it with a WARN — the allowlist operators deployed today does nothing. This pins the config key name.
2. **The cmd binary never reaches the fallback** (`config_load.go` defaults `sso-server`, rejects the sentinel, wires `WithIssuer`); the exposure is SDK compositions without `WithIssuer` plus the inert key.
3. **JWT `iss` is a signer constructor literal** (`buildAccessPayload`), so "any path" enforcement centers on the ~50-consumer `resolveIssuer` seam — the spec enumerates the surfaces (discovery, RFC 9207, form_post, JARM, FCL, bearer challenges, signed introspection, resource metadata) for the sweep.

**Scope discipline:** acceptance preserved verbatim and decomposed into A-1..A-7, all testable; mode-off byte-identity kept (no `require_configured_issuer` expansion, no runtime 503 gate); zero billing-module code changes; no new non-test file in `interfaces/sso` (60-file ceiling respected — option goes in options.go).
