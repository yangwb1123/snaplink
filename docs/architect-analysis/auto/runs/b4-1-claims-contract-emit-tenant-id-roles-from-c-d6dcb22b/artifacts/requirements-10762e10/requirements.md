The requirements specification is complete and written to the pipeline-pinned output path:

**`docs/architect-analysis/auto/runs/b4-1-claims-contract-emit-tenant-id-roles-from-c-d6dcb22b/artifacts/requirements-10762e10/requirements.md`**

## Evidence verification summary

Every cited symbol was re-read in the tree — all 10 primary citations confirmed, plus six additional load-bearing facts:

**Confirmed as cited:**
- `buildAccessPayload` (`issue_payload.go:26`) emits no `tenant_id`/`roles`; shared by all three signers (`ed25519_issue.go:43`, `ecdsa_issue.go:37`, `rsa_issue.go:29`)
- `ed25519Payload` (`ed25519_types.go:15`) lacks both fields; `Subject.TenantID` (`types_token.go:226-231`) documented "NOT a token claim"; no `Roles` symbol exists (`KeyRoles`/`KeyTenantID` consts already exist)
- `resolveIssuer` (`server_discovery.go:251`) Host fallback via `requestBaseURL` (`server_federation.go:40`); kid already present (`ed25519_issue.go:33` — do not re-add)

**Newly verified facts that shape the contract:**
- All 8 mint sites in `internal/handler/tokengrant/` already bind `TenantID: client.TenantID` — only wire emission is missing (the analysis doc's "mint time" claim is now pinned to exact sites)
- **Deployments already declare `server.issuer_allowlist`** (`ops/deploy/kustomize/{base,overlays/prod}/config.yaml`, `k8s-distributed`, rendered manifests) but `config/source.go:260-280` warns-and-ignores unknown keys — the knob name is pinned by existing deployment intent
- `test/trusted_proxy_gate_test.go:267-311` has 3 tests locking in Host-derived discovery issuer — must be re-pointed
- Roles source pinned to `permissions.Provider.Roles` (vocabulary `Role.Code`) via the existing grant-deps accessor pattern (`ScopeRegistry()`); `Client.Roles` rejected (no data source, schema expansion)
- `claimsFromPayload`/`tenantHintFromClaims` round-trip seam identified; introspection body confirmed not to echo claims

## Deliverable structure

- R1a/R1b (tenant_id + roles claims, fail-open roles, byte-identical unbound wire) and R2 (issuer allowlist, fail-loud boot validation, Host fallback removed)
- Acceptance preserved and made testable: **A1/T-8(a)** (per-signer unit + wire round trip + byte-compat negative), **A2/T-1.2** (mint→validate fixture; 422 execution explicitly cross-repo), **A3** (six falsifiable allowlist tests incl. the mandated `oidc_discovery_test.go:80` extension and trusted-proxy re-pointing)
- Constraints honored: no kid re-add, no ID-token bleed, `interfaces/sso` 60-file ceiling (extend existing files), `config-reference.md` row for the new key, no openapi/error-codes changes

No `.go` files changed — doc-only artifact, so build gates don't apply; the design stage consumes this next.
