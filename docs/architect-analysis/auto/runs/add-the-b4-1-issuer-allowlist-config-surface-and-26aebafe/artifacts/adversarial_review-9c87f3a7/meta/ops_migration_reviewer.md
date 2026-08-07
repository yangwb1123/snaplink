All verification complete. Here's the full report.

## 1. Migration table vs actual files — per-file verdict

All 8 cited line numbers match the files exactly (verified via grep). Origin-coherence: the 3 sentinel replacements each equal the config's own `base_url` string exactly (not merely same-origin), so they pass the R2-5 gate as designed.

| # | Config (line) | Replacement | `base_url` (actual) | Coherence | Verdict |
|---|---|---|---|---|---|
| 1 | `cmd/sso-server/config.yaml:19` | `http://localhost:8080` | `:27` = `http://localhost:8080` (listen `:28` `:8080`) | exact match | ✅ |
| 2 | `bin/config.yaml:17` | `http://localhost:28898` | `:22` = `http://localhost:28898` (listen `:23` `:28898`) | exact match | ✅ (doc's correction confirmed — 8080 would fail) |
| 3 | `ops/deploy/k8s/config.yaml:11` | `http://sso-server.snaplink-sso.svc.cluster.local:8080` | `:13` = identical string (listen `:14` `:8080`) | exact match | ✅ (doc's correction confirmed) |
| 4 | `docs/examples/basic/config.yaml:2` | already absolute | `:3` = identical string | **evidenced** | ✅ |
| 5 | `ops/deploy/compose/config.yaml:10` | already absolute | `:11` = identical string | **evidenced** | ✅ |
| 6 | `ops/deploy/baremetal-ha/sso/config.yaml:17` | already absolute | `:18` = identical string | **evidenced** | ✅ |
| 7 | `ops/deploy/k8s-prod/config.yaml:12` | already absolute | **no `base_url` key at all** | check skipped (R2-5 documented limitation) | ✅ with caveat |
| 8 | `test/oidc-conformance/config.yaml:15` | already absolute | **no `base_url` key at all** | check skipped | ✅ with caveat |

**On the "asserted but not evidenced" coherence for the 5 already-absolute configs:** 3 of the 5 (rows 4–6) are now *evidenced* — each declares `base_url` with the identical origin. The other 2 (rows 7–8) declare **no `base_url`**, so coherence is vacuous: the gate skips them by design. The table's "already absolute (+ allowlist)" label is accurate for these, but it silently implies a coherence that cannot exist — the rows should say "no `base_url` ⇒ coherence not applicable" rather than implying coherence.

## 2. Per-environment topology

- **k8s (dev) cluster DNS:** `sso-server.snaplink-sso.svc.cluster.local:8080` resolves correctly — `service.yaml` names the Service `sso-server`, kustomization sets `namespace: snaplink-sso`, ClusterIP port `8080` → containerPort `http` 8080. No Ingress in the base (intentional: "Front this with an Ingress / Gateway (intentionally not in the base — controller choice is opinionated)"). Plain http cluster-internal — matches the `base_url` scheme. ✅
- **k8s-prod TLS:** no Ingress resource exists in the overlay; the config comment (`:11` "issuer MUST be the externally-reachable URL the edge terminates TLS on") and README prerequisite ("configure … a TLS-terminating trusted edge") make the edge an operator contract. `https://sso.example.com` is consistent with that. ✅ Also note: `k8s-prod` is marked deprecated in its README; the new home is `ops/deploy/kustomize/overlays/prod/` (same issuer). 
- **baremetal-ha TLS:** HAProxy terminates TLS (`bind *:443 ssl crt /run/secrets/sso-edge.pem alpn h2,http/1.1`, sets `X-Forwarded-Proto https`), backends `sso1/2/3:8080`; config `listen: ":8080"`. ✅
- **compose:** `sso-server` plain `8080:8080`, no TLS in front of SSO (Caddy TLS `:8443` is only the billing/stripe edge). `localhost:8080` issuer/base_url coherent. ✅
- **oidc-conformance:** in-container `listen: ":8080"`, host publish `8180:8080`, issuer `http://sso-issuer:8180` browser-facing; suite reaches the server internally at `http://sso-server:8080`; `extra_hosts: sso-issuer:host-gateway`; env pin `SSO_SERVER__ISSUER` matches the file. ✅

## 3. `bin/k8s-rendered/*` regeneration — proven, not just asserted

- Tooling exists: `make k8s-render` (Makefile:421–458) renders `ops/deploy/kustomize/overlays/{dev,prod}` + billing/stripe-adapter/audit-provisioner via `kubectl kustomize`/`kustomize build`.
- I **ran `make k8s-render` and diffed against the committed state: byte-identical** across all 5 rendered `all.yaml` files.
- `bin/` is gitignored (`git check-ignore` → `.gitignore:12:/bin/`), so these are untracked build artifacts — "generated, not hand-edited" is the correct model.

## 4. Material gaps found (scope is narrower than the deploy tree)

1. **`ops/deploy/kustomize/base/config.yaml` is byte-identical to `ops/deploy/k8s/config.yaml` (sentinel `issuer: sso-server`, same cluster-DNS `base_url`) but is NOT in the table.** It is the *canonical* base ("new deployments should use `ops/deploy/kustomize/base/`") and it feeds `bin/k8s-rendered/dev/all.yaml`, which I confirmed embeds `issuer: sso-server` (`dev/all.yaml:21`). Consequence: after the documented migration, `make k8s-render` still emits the sentinel issuer in the dev render — the "regenerated, not hand-edited" instruction is mechanically true but the regenerated artifact would still fail the new gate. The kustomize base needs the same migration row (same replacement value as row 3).
2. **`ops/deploy/kustomize/overlays/prod/config.yaml:12`** (`https://sso.example.com`, already absolute, no `base_url`) is absent from the table; it feeds `bin/k8s-rendered/prod/all.yaml` and would fail the gate on the missing allowlist key (R2-2).
3. **`ops/deploy/k8s-distributed/config.yaml:3`** (`issuer: https://sso.ywbsd.site`, Tier B verified topology, OpenResty TLS edge "separate manifest") is a live deploy-tree config absent from the table; already absolute but no allowlist ⇒ would fail the new gate.

The table is self-consistent with its stated scope ("7 CI-validated + conformance fixture" — I confirmed `make config-validate-all` validates exactly those 7, excluding all kustomize/k8s-distributed files), so the rows themselves are accurate — but the deliverable's §7 title "Deploy-tree configs" and the "`bin/k8s-rendered/*` regenerated" claim overreach: the canonical kustomize tree and k8s-distributed are deploy configs that the gate will reject after this migration.

**Bottom line:** all 8 table rows verified accurate (line numbers, replacement values, topology); regeneration tooling proven byte-reproducible; 3 additional configs outside the table (kustomize base — a duplicate sentinel of row 3 — plus prod overlay and k8s-distributed) will fail the new gate and need rows or an explicit scope note.
