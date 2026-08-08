All verification complete. I made no code edits, so no gates are required. Here is the review.

# Adversarial review: allowlist comparison basis, FM-1/FM-3/FM-4/FM-5

## 1. Comparison basis vs every `resolveIssuer` output path — **holds, with two conditions**

I traced every issuer-emission path. They converge on exactly **two raw strings**, both emitted verbatim with **zero normalization anywhere in the server** (the only `TrimSuffix("/")` hits are in downstream *consumers* — rs-client JWKS URL building, billing, workload-identity presets — never in the emission path):

| Path | Value | Trailing slash | Port | Case |
|---|---|---|---|---|
| Configured (`WithIssuer`, options.go:350 → `s.issuer`) | `cfg.Server.Issuer` verbatim, no runtime touch | as configured | literal | preserved |
| Host fallback (server_discovery.go:251-255 → `requestBaseURL` → `middleware.BaseURL`) | `scheme://host[:port]` (`r.Host` or trusted `X-Forwarded-Host`, first hop) | **impossible** (Host carries no path) | literal | preserved (no lowercasing in `BaseURL`) |
| Discovery-derived (server_discovery_config.go:62 `base` + :264-265 override; RFC 8414 signed_metadata; federation `BuildOPMetadata` via `cfg.Issuer`; resource-server `authorization_servers` at server_resource.go:182) | same two branches, byte-identical to `resolveIssuer` | same | same | same |

Verified anchors: JWT `iss` = `buildAccessPayload(j.issuer, ...).Iss` with `j.issuer = srv.Issuer` (serverbuildsign → `WithEd25519Issuer(srv.Issuer)`); `TestBuildApp_*` in the untracked `issuer_wiring_test.go` pins discovery==RFC 9207==JWT `iss` end to end; all 20+ `resolveIssuer` call sites consume the value untransformed.

**Critical lemma:** under `require_configured=true`, the Host-fallback branch is **dead code** — the gated "issuer set" check (post-`applyDefaults`, whose fallback the design skips under R3) plus the unconditional sentinel check guarantee `s.issuer` is always non-empty and non-sentinel at runtime. So the config-time membership check on the raw `cfg.Server.Issuer` string exactly predicts every runtime emission. No basis drift is possible — **provided**:

1. **Normalization is a total, idempotent function applied to both sides** (entry and configured issuer) with the identical definition ("strip all trailing slashes, then ensure exactly one"). The runtime value is emitted verbatim — including any trailing slash the operator wrote — and discovery/token/`iss` always agree with each other, so trailing-slash flexibility at config time cannot create internal divergence. The failure mode (FM-2) is a one-sided normalization (e.g., `TrimSuffix` on entries only): `https://host` entry vs `https://host/` issuer silently flips membership.
2. **Membership is compared on canonical raw strings** — never parsed components (see FM-4).

Literal ports and case-significance hold on every path: both runtime branches preserve `:port` and case verbatim, so `https://host:443` ≠ `https://host` and `HTTPS://HOST` ≠ `https://host` at runtime exactly as at config time — fail-closed direction in both axes.

## 2. FM-1: sentinel check unconditional — **holds (design-level)**

Today the check sits directly in `Validate()` at config_load.go:176-185, ungated (verified: comment at 176-182, `if c.Server.Issuer == sso.DefaultIssuer` at 183-184). The design commits to moving it **verbatim** into `validateIssuerPolicy()`, with only the five new checks gated on `require_configured`. The trap is real and correctly identified: gating the sentinel would re-open the exact divergence documented at config_load.go:176-182 — with `require_configured=false` (the default), `issuer: snaplink-sso` would pass, tokens would carry `iss=snaplink-sso` while discovery/RFC 9207 fall back to the base URL, breaking every RFC 9068 validator. The `W1` pin must assert rejection under **both** gate states (default-off is the only state the current `TestConfigRejectsSDKSentinel` covers).

## 3. FM-4: `url.Parse` leniency/userinfo — **cannot bypass, if three predicates land**

Empirically probed Go's `url.Parse`:

- `sso.example.com:8080` → `Scheme="sso.example.com"`, `Opaque="8080"`, **`IsAbs()==true`** — a bare host:port passes a naive absolute-URL check.
- `https://sso.example.com@evil.example` → `Host="evil.example"`, `User="sso.example.com"` — userinfo silently relocates the host.
- Host case preserved; dot-segments not normalized; `%0a` rejected.

Consequences for the design:
- The "absolute URL" check must require `Scheme ∈ {http,https}` **and** `Host ≠ ""` — never `IsAbs()` alone. Otherwise `sso.example.com:8080` as an entry or as the configured issuer passes under the gate while never matching a runtime URL form (FM-3) or matching nothing coherent.
- Entry validation must reject `User`, `Path` (beyond canonical `""`/`"/"`), `Query`, `Fragment` — the allowlist may contain only canonical `scheme://host[:port]` origins.
- Membership must be raw-string equality of canonical forms. Component-based comparison is the *only* way userinfo creates a bypass: entry `https://host` matching runtime `https://host@evil` (Host-equal after userinfo strip) would let tokens carry an `iss` string that was never allowlisted — exact-match validators pinned to the entry silently always-fail (FM-3) while discovery-validating RPs accept an unapproved issuer. With string comparison + userinfo-rejecting entry validation, no bypass and no silent always-fail is constructible: the runtime value is byte-identical to the string that passed membership.

## 4. FM-5: `base_url` rejection — **correct, and it closes FM-3 rather than creating it**

Verified the dead key end to end: `ServerConfig.BaseURL` (config_server.go:18) has **no reader** in the binary — `ServerOptions()` (config_load.go:303-306) explicitly documents `Server.{BaseURL,...}` as NOT wired; `WithBaseURL` (options_security.go:399-405) is a documented no-op; real manifests set the key (`ops/deploy/kustomize/base/config.yaml:14`, `bin/k8s-rendered/dev/all.yaml:24`), so a check against it would *look* meaningful.

The rejection is the only sound choice: a `base_url`-based membership basis would compare a value with zero runtime effect — the gate could pass (`base_url ∈ allowlist`) while the actual issuer (`cfg.Server.Issuer` verbatim, or the Host fallback when unset) is not in the allowlist. Tokens would then carry an un-allowlisted `iss`; downstream exact-match validators (`remote.WithIssuer`, `rs.Config.Issuer` — both match `iss` exactly, verified) would silently always-fail, or accept an issuer the operator never approved. Because the design instead compares the **wired** `cfg.Server.Issuer` — the exact string `WithIssuer` → `s.issuer` → JWT/discovery/RFC 9207 emit verbatim, pinned by `issuer_wiring_test.go` — the config-time membership result *equals* the token-time `iss` membership. FM-3 is structurally impossible at token validation time through either FM-4 or FM-5 paths.

Also confirmed along the way: `issuer_allowlist` is a live `validate-schema` violation today (reproduced: `sso-ctl config validate-schema` on `ops/deploy/kustomize/base/config.yaml` → `server.issuer_allowlist: unknown field`); the four manifests' entry values are byte-identical to their `issuer` values (no trailing slash, literal port, lowercase), so the new surface converts them to recognized-and-passing with zero normalization.

## Residual gap

The design artifact is a 19-line summary, not the full spec; the exact normalization predicate and entry-validation predicates are implied, not pinned. The `G*`/`W1` acceptance tests must encode concretely: bare `host:port` entry (reject), userinfo entry (reject), path/query/fragment entry (reject), multi-trailing-slash both directions, `https://host:443` vs `https://host` distinctness, mixed-case distinctness, and sentinel rejection under both `require_configured` states. All cited line numbers verified correct: server_discovery.go:251-255, options.go:350, config_load.go:176-185.

**Verdict: all four claims verified sound against the tree; the design's comparison basis and both failure-mode rejections are correct, with the two conditions above (symmetric idempotent normalization; raw-string, not component, comparison) as the load-bearing implementation requirements.**
