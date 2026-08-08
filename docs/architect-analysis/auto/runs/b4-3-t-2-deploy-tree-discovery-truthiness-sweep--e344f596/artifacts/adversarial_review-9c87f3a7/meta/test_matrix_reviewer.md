Everything is verified and consistent. The deliverable is complete.

## Deliverable

**`docs/architect-analysis/auto/runs/b4-3-t-2-deploy-tree-discovery-truthiness-sweep--e344f596/artifacts/design-a77de8a6/task-1-design-amended.md`** — the amended design with the definitive consolidated acceptance matrix. Plus two contradiction fixes:

- **Run summary artifact** (`task-1-design.md`): C5 paragraph rewritten as **C5-R** — the mechanism claim is withdrawn; final construction keeps `WithIssuer`.
- **Companion design doc §6** (`cmd-sso-ctl-b4-3-t2-design.md`): helper spec now states the final construction explicitly with the C5-R rationale.

## Key decisions in the matrix

**C5 resolution** — `WithIssuer` overrides only the `issuer` claim (`applyMFAIssuerSigning`, :264-265); all endpoints derive from `requestBaseURL` (`buildBaseMetadata`, :142-161). Final helper: `sso.NewServer(WithIssuer("https://sso.test"), WithClientStore(seeded), WithTokenIssuer("jwt", Ed25519…), WithDefaultTokenStrategy("jwt"), WithIDTokenIssuer(Ed25519…))` — mirrors `newDiscoveryServer` exactly (all call sites pass `true`), passes case 1 empirically, and makes every green test also pin C1b.

**All reviewer pins folded in** — 41 failure-mode rows (F1–F41), each with a dedicated test:
- *Acceptance 9 pins*: timeout expiry (single `sweep timed out after 50ms` line, exit 1), base pass 0 with pre-fetch short-circuit (trailing-slash/path/query-fragment: one diagnostic, zero requests, no cascade), redirect-chain-to-404 (with POST→GET method-conversion recording), `--timeout <= 0` → exit 2 (`0s`/`-1s`), multi-violation byte-exact (4 ordered lines pinning equality→shape→probe cross-pass order + shape-failed-skip), empty stdout with/without `--print`, IPv6 green + trailing-slash red, allowlist whitespace/dedup/empty-entry semantics, F1/F3/F5/F7 partials filled (fetch-404, fetch-dial, probe-dial, `://`/`ftp://`/`""`, port 65536/overflow, empty host/port, userinfo).
- *Security 3 additions*: explicit `CheckRedirect` (refuses https→http downgrade + non-http(s), enforces the 10-hop cap itself — verified it lives in `defaultCheckRedirect`, client.go:834-838), TLS-cert-failure exit 1 (`httptest.NewTLSServer` locks verify-always), 1 MiB `io.LimitReader` doc cap (probes close without reading).
- *Protocol decision*: **probe `mfa_endpoint` and `mtls_endpoint_aliases`** (probe-when-present, no absence semantics; six fixed alias keys, never map iteration; zero-cost on stock servers via dedup).

**Exit-code inventory, no gaps**: 0 → 14 catalog rows; 1 → 36 rows; 2 → 12 rows + pre-existing; counts machine-verified against the tables. Each row carries test name, mechanism, exit code, and the byte-exact stderr/stdout assertion (fully exact bytes where the implementation controls the text; deterministic prefix + required substring for Go-embedded net/JSON error tails, as noted per row).

One implementation note surfaced during verification: the 10-hop redirect cap is part of the *default* policy, so the amended `CheckRedirect` must return `stopped after 10 redirects` itself — the matrix pins this via `TestCheckDiscovery_RedirectLoop`.
