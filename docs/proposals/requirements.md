Spec written to `docs/requirements/domains-anomaly-detect-convergence.md`, following the sibling format of `domains-anomaly-tenant-dimension.md` (direction #1's spec, which explicitly defers this convergence to a separate spec). All three decisions verified against current code:

## 1. Delete the dead subtree `domains/anomaly/{detect,signature,fingerprint}`
- **Evidence**: repo-wide grep shows only intra-subtree imports; `detect/` has zero test files; `docs/proposals/design.md:21` calls it "the dead `domains/anomaly/detect/` package" that must be mechanically updated on every SPI change (proven during the v2 store migration); `signature.Store.DistinctCount` (store.go:30) has zero callers; production wiring at `cmd/sso-server/anomaly.go:258-349` uses only `defaultimpl/detectors`.
- **Acceptance**: zero import matches, `go build/vet`, maintainability+architecture gates, `make ci`.

## 2. Single source of truth for wire-stable `Signal.Type` constants
- **Evidence**: collision table — `detect/velocity.go:96` `"velocity_burst"` == `detectors/velocity.go:15` `DetectorTypeVelocity`; same for `new_device`/`new_country`; `credential_stuffing` vs `brute_force_shadow` (semantic twin, different name). Wire-stability contract documented in `velocity.go:12-14` ("renaming silently breaks operator dashboards") and `types.go:112-114` — yet the domain package defines no constants.
- **Acceptance**: `SignalType*` consts in `domains/anomaly`, `DetectorType*` become aliases, no raw-string `Type:` emissions.

## 3. Fix reference-pointer drift + codify ordering/write-ownership contract
- **Evidence**: `runner.go:13` points at nonexistent `infrastructure/defaultimpl/anomaly` (verified: only `detectors/` exists); the load-bearing order (impossible-travel owns history writes, velocity/new-baseline read-only, per `detectors/velocity.go:21-26`) is enforced by nothing — `buildAnomalyDetectors` order is silently load-bearing.
- **Acceptance**: stale pointer gone everywhere; runner doc states order + write-ownership rule; zero behavior change.

Non-goals stated: tenant dimension (spec exists) and the retention loop (separate spec), plus the `inspectTimeout` shared-budget caveat recorded as a documented limitation only.
