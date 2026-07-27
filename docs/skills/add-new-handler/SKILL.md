# Skill: Add a handler

**Trigger:** Add or change an OAuth/OIDC, self-service, federation/SSF, ReBAC,
or admin HTTP endpoint.

The current `run.py` scaffold is legacy: it emits pre-layer import paths and
must not be used to create code. Follow this checked workflow instead.

## Workflow

1. Choose the owning package. Protocol behavior belongs under `protocols/`;
   business policy belongs under `domains/`; HTTP wiring stays thin in
   `interfaces/sso`.
2. Check the target file and directory frozen ceilings before editing.
3. Bind OAuth form/JSON via `oauth.BindParams` (`bindOAuthParams` in the
   Server); preserve HTTP Basic precedence where applicable.
4. For credential/bearer routes, call `tokenNoStoreHeaders` at entry and use
   `setBearerChallenge` for every 401.
5. Collapse oracle-safe and anti-enumeration failures exactly as `AGENTS.md`
   requires.
6. Consume single-use state atomically; carry refresh `FamilyID` through every
   rotation.
7. Register in the applicable `interfaces/sso/server_routes*.go`; update
   discovery if it advertises the capability.
8. Update `docs/openapi.yaml` and `docs/error-codes.md`.
9. Add unit and cross-server negative-path tests.

## Verify

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
python cli.py check-invariants
make ci
```
