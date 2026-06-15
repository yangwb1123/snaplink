# Developer Guide

## First-Time Setup

```bash
# 1. Install Go 1.26+
go version

# 2. Clone and build
git clone https://github.com/snaplink/sso
cd sso
go build ./...

# 3. Initialize engineering tools
bash scripts/setup.sh

# 4. Verify gates
make harness

# 5. Run tests
make test
```

## Daily Development Workflow

```
1. git pull         → sync
2. make harness     → verify current state
3. make help        → see available targets
4. develop          → make changes
5. make harness     → gates must pass
6. make test        → unit tests
7. git commit       → pre-commit checks run
8. git push         → pre-push checks run
```

## Engineering System Overview

The project uses a formal engineering system (see `HARNESS.md`) with 6 automated gates:

| Gate | What | When |
|---|---|---|
| G1: File Size | .go files ≤ 500 lines | pre-commit |
| G2: Complexity | cyclo ≤ 15, cognit ≤ 20 | pre-push |
| G3: Build & Test | go build + go test -race | pre-push |
| G4: Architecture | dependency direction rules | pre-push |
| G5: No Mocks | use Memory* impls instead | review |
| G6: Security | no-store headers, oracle-leak safe | CI |

## Available Make Targets

Run `make help` for the full list. Key targets:

| Target | Purpose |
|---|---|
| `make harness` | All engineering gates |
| `make test` | Unit tests |
| `make race` | Race detector tests |
| `make lint` | golangci-lint |
| `make check-invariants` | Security invariant check |
| `make diagnose` | Codebase health diagnosis |
| `make health-report` | Architecture health report |
| `make trend` | Engineering metrics snapshot |
| `make review` | Code review checklist |

## Writing Code

### Package Ownership

| Package | Owns |
|---|---|
| `core/` | SPIs, interfaces, consts |
| `oauth/` | OAuth grant handlers |
| `oidc/` | OIDC flow handlers |
| `security/` | Lockout, JTI, JWE |
| `defaultimpl/` | Memory/SQLite implementations |
| `admin/` | Admin API |

### Adding an Endpoint

1. Determine ownership (OAuth → `oauth/`, OIDC → `oidc/`)
2. Follow `skills/add-new-handler.md`
3. Wire in `sso.go` route registration
4. Document in `docs/error-codes.md` and `docs/openapi.yaml`
5. Add oracle-leak tests

### Conventions

- No emoji in code, comments, or commits
- Comments explain WHY, never what
- Interface guards in impl packages, not interface packages
- Use `SetMeta(e, k, v)` for audit — never `e.Metadata = map{...}`
- Every credential endpoint: `tokenNoStoreHeaders(ctx)` at entry
- Every 401: `setBearerChallenge(ctx, ...)`
- Oracle-leak: unknown/expired/consumed → unified error

## Common Tasks

### Running a specific test
```bash
go test ./oauth/ -run TestAuthCode -v
```

### Checking file size
```bash
bash .check-filesize.sh handlers.go
```

### Measuring complexity
```bash
gocyclo -top 10 -ignore "gen/proto/" .
```

### Checking architecture
```bash
bash .check-architecture.sh
```

### Viewing trend data
```bash
cat .trends/2026-06.md
```
