# Code Review Checklist

## Engineering Gates
- [ ] `make harness` passes (filesize + complexity + architecture)
- [ ] No new file > 500 lines, no new function > 15 cyclo
- [ ] Architecture dependency rules satisfied

## Security
- [ ] Credential/bearer endpoints: `tokenNoStoreHeaders(ctx)` at entry
- [ ] Every 401: `setBearerChallenge(ctx, ...)`
- [ ] Oracle-leak: unknown/expired/consumed/mismatch -> unified error response
- [ ] Anti-enumeration: bcrypt dummy hash for unknown users
- [ ] Audit: `SetMeta(e, k, v)`, never `e.Metadata = map{...}`
- [ ] `make check-invariants` passes

## Code Quality
- [ ] No mocks -- Memory* implementations used
- [ ] No emoji in code, comments, or commits
- [ ] Comments explain WHY, not what
- [ ] Error codes documented in docs/error-codes.md
- [ ] Endpoint changes documented in docs/openapi.yaml

## Commit
- [ ] Conventional format: feat(area):, fix(area):, chore:, docs:
- [ ] Imperative subject
- [ ] Body explains WHY, not what
