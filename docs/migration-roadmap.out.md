The roadmap migration has already been completed. Here's a summary of the current state vs. what the roadmap describes:

**Current state (migration DONE):**

| Metric | Roadmap (Old) | Actual (Now) |
|--------|--------------|--------------|
| Root non-test `.go` files | 65 | **0** ✅ |
| `check-root` violations | 70 | **0** ✅ |
| Server package location | Root (`package sso`) | `interfaces/sso/` (111 files) ✅ |
| OAuth handlers | `auth_code_handler.go` etc. | `protocols/oauth/` ✅ |
| OIDC handlers | `backchannel_logout.go` etc. | `protocols/oidc/` ✅ |
| Self-service | Not yet created | `protocols/selfservice/` ✅ |
| Token grants | `token_handler.go` etc. | `internal/handler/tokengrant/` ✅ |
| Security logic | `dpop.go` etc. | `shared/security/` ✅ |
| Federation | `federation_handler.go` | `domains/federation/` ✅ |
| Audit helpers | `audit_helpers.go` | `platform/audit/` ✅ |
| Tenant logic | `tenant_metrics.go` etc. | `domains/tenant/` ✅ |
| Cluster coordination | Root files | `platform/cluster/` ✅ |
| Permissions | Not moved | `domains/permissions/` ✅ |

The migration was completed in commit `2d01b06` ("根目录业务代码重构") which moved all business logic out of root, followed by subsequent architecture refactors. The roadmap document at `docs/migration-roadmap.md` is now a historical record of the plan rather than reflecting current reality.

Would you like me to update the document to reflect the completed state, or would you like to discuss next steps for further refinements?
