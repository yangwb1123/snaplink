# Skill: Add New Handler

**Trigger:** New OAuth/OIDC handler, store, or endpoint.

**Usage:** `python skills/add-new-handler/run.py --name <Name> --type <handler|store> --module <oauth|oidc>`

## Requirements
- bindOAuthParams for parameter binding
- DELETE RETURNING for single-use stores
- Oracle-leak: unknown/expired/consumed -> unified error
- tokenNoStoreHeaders(ctx) on credential/bearer endpoints
- setBearerChallenge(ctx, ...) on every 401
- Wire in sso.go + advertise in discovery
- Add WithXxxStore option
