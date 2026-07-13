package web

import "embed"

// LoginFS embeds the hosted-login SPA assets. Pass the sub-filesystem
// (fs.Sub(LoginFS, "login")) to sso.WithHostedLoginFS so the SPA is served
// at /login/. Nil when not embedded — the operator's cmd binary controls
// whether to wire it.
//
//go:embed login
var LoginFS embed.FS

// AdminFS embeds the hosted admin console SPA assets. Pass the sub-filesystem
// (fs.Sub(AdminFS, "admin")) to sso.WithAdminConsoleFS so the SPA is served
// at /admin/. The console communicates with the server via the existing
// /api/v1/admin/* REST endpoints using a Bearer token with admin:read or
// admin:write scope.
//
//go:embed admin
var AdminFS embed.FS

// PortalFS embeds the end-user self-service portal SPA assets. Pass the
// sub-filesystem (fs.Sub(PortalFS, "portal")) to sso.WithSelfServicePortalFS
// so the SPA is served at /portal/. The portal is a standalone browser client
// that calls the /me, /sessions/me, /consents/me, /me/password and /me/mfa
// endpoints with the end-user's own Bearer token.
//
//go:embed portal
var PortalFS embed.FS

// DeveloperFS embeds the developer-portal SPA assets. Pass the
// sub-filesystem (fs.Sub(DeveloperFS, "developer")) to
// sso.WithDeveloperPortalFS so the SPA is served at /developer/. Unlike
// the admin console and self-service portal (both authenticated, either
// via admin bearer or an end-user's own token), this SPA is for an
// ANONYMOUS third-party developer: it calls POST /register (RFC 7591 DCR)
// to self-register a new OAuth client, then GET/PUT/DELETE
// /register/:client_id (RFC 7592) — authenticated by the
// registration_access_token issued at registration, never an admin or
// end-user credential.
//
//go:embed developer
var DeveloperFS embed.FS

// SetupFS embeds the first-run setup-wizard SPA assets. Pass the
// sub-filesystem (fs.Sub(SetupFS, "setup")) to sso.WithSetupWizardFS so the
// SPA is served at /setup/. The wizard is a standalone browser client that
// calls GET /api/v1/setup/status and POST /api/v1/setup to provision the first
// administrator before any credential exists. Nil when not embedded — the
// operator's cmd binary controls whether to wire it.
//
//go:embed setup
var SetupFS embed.FS
