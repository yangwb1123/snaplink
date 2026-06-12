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
