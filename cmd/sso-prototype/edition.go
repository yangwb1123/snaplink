package main

import "github.com/yangwb1123/snaplink/internal/composition"

// edition is the prototype runtime surface: smallest runnable SSO/OAuth
// slice — Authorization Code + mandatory PKCE, password login and the
// reusable OP session, basic JSON logs, memory defaults, and the stable
// default tenant. The OIDC surface (discovery, ID Token, UserInfo, logout)
// and request tracing are minimal-only and are NOT part of this composition
// root, so none of that code is compiled into the prototype binary.
var edition = composition.Edition{
	Profile:       "prototype",
	OIDC:          false,
	Tracing:       false,
	DefaultScopes: "profile,email",
	Modules: []string{
		"core-runtime",
		"sso-prototype-runtime",
	},
	Capabilities: []string{
		"config.host.v1",
		"core.runtime.v1",
		"lifecycle.host.v1",
		"oauth.sso-prototype.v1",
		"observability.logging.v1",
		"security.policy.v1",
		"server.sso-prototype.v1",
		"tenant.default.v1",
	},
}
