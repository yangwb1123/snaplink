package main

import "github.com/yangwb1123/snaplink/internal/composition"

// edition is the minimal runtime surface: it inherits the prototype scope and
// adds the common OIDC surface (discovery, ID Token, UserInfo, logout) and
// request tracing. This composition root is the ONLY one that references the
// OIDC surface, so the OIDC-serving composition code is compiled only into
// the minimal binary.
var edition = composition.Edition{
	Profile:       "minimal",
	OIDC:          true,
	Tracing:       true,
	DefaultScopes: "openid,profile,email",
	Modules: []string{
		"core-runtime",
		"sso-prototype-runtime",
		"sso-minimal-runtime",
	},
	Capabilities: []string{
		"config.host.v1",
		"core.runtime.v1",
		"lifecycle.host.v1",
		"oauth.sso-prototype.v1",
		"observability.logging.v1",
		"observability.tracing.v1",
		"oidc.common.v1",
		"security.policy.v1",
		"server.sso-minimal.v1",
		"server.sso-prototype.v1",
		"tenant.default.v1",
	},
}
