// Package composition hosts the edition-generic server composition shared by
// the two small-edition composition roots (cmd/sso-prototype and
// cmd/sso-minimal). It wires the in-memory stores, the OP-session lifecycle,
// CLI/config parsing, HTTP serving, and the OAuth metadata surface envelope
// that both editions share; each root supplies its own Edition descriptor,
// surface hooks, and OIDC/tracing option hook so that edition-specific code
// (the minimal OIDC surface) is compiled only into its own root.
//
// The package is classified as the composition layer: it may import the whole
// stack, and only cmd/ roots import it. Edition-generic code lives here
// exactly once — the two editions must not drift two copies of the same
// behavior (see docs/design/prototype-minimal-physical-isolation.md).
package composition

// Edition describes one small-server runtime surface. The descriptor is data:
// the runtime behavior that differs between editions (OIDC/tracing wiring,
// scopes, feature gates, unlocked-build inventory) is driven from it, while
// surface code that must be compiled per edition stays in each cmd root.
type Edition struct {
	// Profile is the buildinfo profile identity ("prototype" or "minimal").
	Profile string

	// OIDC enables the common OIDC surface (discovery, ID Token, UserInfo,
	// logout) — minimal-only.
	OIDC bool

	// Tracing enables the request-tracing middleware — minimal-only.
	Tracing bool

	// DefaultScopes are the seeded client scopes ("profile,email" for
	// prototype; "openid,profile,email" for minimal).
	DefaultScopes string

	// Modules and Capabilities are the unlocked-build inventory fallback
	// (plain `go build` without profile ldflags): each root reports its own
	// edition's module/capability identity.
	Modules      []string
	Capabilities []string
}
