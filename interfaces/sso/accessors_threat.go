package sso

import (
	"github.com/yangwb1123/snaplink/domains/threataction"
	"github.com/yangwb1123/snaplink/domains/tokenexchange"
	"github.com/yangwb1123/snaplink/interfaces/admin"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Active ITDR threat-policy admin route-path re-exports.
const PathAdminThreatPolicies = core.PathAdminThreatPolicies
const PathAdminThreatPolicyByID = core.PathAdminThreatPolicyByID

// threatState is the Active ITDR detection-to-response bridge wiring.
// Embedded anonymously in [Server] via sso.go so its fields are promoted.
type threatState struct {
	// threatPolicyStore persists threat-to-action mapping rules. Nil ⇒ no
	// admin policy CRUD mounted — byte-identical without the feature.
	threatPolicyStore threataction.ThreatPolicyStore

	// threatExecutor translates anomaly/token-anomaly signals into
	// security actions. Nil (default) = no-op, byte-identical to current
	// behavior.
	threatExecutor threataction.ThreatExecutor
}

// ThreatPolicyStore exposes the wired threat-policy store for admin CRUD.
// May be nil — the admin policy routes are only mounted when non-nil.
func (s *Server) ThreatPolicyStore() threataction.ThreatPolicyStore {
	return s.threatPolicyStore
}

// ThreatExecutor exposes the wired threat executor for Active ITDR.
// May be nil — anomaly/token-anomaly pipelines check it before calling.
func (s *Server) ThreatExecutor() threataction.ThreatExecutor {
	return s.threatExecutor
}

// WithThreatPolicyStore wires the Active ITDR threat-policy store
// (domains/threataction.ThreatPolicyStore) that persists threat-to-action
// mapping rules. When set, the Server mounts admin CRUD endpoints at
// /api/v1/admin/threat-policies (admin:read / admin:write gated).
//
// nil store = no admin policy surface — byte-identical to a build without
// the feature. Combine with [WithThreatExecutor] to also wire the executor
// that anomaly.Runner and tokenanomaly.Detector consult.
func WithThreatPolicyStore(store threataction.ThreatPolicyStore) Option {
	return func(s *Server) { s.threatPolicyStore = store }
}

// WithThreatExecutor wires the Active ITDR composite threat executor
// (domains/threataction.ThreatExecutors) that translates anomaly and
// token-anomaly signals into security actions (session suspension, token
// family revocation, MFA step-up).
//
// When set, the anomaly.Runner (if wired via [WithAnomalyRunner]) and the
// tokenanomaly.Detector (if wired via [WithTokenAnomalyDetector]) each call
// executor.Execute for every detected signal/finding. Nil (default) = no-op,
// byte-identical to current behavior.
func WithThreatExecutor(exec threataction.ThreatExecutor) Option {
	return func(s *Server) { s.threatExecutor = exec }
}

// --- RFC 8693 token-exchange delegation-chain wiring ---
//
// Unrelated to Active ITDR above; appended to this file rather than its own
// (interfaces/sso is at its frozen 60-file directory-fanout ceiling —
// directory_fanout_test.go — so a new file here would regress that budget)
// rather than growing an already-at-budget file elsewhere in the package.

// tokenExchangeChainState is the RFC 8693 token-exchange delegation-chain
// persistence + read-visibility wiring. PURE OBSERVABILITY (see
// domains/tokenexchange.ChainStore's doc comment): adds no new exchange
// semantics, no cascade-revocation, and no cycle-detection beyond what
// internal/handler/tokengrant already enforces unconditionally. Embedded
// anonymously in Server via sso.go so its field is promoted.
type tokenExchangeChainState struct {
	// tokenExchangeChainStore persists RFC 8693 act-chain hops recorded by
	// HandleTokenExchangeGrant (WithTokenExchangeChainStore). Nil (default)
	// = no hop is ever recorded and the admin read endpoint is not mounted —
	// byte-identical to a build without this feature.
	tokenExchangeChainStore tokenexchange.ChainStore
}

// TokenExchangeChainStore returns the wired delegation-chain store, or nil
// when unwired (tokengrant's tokExRecordChainHop is then a no-op).
func (s *Server) TokenExchangeChainStore() tokenexchange.ChainStore {
	return s.tokenExchangeChainStore
}

// WithTokenExchangeChainStore wires an OPTIONAL RFC 8693 token-exchange
// delegation-chain persistence + read-visibility store
// (domains/tokenexchange.ChainStore). When set, every successful
// token-exchange grant best-effort records the hop it just produced
// (FAIL-OPEN — a store error or unavailability NEVER fails the grant, see
// tokenexchange.RecordHopFailOpen), and the admin read endpoint
// GET /api/v1/admin/tokenexchange/chains/:jti is mounted (admin:read).
//
// This is pure, append-only OBSERVABILITY: it does not change token-exchange
// semantics, add cascade-revocation, or add cycle-detection — the existing
// in-request MaxActChainDepth cap + act-chain cycle check (internal/handler/
// tokengrant) are unaffected and unrelated. Reference implementations:
// domains/tokenexchange/memory (dev/test, no persistence across restart) and
// domains/tokenexchange/sqlite (durable, multi-replica).
//
// nil (the default) is a complete no-op — byte-identical to a build without
// this feature.
func WithTokenExchangeChainStore(store tokenexchange.ChainStore) Option {
	return func(s *Server) { s.tokenExchangeChainStore = store }
}

// handleAdminTokenExchangeChain serves GET
// /api/v1/admin/tokenexchange/chains/:jti — the recorded RFC 8693 delegation
// chain for one minted access token's jti. Admin-gated (admin:read) via the
// /api/v1/admin/ prefix. Only mounted when a ChainStore is wired (see
// mountAdminTokenExchangeChainRoutes), so s.tokenExchangeChainStore is
// always non-nil here in production; HandleTokenExchangeChain itself is also
// nil-tolerant for direct unit-test calls.
func (s *Server) handleAdminTokenExchangeChain(ctx HandlerContext) {
	admin.HandleTokenExchangeChain(s.tokenExchangeChainStore, s.logger, ctx)
}

// mountAdminTokenExchangeChainRoutes registers the token-exchange chain read
// endpoint. Kept here (rather than mountAdminSurface/mountAdminTokenGovernance
// in server_routes_admin.go) because that file is already at its 500-line
// maintainability budget from concurrent expiry-calendar work landing in
// parallel; this avoids touching it. Called directly from Mount()
// (server_routes.go). Not mounted without a store — byte-identical to a
// build without the feature.
func (s *Server) mountAdminTokenExchangeChainRoutes() {
	if s.tokenExchangeChainStore == nil {
		return
	}
	api := core.NewGatedRouter(s.router.Group(PathAPIPrefix), s.adminAPIGateOn)
	api.GET(core.PathAdminTokenExchangeChain, s.handleAdminTokenExchangeChain)
}
