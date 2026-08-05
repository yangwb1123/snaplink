package sso

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/yangwb1123/snaplink/domains/threataction"
	"github.com/yangwb1123/snaplink/domains/tokenexchange"
	"github.com/yangwb1123/snaplink/interfaces/admin"
	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/notification"
	"github.com/yangwb1123/snaplink/platform/sse"
	"github.com/yangwb1123/snaplink/shared/core"
)

const ctxKeyAuthHookSkipMFA = "auth_hook_skip_mfa"

type notificationState struct {
	notificationStore           core.NotificationStore
	notificationPreferenceStore core.NotificationPreferenceStore
	notificationRouter          *notification.Router
}

// WithNotificationStore mounts the authenticated inbox and preference API.
func WithNotificationStore(store core.NotificationStore, preferences core.NotificationPreferenceStore) Option {
	return func(s *Server) {
		s.notificationStore, s.notificationPreferenceStore = store, preferences
	}
}

// WithNotificationRouter attaches the asynchronous audit-event delivery tap.
func WithNotificationRouter(router *notification.Router) Option {
	return func(s *Server) { s.notificationRouter = router }
}

func (s *Server) NotificationStore() core.NotificationStore { return s.notificationStore }
func (s *Server) NotificationPreferenceStore() core.NotificationPreferenceStore {
	return s.notificationPreferenceStore
}
func (s *Server) NotificationBroker() *sse.Broker {
	if s.notificationRouter == nil {
		return nil
	}
	return s.notificationRouter.Broker()
}

// StartNotificationRouter starts the optional delivery workers.
func (s *Server) StartNotificationRouter(ctx context.Context) <-chan struct{} {
	if s.notificationRouter != nil {
		return s.notificationRouter.Start(ctx)
	}
	done := make(chan struct{})
	close(done)
	return done
}

func (s *Server) applyNotificationErasureWiring() {
	if s.accountEraser == nil {
		return
	}
	s.accountEraser.Notifications = s.notificationStore
	s.accountEraser.NotificationPreferences = s.notificationPreferenceStore
}

// ShutdownNotificationRouter stops and drains the optional delivery workers.
func (s *Server) ShutdownNotificationRouter(ctx context.Context) error {
	if s.notificationRouter == nil {
		return nil
	}
	return s.notificationRouter.Close(ctx)
}

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
// Threat execution is tenant-scoped by the signal's TenantID: the
// anomaly.Runner refuses to execute a threat whose signal carries no
// tenant (warn log + metric), because the executors act on SubjectID
// with no tenant predicate of their own — a tenant-less signal must
// never act on an ambiguous subject.
//
// When set, the anomaly.Runner (if wired via [WithAnomalyRunner]) and the
// tokenanomaly.Detector (if wired via [WithTokenAnomalyDetector]) each call
// executor.Execute for every detected signal/finding. Nil (default) = no-op,
// byte-identical to current behavior.
func WithThreatExecutor(exec threataction.ThreatExecutor) Option {
	return func(s *Server) { s.threatExecutor = exec }
}

// resolveTenantID resolves a client's tenant for anomaly dispatch.
// Best-effort: unknown/disabled clients and store errors yield empty
// tenant (the anomaly still dispatches tenant-less — fail-open,
// consistent with the runner's non-blocking contract).
func (s *Server) resolveTenantID(ctx HandlerContext, clientID string) string {
	if clientID == "" || s.clientStore == nil {
		return ""
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil || client == nil {
		return ""
	}
	return client.TenantID
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

// authPipelineState holds the optional lifecycle extension registry. It lives
// here because interfaces/sso is at its frozen production-file ceiling.
type authPipelineState struct {
	authHooks *core.AuthHookRegistry
}

// WithAuthHook registers one ordered authentication lifecycle extension.
// Invalid or duplicate registrations panic during server construction so a
// security control can never be silently omitted due to bad startup wiring.
func WithAuthHook(hooks ...core.AuthHook) Option {
	return func(s *Server) {
		if s.authHooks == nil {
			s.authHooks = core.NewAuthHookRegistry(s.observeAuthHook)
		}
		for _, hook := range hooks {
			if err := s.authHooks.Register(hook); err != nil {
				panic(fmt.Sprintf("sso: register auth hook: %v", err))
			}
		}
	}
}

// WithConfiguredAuthHook registers one hook with configuration supplied by the
// composition root instead of the hook implementation.
func WithConfiguredAuthHook(hook core.AuthHook, config core.AuthHookConfig) Option {
	return func(s *Server) {
		if s.authHooks == nil {
			s.authHooks = core.NewAuthHookRegistry(s.observeAuthHook)
		}
		if err := s.authHooks.Register(hook, config); err != nil {
			panic(fmt.Sprintf("sso: register configured auth hook: %v", err))
		}
	}
}

func (s *Server) runPreAuthenticateHook(ctx HandlerContext, req *login.Request, client *Client) bool {
	if s.authHooks == nil || !s.authHooks.Has(core.PhasePreAuthenticate) {
		return false
	}
	_, err := s.authHooks.Execute(ctx.Request().Context(), s.loginHookInput(ctx, req, client, nil, core.PhasePreAuthenticate))
	return s.rejectAuthHook(ctx, req, err)
}

func (s *Server) runPostAuthenticateHook(ctx HandlerContext, req *login.Request, client *Client, result *AuthResult) bool {
	if s.authHooks == nil || !s.authHooks.Has(core.PhasePostAuthenticate) {
		return false
	}
	input := s.loginHookInput(ctx, req, client, result, core.PhasePostAuthenticate)
	output, err := s.authHooks.Execute(ctx.Request().Context(), input)
	if s.rejectAuthHook(ctx, req, err) {
		return true
	}
	if output != nil {
		mergeAuthResultAttributes(result, output.Attributes)
		if output.SkipMFA {
			ctx.Set(ctxKeyAuthHookSkipMFA, true)
		}
	}
	return false
}

func (s *Server) notifyLoginFailedHook(ctx HandlerContext, req *login.Request, code string) {
	if s.authHooks == nil || !s.authHooks.Has(core.PhaseOnLoginFailed) {
		return
	}
	input := s.loginHookInput(ctx, req, nil, nil, core.PhaseOnLoginFailed)
	input.FailureCode = code
	_, _ = s.authHooks.Execute(ctx.Request().Context(), input)
}

func (s *Server) loginHookInput(ctx HandlerContext, req *login.Request, client *Client, result *AuthResult, phase core.LoginPhase) *core.HookInput {
	input := &core.HookInput{Phase: phase, ClientID: req.ClientID, Provider: req.Provider,
		IP: audit.ClientIP(ctx.Request()), Headers: firstHeaderValues(ctx.Request().Header), Scopes: append([]string(nil), req.Scope...)}
	if client != nil {
		input.TenantID = client.TenantID
	}
	if result != nil {
		input.UserID, input.AuthResult = result.UserID, result
	}
	return input
}

func (s *Server) rejectAuthHook(ctx HandlerContext, req *login.Request, err error) bool {
	if err == nil {
		return false
	}
	status, code, ok := core.AuthHookHTTPError(err)
	if !ok {
		status, code = http.StatusForbidden, core.ErrAuthHookRejected
	}
	s.logErrorCtx(ctx, "authentication hook rejected request", "error", err)
	s.recordLoginFailure(ctx, req.ClientID, req.Provider, code)
	s.notifyLoginFailedHook(ctx, req, code)
	ctx.JSON(status, s.authzErrorBodyWithState(ctx, code, req.State))
	return true
}

func authHookSkipsMFA(ctx HandlerContext) bool {
	value, ok := ctx.Get(ctxKeyAuthHookSkipMFA).(bool)
	return ok && value
}

func mergeAuthResultAttributes(result *AuthResult, additions map[string]string) {
	if len(additions) == 0 {
		return
	}
	if result.Attributes == nil {
		result.Attributes = make(map[string]string, len(additions))
	}
	for key, value := range additions {
		result.Attributes[key] = value
	}
}

func firstHeaderValues(headers http.Header) map[string]string {
	values := make(map[string]string, len(headers))
	for name, entries := range headers {
		if len(entries) != 0 {
			values[name] = entries[0]
		}
	}
	return values
}

func (s *Server) authHookIssuer(client *Client, issuer TokenIssuer) TokenIssuer {
	if s.authHooks == nil || (!s.authHooks.Has(core.PhasePreTokenIssuance) && !s.authHooks.Has(core.PhasePostTokenIssuance)) {
		return issuer
	}
	tenantID := ""
	if client != nil {
		tenantID = client.TenantID
	}
	return &pipelineTokenIssuer{inner: issuer, hooks: s.authHooks, tenantID: tenantID}
}

type pipelineTokenIssuer struct {
	inner    TokenIssuer
	hooks    *core.AuthHookRegistry
	tenantID string
}

func (i *pipelineTokenIssuer) Issue(ctx context.Context, subject *Subject, scopes []string) (*Token, error) {
	subjectCopy := cloneHookSubject(subject)
	input := &core.HookInput{Phase: core.PhasePreTokenIssuance, ClientID: subjectCopy.ClientID,
		TenantID: i.tenantID, Provider: subjectCopy.Provider, UserID: subjectCopy.ID,
		Claims: subjectCopy.Claims, Scopes: append([]string(nil), scopes...), SessionID: subjectCopy.SID}
	if output, err := i.hooks.Execute(ctx, input); err != nil {
		return nil, err
	} else if output != nil {
		mergeSubjectClaims(subjectCopy, output.Claims)
	}
	token, err := i.inner.Issue(ctx, subjectCopy, scopes)
	if err != nil {
		return nil, err
	}
	input.Phase, input.Token = core.PhasePostTokenIssuance, token
	_, _ = i.hooks.Execute(ctx, input)
	return token, nil
}

func (i *pipelineTokenIssuer) Validate(ctx context.Context, token string) (*TokenClaims, error) {
	return i.inner.Validate(ctx, token)
}

func (i *pipelineTokenIssuer) Revoke(ctx context.Context, token string) error {
	return i.inner.Revoke(ctx, token)
}

func cloneHookSubject(subject *Subject) *Subject {
	clone := *subject
	clone.Claims = make(map[string]string, len(subject.Claims))
	for key, value := range subject.Claims {
		clone.Claims[key] = value
	}
	clone.Resources = append([]string(nil), subject.Resources...)
	clone.AMR = append([]string(nil), subject.AMR...)
	clone.AuthorizationDetails = append([]byte(nil), subject.AuthorizationDetails...)
	clone.RequestedClaims = append([]byte(nil), subject.RequestedClaims...)
	return &clone
}

func mergeSubjectClaims(subject *Subject, additions map[string]string) {
	if len(additions) == 0 {
		return
	}
	if subject.Claims == nil {
		subject.Claims = make(map[string]string, len(additions))
	}
	for key, value := range additions {
		subject.Claims[key] = value
	}
}

func (s *Server) observeAuthHook(ctx context.Context, execution core.AuthHookExecution) {
	if s.metrics != nil {
		s.metrics.ObserveAuthHookExecution(string(execution.Phase), execution.Name, execution.Outcome, execution.Duration)
	}
	if s.auditor == nil {
		return
	}
	eventType, outcome := audit.EventAuthHookExecuted, audit.OutcomeSuccess
	if execution.Outcome != "success" {
		eventType, outcome = audit.EventAuthHookFailed, audit.OutcomeFailure
	}
	event := &audit.Event{Type: eventType, Outcome: outcome, ActorID: execution.UserID,
		ActorIP: execution.IP, ClientID: execution.ClientID, TenantID: execution.TenantID, Reason: execution.Code}
	audit.SetMeta(event, "auth_hook.phase", string(execution.Phase))
	audit.SetMeta(event, "auth_hook.name", execution.Name)
	audit.SetMeta(event, "auth_hook.duration_ms", strconv.FormatInt(execution.Duration.Milliseconds(), 10))
	audit.SetMeta(event, "auth_hook.continued", strconv.FormatBool(execution.Continued))
	s.auditor.Record(ctx, event)
}

func (s *Server) recordPasswordExpiring(ctx HandlerContext, req *login.Request, result *AuthResult, remaining time.Duration) {
	if s.auditor == nil || remaining > 7*24*time.Hour {
		return
	}
	event := &audit.Event{Type: audit.EventPasswordExpiring, Outcome: audit.OutcomeSuccess,
		ActorID: result.UserID, ActorIP: audit.ClientIP(ctx.Request()), ClientID: req.ClientID}
	days := int((remaining + 24*time.Hour - 1) / (24 * time.Hour))
	audit.SetMeta(event, "days_remaining", strconv.Itoa(days))
	s.auditor.Record(ctx.Request().Context(), event)
}
