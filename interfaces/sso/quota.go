package sso

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/yangwb1123/snaplink/domains/tenant/quotabinding"
	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

const tenantQuotaIncrementFailedReason = "increment_failed"

const (
	tenantQuotaProjectionRealm   = "tenant-quota-projection"
	maxTenantQuotaProjectionBody = 32 << 10
)

// TenantQuotaProjectionSource binds a validated OAuth client and an exact
// source namespace to one tenant. A client may own many tenant sources; the
// request body can only select from that signed client's configured set.
type TenantQuotaProjectionSource = quotabinding.Source

// TenantQuotaProjectionSourceRegistry is a live, monotonic desired-state
// registry. ApplyDesired safely updates a mounted handler without replacing
// its route or loading executable code.
type TenantQuotaProjectionSourceRegistry = quotabinding.Registry

func NewTenantQuotaProjectionSourceRegistry(
	sources []TenantQuotaProjectionSource,
) (*TenantQuotaProjectionSourceRegistry, error) {
	return quotabinding.NewRegistry(sources)
}

// TenantQuotaProjectionReceipt is the monotonic store acknowledgement.
type TenantQuotaProjectionReceipt struct {
	TenantID string `json:"tenant_id"`
	Revision uint64 `json:"revision"`
	Applied  bool   `json:"applied"`
}

type tenantQuotaProjectionHandler struct {
	server   *Server
	store    core.TenantQuotaProjectionStore
	audience string
	sources  *TenantQuotaProjectionSourceRegistry
}

// NewTenantQuotaProjectionHandler builds the machine-only commercial quota
// ingress. Tenant authority comes from (validated client_id, configured
// source_system); tenant_id in JSON is only an exact consistency assertion.
func NewTenantQuotaProjectionHandler(
	server *Server, audience string, sources []TenantQuotaProjectionSource,
) (http.HandlerFunc, error) {
	registry, err := NewTenantQuotaProjectionSourceRegistry(sources)
	if err != nil || len(sources) == 0 {
		return nil, core.ErrInvalidQuotaOperation
	}
	return NewTenantQuotaProjectionHandlerWithRegistry(server, audience, registry)
}

// NewTenantQuotaProjectionHandlerWithRegistry retains a live registry so a
// precompiled module may apply a new desired-state generation in place.
func NewTenantQuotaProjectionHandlerWithRegistry(
	server *Server, audience string, registry *TenantQuotaProjectionSourceRegistry,
) (http.HandlerFunc, error) {
	if server == nil || !validProjectionBindingValue(audience) || registry == nil ||
		len(registry.Snapshot()) == 0 {
		return nil, core.ErrInvalidQuotaOperation
	}
	store, ok := server.tenantQuotaStore.(core.TenantQuotaProjectionStore)
	if !ok {
		return nil, core.ErrUnsupportedOperation
	}
	handler := &tenantQuotaProjectionHandler{
		server: server, store: store, audience: audience, sources: registry,
	}
	return handler.ServeHTTP, nil
}

func validProjectionBindingValue(value string) bool {
	return quotabinding.ValidIdentity(value)
}

type tenantQuotaProjectionRequest struct {
	TenantID     string                     `json:"tenant_id"`
	SourceSystem string                     `json:"source_system"`
	Projection   core.TenantQuotaProjection `json:"projection"`
}

func (h *tenantQuotaProjectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := handlerContextForRequest(w, r)
	tokenNoStoreHeaders(ctx)
	claims, clientID, ok := h.authenticate(ctx)
	if !ok {
		return
	}
	request, ok := decodeTenantQuotaProjectionRequest(ctx)
	if !ok {
		h.record(ctx, audit.OutcomeFailure, clientID, "", "", "invalid_request")
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, core.ErrInvalidRequest))
		return
	}
	if !quotaProjectionMachineClaims(claims, h.audience) {
		h.rejectScope(ctx, clientID, "", "")
		return
	}
	tenantID, bound := h.sources.Resolve(clientID, request.SourceSystem)
	if !bound {
		h.rejectScope(ctx, clientID, "", "")
		return
	}
	if tenantID != request.TenantID {
		h.rejectTenantMismatch(ctx, clientID, tenantID, request.SourceSystem)
		return
	}
	h.apply(ctx, clientID, tenantID, request)
}

func (h *tenantQuotaProjectionHandler) authenticate(
	ctx HandlerContext,
) (*TokenClaims, string, bool) {
	token := dpopSchemeToken(ctx.Request())
	if token == "" {
		h.rejectToken(ctx)
		return nil, "", false
	}
	claims, _, err := h.server.validateAnyToken(ctx.Request().Context(), token)
	if err != nil || claims == nil || claims.TokenUse != core.TokenUseAccessToken ||
		h.server.verifyDPoPBearer(ctx, claims) != nil || h.server.verifyMTLSBearer(ctx, claims) != nil {
		h.rejectToken(ctx)
		return nil, "", false
	}
	return claims, claims.ClientID, true
}

func quotaProjectionMachineClaims(claims *TokenClaims, audience string) bool {
	if claims == nil || claims.ClientID == "" || claims.Subject != claims.ClientID || claims.JTI == "" ||
		!claims.AuthTime.IsZero() || claims.SID != "" || claims.Actor != nil || claims.MayAct != nil ||
		claims.ACR != "" || len(claims.AMR) != 0 {
		return false
	}
	return containsProjectionValue(claims.Audience, audience) &&
		containsProjectionValue(claims.Scopes, core.ScopeTenantQuotaProjectionWrite)
}

func containsProjectionValue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func decodeTenantQuotaProjectionRequest(ctx HandlerContext) (tenantQuotaProjectionRequest, bool) {
	mediaType, _, err := mime.ParseMediaType(ctx.Request().Header.Get("Content-Type"))
	if err != nil || mediaType != core.ContentTypeJSON {
		return tenantQuotaProjectionRequest{}, false
	}
	body := http.MaxBytesReader(ctx.ResponseWriter(), ctx.Request().Body, maxTenantQuotaProjectionBody)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request tenantQuotaProjectionRequest
	if decoder.Decode(&request) != nil {
		return tenantQuotaProjectionRequest{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return tenantQuotaProjectionRequest{}, false
	}
	if core.ValidateQuotaTenantID(request.TenantID) != nil {
		return tenantQuotaProjectionRequest{}, false
	}
	return request, true
}

func (h *tenantQuotaProjectionHandler) apply(
	ctx HandlerContext, clientID, tenantID string, request tenantQuotaProjectionRequest,
) {
	if core.ValidateTenantQuotaProjection(&request.Projection) != nil {
		h.record(ctx, audit.OutcomeFailure, clientID, tenantID, request.SourceSystem, "invalid_projection")
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, core.ErrInvalidRequest))
		return
	}
	applied, err := h.store.ApplyQuotaProjection(
		ctx.Request().Context(), tenantID, &request.Projection,
	)
	if errors.Is(err, core.ErrQuotaRevisionConflict) {
		h.record(ctx, audit.OutcomeFailure, clientID, tenantID, request.SourceSystem, "revision_conflict")
		ctx.JSON(http.StatusConflict, errorBody(ctx, core.ErrQuotaProjectionConflict))
		return
	}
	if err != nil {
		h.server.logger.Error("tenant quota projection apply failed", "tenant_id", tenantID, "client_id", clientID, "error", err)
		h.record(ctx, audit.OutcomeFailure, clientID, tenantID, request.SourceSystem, "store_unavailable")
		ctx.JSON(http.StatusServiceUnavailable, errorBody(ctx, core.ErrQuotaProjectionUnavailable))
		return
	}
	reason := "monotonic_noop"
	if applied {
		reason = "applied"
	}
	h.record(ctx, audit.OutcomeSuccess, clientID, tenantID, request.SourceSystem, reason)
	ctx.JSON(http.StatusOK, TenantQuotaProjectionReceipt{
		TenantID: tenantID, Revision: request.Projection.Revision, Applied: applied,
	})
}

func (h *tenantQuotaProjectionHandler) rejectToken(ctx HandlerContext) {
	h.record(ctx, audit.OutcomeFailure, "", "", "", "invalid_token")
	setBearerChallenge(ctx, tenantQuotaProjectionRealm, core.ErrInvalidToken, "")
	ctx.JSON(http.StatusUnauthorized, errorBody(ctx, core.ErrInvalidToken))
}

func (h *tenantQuotaProjectionHandler) rejectScope(
	ctx HandlerContext, clientID, tenantID, sourceSystem string,
) {
	h.record(ctx, audit.OutcomeFailure, clientID, tenantID, sourceSystem, "insufficient_scope")
	setBearerChallenge(ctx, tenantQuotaProjectionRealm, core.ErrInsufficientScope, "")
	ctx.JSON(http.StatusForbidden, errorBody(ctx, core.ErrInsufficientScope))
}

func (h *tenantQuotaProjectionHandler) rejectTenantMismatch(
	ctx HandlerContext, clientID, tenantID, sourceSystem string,
) {
	h.record(ctx, audit.OutcomeFailure, clientID, tenantID, sourceSystem, core.ErrTenantMismatch)
	setBearerChallenge(ctx, tenantQuotaProjectionRealm, core.ErrTenantMismatch, "")
	ctx.JSON(http.StatusForbidden, errorBody(ctx, core.ErrTenantMismatch))
}

func (h *tenantQuotaProjectionHandler) record(
	ctx HandlerContext, outcome audit.Outcome, clientID, tenantID, sourceSystem, reason string,
) {
	if h.server.auditor == nil {
		return
	}
	event := audit.EventFromRequest(ctx)
	event.Type, event.Outcome, event.Reason = audit.EventTenantQuotaProjectionApplied, outcome, reason
	event.ActorID, event.ClientID, event.TenantID = clientID, clientID, tenantID
	if tenantID != "" && sourceSystem != "" && validProjectionBindingValue(sourceSystem) {
		audit.SetMeta(event, "source_system", sourceSystem)
	}
	h.server.auditor.Record(ctx.Request().Context(), event)
}

// checkQuotaBeforeCreate checks if the tenant has capacity to create a
// resource. denied=true means a 403 was already written and the caller must
// stop; charged=true means the caller MUST compensate with
// releaseResourceQuota if the resource creation subsequently fails, so a
// transient store error never permanently over-counts usage.
func (s *Server) checkQuotaBeforeCreate(ctx HandlerContext, tenantID string, resource core.ResourceType, resourceID string) (charged, denied bool) {
	if s.tenantQuotaStore == nil || tenantID == "" {
		return false, false
	}
	err := s.reserveResourceQuota(ctx.Request().Context(), tenantID, resource, resourceID)
	switch {
	case err == nil:
		return true, false
	case err == core.ErrQuotaExceeded:
		s.logger.Error("tenant quota exceeded", "tenant_id", tenantID, "resource", resource)
		ctx.JSON(http.StatusForbidden, errorBody(ctx, core.ErrQuotaExceededCode))
		return false, true
	default:
		s.logger.Error("quota check failed", "tenant_id", tenantID, "resource", resource, "error", err)
		// Fail-open on store errors — don't block resource creation.
		return false, false
	}
}

// releaseResourceQuota compensates a checkQuotaBeforeCreate charge when the
// resource creation it guarded fails afterward. Fail-open: a decrement error
// is logged, never surfacing over the original creation error.
func (s *Server) releaseResourceQuota(ctx context.Context, tenantID string, resource core.ResourceType, resourceID string) {
	if s.tenantQuotaStore == nil || tenantID == "" {
		return
	}
	var err error
	if leases, ok := s.tenantQuotaStore.(core.TenantQuotaResourceStore); ok && resourceID != "" {
		_, err = leases.ReleaseResource(ctx, tenantID, resource, resourceID)
	} else {
		err = s.tenantQuotaStore.DecrementUsage(ctx, tenantID, resource, 1)
	}
	if err != nil {
		s.logger.Error("tenant quota release failed", "tenant_id", tenantID, "resource", resource, "error", err)
	}
}

func (s *Server) reserveResourceQuota(ctx context.Context, tenantID string, resource core.ResourceType, resourceID string) error {
	if leases, ok := s.tenantQuotaStore.(core.TenantQuotaResourceStore); ok && resourceID != "" {
		_, err := leases.ReserveResource(ctx, tenantID, resource, resourceID)
		return err
	}
	return s.tenantQuotaStore.IncrementUsage(ctx, tenantID, resource, 1)
}

// chargeSessionQuota increments the tenant's session-quota counter before a
// new session is created (createSession, server_logout.go). denied=true
// means a 403 quota_exceeded was already written and the caller must stop
// without creating anything; charged=true means the caller MUST compensate
// with releaseSessionQuota if session creation subsequently fails, so a
// transient session-store error never permanently over-counts usage.
// Fail-open on a non-quota store error (charged=false, denied=false): a
// store outage must not block login.
func (s *Server) chargeSessionQuota(ctx HandlerContext, tenantID, userID string) (charged, denied bool) {
	if s.tenantQuotaStore == nil || tenantID == "" {
		return false, false
	}
	if _, managed := s.sessionMgr.(core.TenantSessionQuotaManager); managed {
		return false, false
	}
	rctx := ctx.Request().Context()
	err := s.tenantQuotaStore.IncrementUsage(rctx, tenantID, core.ResourceSessions, 1)
	if errors.Is(err, core.ErrQuotaExceeded) && s.reconcileSessionQuota(rctx, tenantID) {
		err = s.tenantQuotaStore.IncrementUsage(rctx, tenantID, core.ResourceSessions, 1)
	}
	switch {
	case err == nil:
		return true, false
	case errors.Is(err, core.ErrQuotaExceeded):
		s.denySessionQuota(ctx, tenantID, userID)
		return false, true
	default:
		s.logger.Error("tenant quota check failed", "tenant_id", tenantID, "error", err)
		return false, false
	}
}

func (s *Server) denySessionQuota(ctx HandlerContext, tenantID, userID string) {
	s.logger.Error("tenant session quota exceeded", "tenant_id", tenantID, "user", userID)
	ctx.JSON(http.StatusForbidden, errorBody(ctx, core.ErrQuotaExceededCode))
}

func (s *Server) reconcileSessionQuota(ctx context.Context, tenantID string) bool {
	reconciler, ok := s.sessionMgr.(core.TenantSessionQuotaReconciler)
	if !ok {
		return false
	}
	if err := reconciler.ReconcileTenantSessionQuota(ctx, tenantID); err != nil {
		s.logger.Error("tenant session quota reconciliation failed", "tenant_id", tenantID, "error", err)
		return false
	}
	return true
}

// releaseSessionQuota compensates a chargeSessionQuota charge when the
// session creation it guarded fails afterward. Fail-open: a decrement error
// is logged, never surfacing over the original session-creation error.
func (s *Server) releaseSessionQuota(rctx context.Context, tenantID string) {
	if err := s.tenantQuotaStore.DecrementUsage(rctx, tenantID, core.ResourceSessions, 1); err != nil {
		s.logger.Error("tenant session quota release failed", "tenant_id", tenantID, "error", err)
	}
}

// CheckClientCreateQuota is the oauth.RegisterDeps seam that makes the tenant
// client-create quota LIVE on the DCR /register path. It charges one unit of
// core.ResourceClients against the tenant; denied=true means a 403
// quota_exceeded was already written (the caller must stop). charged=true
// means the caller MUST call ReleaseClientCreateQuota if the client-store
// write subsequently fails. Skips (false, false) when no quota store is
// wired or the client is tenant-less, and fails OPEN on a non-quota store
// error — matching the createSession session-quota precedent.
func (s *Server) CheckClientCreateQuota(ctx HandlerContext, tenantID, clientID string) (charged, denied bool) {
	return s.checkQuotaBeforeCreate(ctx, tenantID, core.ResourceClients, clientID)
}

// ReleaseClientCreateQuota releases the client counter after a failed charged
// create or a successful DCR delete.
func (s *Server) ReleaseClientCreateQuota(ctx context.Context, tenantID, clientID string) {
	s.releaseResourceQuota(ctx, tenantID, core.ResourceClients, clientID)
}

// ReleaseDeletedClientQuota is the admin-client lifecycle hook. The full
// stored record supplies TenantID without adding it to the stable admin proto.
func (s *Server) ReleaseDeletedClientQuota(ctx context.Context, client *Client) {
	if client != nil {
		s.releaseResourceQuota(ctx, client.TenantID, core.ResourceClients, client.ID)
	}
}

// consumeTokenRateQuota charges one authenticated, tenant-matched /token
// dispatch. A successful idempotency replay never reaches this helper. Quota
// exhaustion uses the stable rate_limited response; dependency failures are
// observable but fail open so an outage cannot become an authentication outage.
func (s *Server) consumeTokenRateQuota(ctx HandlerContext, client *Client) bool {
	if s.tenantQuotaStore == nil || client == nil || client.TenantID == "" {
		return false
	}
	err := s.tenantQuotaStore.IncrementUsage(ctx.Request().Context(), client.TenantID, core.ResourceTokenRate, 1)
	if err == nil {
		return false
	}
	if errors.Is(err, core.ErrQuotaExceeded) {
		ctx.ResponseWriter().Header().Set(ratelimit.HeaderRetryAfter, strconv.Itoa(1))
		ctx.JSON(http.StatusTooManyRequests, errorBody(ctx, ratelimit.ErrRateLimited))
		return true
	}
	s.logger.Error("tenant token quota check failed", "tenant_id", client.TenantID, "client_id", client.ID, "error", err)
	s.recordTenantQuotaStoreFailure(ctx, client.ID, client.TenantID, core.ResourceTokenRate)
	return false
}

func (s *Server) dispatchTokenGrantWithQuota(ctx HandlerContext, client *Client, req oauth.TokenRequest, dpopJKT, mtlsX5T, idemKey string, idemRW *middleware.CaptureWriter) {
	if !s.consumeTokenRateQuota(ctx, client) {
		s.dispatchTokenGrant(ctx, client, req, dpopJKT, mtlsX5T)
	}
	s.finishTokenIdempotency(ctx, idemKey, idemRW)
}

func (s *Server) recordTenantQuotaStoreFailure(ctx HandlerContext, clientID, tenantID string, resource core.ResourceType) {
	if s.auditor == nil {
		return
	}
	e := audit.EventFromRequest(ctx)
	e.Type = audit.EventTenantQuotaStoreFailure
	e.Outcome = audit.OutcomeFailure
	e.ClientID = clientID
	e.TenantID = tenantID
	e.Reason = tenantQuotaIncrementFailedReason
	audit.SetMeta(e, "resource", string(resource))
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordRoleResolutionFailure emits the role_resolution_failed audit event
// when the mint path's tenant-roster lookup failed (details-only-in-audit
// discipline): the wire keeps its byte-identical shape — the token is still
// minted with the roles claim omitted — and the failure evidence (tenant,
// user, client) lives only in the audit row, never in a response or error
// body. A log-only outage would be forensically unrecoverable: the degraded
// artifact IS the deliverable (a valid token missing an authorization
// input), so the event is the permanent record of the fail-open window.
func (s *Server) recordRoleResolutionFailure(ctx HandlerContext, client *Client, userID string) {
	if s.auditor == nil {
		return
	}
	e := audit.EventFromRequest(ctx)
	e.Type = audit.EventRoleResolutionFailed
	e.Outcome = audit.OutcomeFailure
	e.ClientID = client.ID
	e.TenantID = client.TenantID
	e.ActorID = userID
	e.Reason = "tenant_roster_lookup_failed"
	s.auditor.Record(ctx.Request().Context(), e)
}
