package serverbuildstore

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

const (
	sessionQuotaReconcileAttempts = 16
	sessionQuotaPendingGrace      = 30 * time.Second
)

// WrapSessionManagerWithTenantQuota adds exact lifecycle leases to a durable
// session manager. A session remains quota_pending and unusable until its
// lease is durable; exact-set CAS reconciliation repairs expiry and crashes.
func WrapSessionManagerWithTenantQuota(
	ctx context.Context,
	sessions core.SessionManager,
	quotas core.TenantQuotaStore,
	logger spi.Logger,
) (core.SessionManager, error) {
	resources, ok := quotas.(core.TenantQuotaResourceSetStore)
	meta, hasMeta := sessions.(core.SessionMetaCreator)
	kinds, hasKinds := sessions.(core.SessionKindManager)
	if sessions == nil || !ok || !hasMeta || !hasKinds {
		return sessions, nil
	}
	wrapped := &quotaSessionManager{
		sessions: sessions,
		meta:     meta,
		kinds:    kinds,
		quotas:   resources,
		logger:   logger,
	}
	if err := wrapped.reconcileKnownTenants(ctx); err != nil {
		return nil, err
	}
	return wrapped, nil
}

type quotaSessionManager struct {
	sessions core.SessionManager
	meta     core.SessionMetaCreator
	kinds    core.SessionKindManager
	quotas   core.TenantQuotaResourceSetStore
	logger   spi.Logger
	stateMu  sync.RWMutex
}

func (m *quotaSessionManager) Create(ctx context.Context, userID string) (*core.Session, error) {
	return m.sessions.Create(ctx, userID)
}

func (m *quotaSessionManager) CreateWithMeta(ctx context.Context, userID string, meta core.SessionMeta) (*core.Session, error) {
	if meta.TenantID == "" || meta.Kind == core.SessionKindAdminImpersonation {
		return m.meta.CreateWithMeta(ctx, userID, meta)
	}
	originalKind := meta.Kind
	meta.Kind = core.SessionKindQuotaPending
	session, err := m.meta.CreateWithMeta(ctx, userID, meta)
	if err != nil {
		return nil, err
	}
	if err := m.reserveSessionQuota(ctx, session); err != nil {
		return m.handleReservationFailure(ctx, session, originalKind, err)
	}
	return m.publishSession(ctx, session, originalKind)
}

func (m *quotaSessionManager) reserveSessionQuota(ctx context.Context, session *core.Session) error {
	_, err := m.quotas.ReserveResource(ctx, session.TenantID, core.ResourceSessions, session.ID)
	if !errors.Is(err, core.ErrQuotaExceeded) {
		return err
	}
	if reconcileErr := m.ReconcileTenantSessionQuota(ctx, session.TenantID); reconcileErr != nil {
		if m.logger != nil {
			m.logger.Error("tenant session quota reconciliation failed",
				"tenant_id", session.TenantID, "error", reconcileErr)
		}
		return core.ErrQuotaExceeded
	}
	_, err = m.quotas.ReserveResource(ctx, session.TenantID, core.ResourceSessions, session.ID)
	return err
}

func (m *quotaSessionManager) handleReservationFailure(
	ctx context.Context,
	session *core.Session,
	originalKind string,
	err error,
) (*core.Session, error) {
	if errors.Is(err, core.ErrQuotaExceeded) {
		_ = m.sessions.Destroy(ctx, session.ID)
		return nil, core.ErrQuotaExceeded
	}
	if m.logger != nil {
		m.logger.Error("tenant session quota reservation failed open",
			"tenant_id", session.TenantID, "session_id", session.ID, "error", err)
	}
	return m.publishSession(ctx, session, originalKind)
}

func (m *quotaSessionManager) publishSession(
	ctx context.Context,
	session *core.Session,
	kind string,
) (*core.Session, error) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if err := m.kinds.SetKind(ctx, session.ID, kind); err != nil {
		m.releaseQuota(ctx, session)
		_ = m.sessions.Destroy(ctx, session.ID)
		return nil, err
	}
	published := *session
	published.Kind = kind
	return &published, nil
}

func (m *quotaSessionManager) Get(ctx context.Context, sessionID string) (*core.Session, error) {
	session, err := m.snapshotSession(ctx, sessionID)
	if err == nil && session != nil && session.Kind == core.SessionKindQuotaPending {
		return nil, core.ErrSessionNotFound
	}
	return session, err
}

func (m *quotaSessionManager) Destroy(ctx context.Context, sessionID string) error {
	session, getErr := m.snapshotSession(ctx, sessionID)
	m.stateMu.Lock()
	if err := m.sessions.Destroy(ctx, sessionID); err != nil {
		m.stateMu.Unlock()
		return err
	}
	m.stateMu.Unlock()
	if getErr != nil {
		m.logLookupFailure(sessionID, getErr)
		return nil
	}
	m.releaseQuota(ctx, session)
	return nil
}

func (m *quotaSessionManager) Refresh(ctx context.Context, sessionID string) (*core.Session, error) {
	if _, err := m.Get(ctx, sessionID); err != nil {
		return nil, err
	}
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	session, err := m.sessions.Refresh(ctx, sessionID)
	return cloneSession(session), err
}

func (m *quotaSessionManager) ListByUser(ctx context.Context, userID string) ([]*core.Session, error) {
	sessions, err := m.sessions.ListByUser(ctx, userID)
	return m.publishedSessions(sessions), err
}

func (m *quotaSessionManager) ListAll(ctx context.Context) ([]*core.Session, error) {
	sessions, err := m.sessions.ListAll(ctx)
	return m.publishedSessions(sessions), err
}

func (m *quotaSessionManager) TrackActivity(ctx context.Context, sessionID string) error {
	tracker, ok := m.sessions.(core.SessionActivityTracker)
	if !ok {
		return core.ErrUnsupportedOperation
	}
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return tracker.TrackActivity(ctx, sessionID)
}

func (m *quotaSessionManager) SetAuthorizedScopes(ctx context.Context, sessionID string, scopes []string) error {
	manager, ok := m.sessions.(core.SessionAuthorizationManager)
	if !ok {
		return core.ErrUnsupportedOperation
	}
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return manager.SetAuthorizedScopes(ctx, sessionID, scopes)
}

func (m *quotaSessionManager) MarkStepUp(ctx context.Context, sessionID string) error {
	manager, ok := m.sessions.(core.SessionTrustManager)
	if !ok {
		return core.ErrUnsupportedOperation
	}
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return manager.MarkStepUp(ctx, sessionID)
}

func (m *quotaSessionManager) SetTrust(ctx context.Context, sessionID string, score float64, setAt time.Time) error {
	manager, ok := m.sessions.(core.SessionTrustManager)
	if !ok {
		return core.ErrUnsupportedOperation
	}
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return manager.SetTrust(ctx, sessionID, score, setAt)
}

func (m *quotaSessionManager) ListByTenant(ctx context.Context, tenantID string) ([]*core.Session, error) {
	sessions, err := m.rawTenantSessions(ctx, tenantID)
	return m.publishedSessions(sessions), err
}

func (m *quotaSessionManager) rawTenantSessions(ctx context.Context, tenantID string) ([]*core.Session, error) {
	if tenantID == "" {
		return []*core.Session{}, nil
	}
	if lister, ok := m.sessions.(core.SessionTenantLister); ok {
		return lister.ListByTenant(ctx, tenantID)
	}
	all, err := m.sessions.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	return filterTenantSessions(all, tenantID), nil
}

func (m *quotaSessionManager) DeleteByTenant(ctx context.Context, tenantID string) (int, error) {
	sessions, err := m.rawTenantSessions(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, session := range sessions {
		if session == nil {
			continue
		}
		if err := m.Destroy(ctx, session.ID); err != nil {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

func (m *quotaSessionManager) ReconcileTenantSessionQuota(ctx context.Context, tenantID string) error {
	for range sessionQuotaReconcileAttempts {
		usage, err := m.quotas.GetResourceUsage(ctx, tenantID, core.ResourceSessions)
		if err != nil {
			return err
		}
		active, err := m.activeTenantSessionIDs(ctx, tenantID)
		if err != nil {
			return err
		}
		_, err = m.quotas.ReconcileResourceSet(
			ctx, tenantID, core.ResourceSessions, active, usage.Generation,
		)
		if !errors.Is(err, core.ErrQuotaRevisionConflict) {
			return err
		}
	}
	return core.ErrQuotaRevisionConflict
}

func (m *quotaSessionManager) ManagesTenantSessionQuota() {}

func (m *quotaSessionManager) Close() error {
	closer, ok := m.sessions.(io.Closer)
	if !ok {
		return nil
	}
	return closer.Close()
}

func (m *quotaSessionManager) activeTenantSessionIDs(ctx context.Context, tenantID string) ([]string, error) {
	all, err := m.sessions.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	active := make([]string, 0)
	for _, candidate := range all {
		if candidate == nil {
			continue
		}
		session, err := m.snapshotSession(ctx, candidate.ID)
		if errors.Is(err, core.ErrSessionNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		include, err := m.includeReconciledSession(ctx, session, tenantID)
		if err != nil {
			return nil, err
		}
		if include {
			active = append(active, session.ID)
		}
	}
	return active, nil
}

func (m *quotaSessionManager) includeReconciledSession(
	ctx context.Context,
	session *core.Session,
	tenantID string,
) (bool, error) {
	if !quotaManagedSession(session, tenantID) {
		return false, nil
	}
	if session.Kind != core.SessionKindQuotaPending {
		return true, nil
	}
	if time.Now().After(session.CreatedAt.Add(sessionQuotaPendingGrace)) {
		return false, m.Destroy(ctx, session.ID)
	}
	return m.quotas.ResourceLeaseActive(ctx, tenantID, core.ResourceSessions, session.ID)
}

func (m *quotaSessionManager) reconcileKnownTenants(ctx context.Context) error {
	all, err := m.sessions.ListAll(ctx)
	if err != nil {
		return err
	}
	tenants := make(map[string]struct{})
	for _, session := range all {
		if quotaManagedSession(session, session.TenantID) {
			tenants[session.TenantID] = struct{}{}
		}
	}
	for tenantID := range tenants {
		if err := m.ReconcileTenantSessionQuota(ctx, tenantID); err != nil {
			return err
		}
	}
	return nil
}

func (m *quotaSessionManager) releaseQuota(ctx context.Context, session *core.Session) {
	if !quotaManagedSession(session, session.TenantID) {
		return
	}
	_, err := m.quotas.ReleaseResource(ctx, session.TenantID, core.ResourceSessions, session.ID)
	if err != nil && m.logger != nil {
		m.logger.Error("tenant session quota release failed",
			"tenant_id", session.TenantID, "session_id", session.ID, "error", err)
	}
}

func (m *quotaSessionManager) logLookupFailure(sessionID string, err error) {
	if errors.Is(err, core.ErrSessionNotFound) || m.logger == nil {
		return
	}
	m.logger.Error("tenant session quota lookup failed", "session_id", sessionID, "error", err)
}

func quotaManagedSession(session *core.Session, tenantID string) bool {
	return session != nil && tenantID != "" && session.TenantID == tenantID &&
		session.Kind != core.SessionKindAdminImpersonation
}

func filterTenantSessions(sessions []*core.Session, tenantID string) []*core.Session {
	filtered := make([]*core.Session, 0)
	for _, session := range sessions {
		if session != nil && session.TenantID == tenantID {
			filtered = append(filtered, session)
		}
	}
	return filtered
}

func (m *quotaSessionManager) snapshotSession(ctx context.Context, sessionID string) (*core.Session, error) {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	session, err := m.sessions.Get(ctx, sessionID)
	return cloneSession(session), err
}

func (m *quotaSessionManager) publishedSessions(sessions []*core.Session) []*core.Session {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	filtered := make([]*core.Session, 0, len(sessions))
	for _, session := range sessions {
		if session != nil && session.Kind != core.SessionKindQuotaPending {
			filtered = append(filtered, cloneSession(session))
		}
	}
	return filtered
}

func cloneSession(session *core.Session) *core.Session {
	if session == nil {
		return nil
	}
	cloned := *session
	cloned.AuthorizedScopes = append([]string(nil), session.AuthorizedScopes...)
	return &cloned
}

var (
	_ core.SessionManager              = (*quotaSessionManager)(nil)
	_ core.SessionMetaCreator          = (*quotaSessionManager)(nil)
	_ core.SessionActivityTracker      = (*quotaSessionManager)(nil)
	_ core.SessionAuthorizationManager = (*quotaSessionManager)(nil)
	_ core.SessionTrustManager         = (*quotaSessionManager)(nil)
	_ core.SessionTenantLister         = (*quotaSessionManager)(nil)
	_ core.SessionTenantIndex          = (*quotaSessionManager)(nil)
	_ core.TenantSessionQuotaManager   = (*quotaSessionManager)(nil)
	_ io.Closer                        = (*quotaSessionManager)(nil)
)
