package commerce

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

var (
	ErrNotEntitled        = errors.New("commerce: feature not entitled")
	ErrCommercialQuota    = errors.New("commerce: commercial quota exceeded")
	ErrInvalidConsumption = errors.New("commerce: invalid quota consumption")
)

type DecisionReason string

const (
	DecisionAllowed         DecisionReason = "allowed"
	DecisionNotEntitled     DecisionReason = "not_entitled"
	DecisionFeatureDisabled DecisionReason = "feature_disabled"
	DecisionLimitExceeded   DecisionReason = "limit_exceeded"
)

// QuotaDecision is advisory until the owning resource service performs its
// increment atomically with the resource mutation. Central pre-checks alone
// cannot enforce a hard limit safely across replicas.
type QuotaDecision struct {
	Allowed      bool           `json:"allowed"`
	Reason       DecisionReason `json:"reason"`
	Unlimited    bool           `json:"unlimited,omitempty"`
	SoftLimit    int64          `json:"soft_limit,omitempty"`
	HardLimit    int64          `json:"hard_limit,omitempty"`
	Projected    int64          `json:"projected"`
	Remaining    int64          `json:"remaining,omitempty"`
	SoftExceeded bool           `json:"soft_exceeded,omitempty"`
}

type EntitlementReader interface {
	CurrentEntitlement(ctx context.Context, tenantID string) (*EntitlementSnapshot, error)
}

type Enforcer struct {
	reader EntitlementReader
	now    func() time.Time
}

func NewEnforcer(reader EntitlementReader, now func() time.Time) (*Enforcer, error) {
	if reader == nil {
		return nil, ErrStoreRequired
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Enforcer{reader: reader, now: now}, nil
}

func (e *Enforcer) RequireFeature(ctx context.Context, tenantID string, key FeatureKey) error {
	snapshot, err := e.reader.CurrentEntitlement(ctx, tenantID)
	if err != nil {
		return err
	}
	if !snapshot.FeatureEnabled(key, e.now()) {
		return ErrNotEntitled
	}
	return nil
}

func (e *Enforcer) EvaluateLimit(
	ctx context.Context, tenantID string, key LimitKey, current, delta int64,
) (QuotaDecision, error) {
	if current < 0 || delta < 0 || current > math.MaxInt64-delta {
		return QuotaDecision{}, ErrInvalidConsumption
	}
	snapshot, err := e.reader.CurrentEntitlement(ctx, tenantID)
	if err != nil {
		return QuotaDecision{}, err
	}
	grant, ok := snapshot.Limit(key, e.now())
	if !ok {
		return QuotaDecision{Reason: DecisionNotEntitled, Projected: current + delta}, nil
	}
	return evaluateGrant(grant, current+delta), nil
}

func evaluateGrant(grant LimitGrant, projected int64) QuotaDecision {
	decision := QuotaDecision{
		Allowed: true, Reason: DecisionAllowed, Unlimited: grant.Unlimited,
		SoftLimit: grant.Soft, HardLimit: grant.Hard, Projected: projected,
	}
	if grant.Unlimited {
		return decision
	}
	decision.Remaining = max(0, grant.Hard-projected)
	decision.SoftExceeded = grant.Soft > 0 && projected > grant.Soft
	if projected > grant.Hard {
		decision.Allowed, decision.Reason = false, DecisionLimitExceeded
	}
	return decision
}

// ProjectCoreQuota maps the commercial snapshot to Snaplink's local resource
// quota SPI. The *Limited flags preserve the difference between an explicit
// finite hard zero and legacy zero-as-unlimited; missing and unlimited grants
// remain unlimited and must still pass their entitlement feature gate.
func ProjectCoreQuota(snapshot *EntitlementSnapshot, at time.Time) core.TenantQuota {
	if snapshot != nil && (!snapshot.effective(at) || !snapshot.Features[FeatureCoreSSO]) {
		return core.TenantQuota{
			ClientsLimited: true, UsersLimited: true, SessionsLimited: true, TokenRateLimited: true,
		}
	}
	clients, clientsLimited := intLimit(snapshot, LimitClients, at)
	users, usersLimited := intLimit(snapshot, LimitUsers, at)
	sessions, sessionsLimited := intLimit(snapshot, LimitSessions, at)
	tokenRate, tokenRateLimited := intLimit(snapshot, LimitTokenRate, at)
	return core.TenantQuota{
		MaxClients: clients, MaxUsers: users, MaxSessions: sessions, MaxTokenRate: tokenRate,
		ClientsLimited: clientsLimited, UsersLimited: usersLimited,
		SessionsLimited: sessionsLimited, TokenRateLimited: tokenRateLimited,
	}
}

// ProjectQuotaProjection carries the entitlement revision with the exact quota
// projection so a TenantQuotaProjectionStore can reject stale deliveries.
func ProjectQuotaProjection(snapshot *EntitlementSnapshot, at time.Time) core.TenantQuotaProjection {
	if snapshot == nil {
		return core.TenantQuotaProjection{}
	}
	return core.TenantQuotaProjection{Revision: snapshot.Revision, Quota: ProjectCoreQuota(snapshot, at)}
}

func intLimit(snapshot *EntitlementSnapshot, key LimitKey, at time.Time) (int, bool) {
	grant, ok := snapshot.Limit(key, at)
	if !ok || grant.Unlimited {
		return 0, false
	}
	if grant.Hard > int64(math.MaxInt) {
		return math.MaxInt, true
	}
	return int(grant.Hard), true
}
