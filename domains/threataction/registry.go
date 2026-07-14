package threataction

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/spi"
)

// ThreatExecutors is a composite executor that:
//  1. Looks up matching policy (first-match wins, ordered by name)
//  2. Rate-limits per (subject, type, action) tuple
//  3. Executes via the appropriate handler
//  4. Records an audit event for every non-Noop action
//
// FAIL-OPEN: all errors are logged but never propagated. A single broken
// executor must not block sibling actions.
type ThreatExecutors struct {
	policies   ThreatPolicyStore
	handlers   map[Action]ThreatExecutor
	auditor    *audit.Recorder
	logger     spi.Logger
	defaultAct Action // action when no policy matches (default Noop)

	mu        sync.Mutex
	rateLimit map[string]*rateLimitEntry // keyed by RateLimitKey
}

// ThreatExecutorsOption tunes the composite executor.
type ThreatExecutorsOption func(*ThreatExecutors)

// WithDefaultAction sets the action taken when no policy matches.
func WithDefaultAction(a Action) ThreatExecutorsOption {
	return func(te *ThreatExecutors) {
		if a != "" {
			te.defaultAct = a
		}
	}
}

// WithLogger sets the logger for the composite executor.
func WithLogger(l spi.Logger) ThreatExecutorsOption {
	return func(te *ThreatExecutors) {
		if l != nil {
			te.logger = l
		}
	}
}

// NewThreatExecutors builds a composite executor. policies may be nil
// (every threat is a no-op); handlers must map action types to executors.
// If no handler exists for a matched action, the action is skipped (logged).
func NewThreatExecutors(
	policies ThreatPolicyStore,
	handlers map[Action]ThreatExecutor,
	auditor *audit.Recorder,
	opts ...ThreatExecutorsOption,
) *ThreatExecutors {
	te := &ThreatExecutors{
		policies:   policies,
		handlers:   handlers,
		auditor:    auditor,
		logger:     spi.NopLogger{},
		defaultAct: ActionNoop,
		rateLimit:  make(map[string]*rateLimitEntry),
	}
	for _, opt := range opts {
		opt(te)
	}
	return te
}

// Name returns the composite executor identifier.
func (te *ThreatExecutors) Name() string { return "threat_executors" }

// Execute executes all applicable actions for a threat. It:
//  1. Looks up matching policy (first-match wins)
//  2. Rate-limits per (subject, type, action) tuple
//  3. Executes via the appropriate handler
//  4. Records an audit event for every non-Noop action
//
// FAIL-OPEN: errors are logged but never propagated.
func (te *ThreatExecutors) Execute(ctx context.Context, threat Threat, _ ThreatPolicy) (ActionResult, error) {
	if te == nil {
		return ActionResult{Action: ActionNoop, OK: true, Detail: "nil executor"}, nil
	}

	// 1. Look up matching policy (first-match wins, ordered by name).
	policy, err := te.matchPolicy(ctx, threat)
	if err != nil {
		te.logger.Error("threat policy lookup failed", "type", threat.Type, "subject", threat.SubjectID, "error", err)
		policy = te.defaultPolicy()
	}
	if policy == nil {
		// No policy configured. Default to Noop.
		te.logger.Debug("threat: no matching policy", "type", threat.Type, "severity", threat.Severity)
		return ActionResult{Action: ActionNoop, OK: true, Detail: "no matching policy"}, nil
	}

	act := policy.Action
	if act == ActionNoop || act == "" {
		return ActionResult{Action: ActionNoop, OK: true, Detail: "policy action is noop"}, nil
	}

	// 2. Rate-limit check.
	if policy.RateLimit != nil && !te.allow(threat, act, policy.RateLimit) {
		te.logger.Info("threat action rate-limited",
			"type", threat.Type, "action", act, "subject", threat.SubjectID)
		te.recordAudit(ctx, threat, *policy, ActionResult{Action: act, OK: false, Detail: "rate-limited"})
		return ActionResult{Action: act, OK: false, Detail: "rate-limited"}, nil
	}

	// 3. Execute via the appropriate handler.
	handler, ok := te.handlers[act]
	if !ok {
		te.logger.Error("threat: no handler registered for action", "action", act)
		te.recordAudit(ctx, threat, *policy, ActionResult{Action: act, OK: false, Detail: "no handler registered"})
		return ActionResult{Action: act, OK: false, Detail: "no handler registered"}, fmt.Errorf("no handler for action %s", act)
	}

	result, execErr := handler.Execute(ctx, threat, *policy)

	// 4. Record audit event for every non-Noop action.
	te.recordAudit(ctx, threat, *policy, result)

	if execErr != nil {
		te.logger.Error("threat executor failed",
			"executor", handler.Name(), "type", threat.Type,
			"action", act, "subject", threat.SubjectID, "error", execErr)
	}
	return result, execErr
}

// matchPolicy finds the first policy that matches the threat. Policies
// are ordered by name for deterministic behavior.
func (te *ThreatExecutors) matchPolicy(ctx context.Context, threat Threat) (*ThreatPolicy, error) {
	if te.policies == nil {
		return nil, nil
	}
	policies, err := te.policies.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		if p.Match(threat) {
			return &p, nil
		}
	}
	return nil, nil
}

// defaultPolicy returns a noop policy for the default action.
func (te *ThreatExecutors) defaultPolicy() *ThreatPolicy {
	return &ThreatPolicy{
		Name:    "_default",
		Enabled: true,
		Action:  te.defaultAct,
	}
}

// rateLimitSweepThreshold bounds how large te.rateLimit is allowed to grow
// before allow() opportunistically reclaims expired entries.
//
// A (subject, type, action) tuple that stops recurring is never looked up
// again, so the "replace if expired" branch below can't reach it — left
// alone, that entry sits in the map forever and te.rateLimit grows without
// bound over the life of a long-running server. This package can't reuse
// infrastructure/defaultimpl/memreaper's ticker+Close convention used by
// the memory OAuth stores for the identical problem: architecture_layer_test.go
// forbids a domains/ package from importing infrastructure/ (layerExemptions
// is shrink-only, so a new upward edge can't be grandfathered in either), and
// a package-local goroutine would need its own shutdown hook threaded through
// cmd/sso-server for no real benefit here. So allow() instead piggybacks a
// bounded eviction pass on the te.mu lock it already holds, once the map
// crosses this size — no goroutine, no lifecycle to leak, and in the common
// case (map stays small) the extra cost is one integer comparison.
//
// A var (not const) so tests can shrink it for a deterministic trigger
// without needing thousands of synthetic keys.
var rateLimitSweepThreshold = 1024

// allow checks whether the action is within the rate limit for the
// (subject, type, action) tuple.
func (te *ThreatExecutors) allow(threat Threat, act Action, rl *RateLimitPolicy) bool {
	if rl == nil || rl.Max <= 0 || rl.PerWindow.Duration <= 0 {
		return true
	}
	key := RateLimitKey(threat.SubjectID, threat.Type, act)
	now := time.Now()

	te.mu.Lock()
	defer te.mu.Unlock()

	if len(te.rateLimit) > rateLimitSweepThreshold {
		te.evictExpiredLocked(now)
	}

	entry, exists := te.rateLimit[key]
	if !exists || now.After(entry.windowEnd) {
		te.rateLimit[key] = &rateLimitEntry{
			count:     1,
			windowEnd: now.Add(rl.PerWindow.Duration),
		}
		return true
	}
	if entry.count >= rl.Max {
		return false
	}
	entry.count++
	return true
}

// evictExpiredLocked removes every rate-limit entry whose window has
// already passed. Callers MUST hold te.mu. Triggered opportunistically
// from allow() (see rateLimitSweepThreshold) instead of a background
// ticker — bounds te.rateLimit's worst-case size without a goroutine.
func (te *ThreatExecutors) evictExpiredLocked(now time.Time) {
	for k, e := range te.rateLimit {
		if now.After(e.windowEnd) {
			delete(te.rateLimit, k)
		}
	}
}

// Bounds on Threat.Evidence copied into audit metadata by recordAudit.
// threat.Evidence is populated by external detectors (domains/anomaly,
// domains/tokenanomaly) — nothing upstream bounds the number of keys or
// their length, so a misbehaving or compromised detector could otherwise
// grow every audit event without limit. Within these bounds, behavior is
// byte-identical to a plain range+SetMeta loop.
const (
	maxEvidenceKeys     = 32
	maxEvidenceKeyLen   = 128
	maxEvidenceValueLen = 1024
)

// recordAudit emits an audit event for the threat action.
func (te *ThreatExecutors) recordAudit(ctx context.Context, threat Threat, policy ThreatPolicy, result ActionResult) {
	if te.auditor == nil {
		return
	}
	e := &audit.Event{
		Type:    EventThreatActionExecuted,
		Outcome: audit.OutcomeFailure,
		ActorID: threat.SubjectID,
		Reason:  threat.Type,
	}
	if result.OK {
		e.Outcome = audit.OutcomeSuccess
	}
	audit.SetMeta(e, MetaKeyThreatType, threat.Type)
	audit.SetMeta(e, MetaKeyThreatAction, string(result.Action))
	audit.SetMeta(e, MetaKeyThreatSubject, threat.SubjectID)
	audit.SetMeta(e, MetaKeyThreatDetail, result.Detail)
	te.recordEvidence(e, threat)
	if threat.TraceID != "" {
		e.TraceID = threat.TraceID
	}
	if threat.ClientID != "" {
		e.ClientID = threat.ClientID
	}
	te.auditor.Record(ctx, e)
}

// recordEvidence copies threat.Evidence onto e's metadata, bounded per the
// maxEvidence* constants above so an external detector cannot grow an audit
// event without limit. Map iteration order is randomized by Go itself, so
// which keys survive when Evidence exceeds maxEvidenceKeys is unspecified —
// only the count is bounded; within maxEvidenceKeys this is a no-op change
// from a plain range loop.
func (te *ThreatExecutors) recordEvidence(e *audit.Event, threat Threat) {
	if len(threat.Evidence) == 0 {
		return
	}
	truncated := false
	written := 0
	for k, v := range threat.Evidence {
		if written >= maxEvidenceKeys {
			truncated = true
			break
		}
		key, val := k, v
		if len(key) > maxEvidenceKeyLen {
			key = key[:maxEvidenceKeyLen]
			truncated = true
		}
		if len(val) > maxEvidenceValueLen {
			val = val[:maxEvidenceValueLen]
			truncated = true
		}
		audit.SetMeta(e, "threat.evidence."+key, val)
		written++
	}
	if truncated {
		te.logger.Debug("threat: evidence truncated before audit",
			"type", threat.Type, "subject", threat.SubjectID, "evidence_keys", len(threat.Evidence))
	}
}
