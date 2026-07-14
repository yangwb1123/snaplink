package threataction

import (
	"context"
)

// ThreatExecutor maps a single Threat into zero or more Actions,
// consulting the policy store. Executed off the request path.
//
// FAIL-OPEN: a threat-executor error (store unavailable, action backend
// timeout) MUST NOT escalate — it is logged, metric'd, and the next
// threat proceeds. A single broken executor (e.g., SMTP server down)
// must not block session-revocation executors from acting on the SAME
// threat.
type ThreatExecutor interface {
	// Name identifies this executor in metrics + audit events.
	Name() string

	// Execute runs the applicable action(s) for the threat. Returns the
	// actions actually taken and any errors per action.
	Execute(ctx context.Context, threat Threat, policy ThreatPolicy) (ActionResult, error)
}

// ExecuteFunc is a function adapter for ThreatExecutor.
type ExecuteFunc func(ctx context.Context, threat Threat, policy ThreatPolicy) (ActionResult, error)

// Name implements ThreatExecutor.
func (f ExecuteFunc) Name() string { return "func" }

// Execute implements ThreatExecutor.
func (f ExecuteFunc) Execute(ctx context.Context, threat Threat, policy ThreatPolicy) (ActionResult, error) {
	return f(ctx, threat, policy)
}
