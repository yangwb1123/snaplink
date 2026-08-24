package configaudit

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Canary window bounds are deliberately constants rather than configuration
// keys: the operator opts in per apply, while the server keeps observation
// bounded even when an admin client is compromised.
const (
	DefaultCanaryWindow       = time.Minute
	DefaultCanaryPollInterval = time.Second
	MinCanaryWindow           = time.Second
	MaxCanaryWindow           = 24 * time.Hour
)

// ErrInvalidCanaryWindow is returned when the explicit window is malformed or
// outside the bounded operator contract.
var ErrInvalidCanaryWindow = errors.New("configaudit: invalid canary window")

// CanaryHealth is the tri-state result of one injected health probe.
type CanaryHealth int

const (
	CanaryHealthy CanaryHealth = iota
	CanaryUnhealthy
	CanaryUnknown
)

// CanaryProbe is the transport-neutral health port used during observation.
// Composition adapts existing storage-health sources to this type.
type CanaryProbe struct {
	Name  string
	Check func(context.Context) CanaryHealth
}

// CanaryController observes an atomically persisted candidate and drives its
// confirmation or rollback. It owns no runtime configuration mutation.
type CanaryController struct {
	store        CanaryStore
	probes       []CanaryProbe
	pollInterval time.Duration
	logger       spi.Logger
	auditor      *audit.Recorder
	wake         chan struct{}
}

// NewCanaryController returns nil when the composition root cannot provide an
// atomic canary store or at least one health probe.
func NewCanaryController(store CanaryStore, probes []CanaryProbe, logger spi.Logger, auditor *audit.Recorder) *CanaryController {
	if store == nil || len(probes) == 0 {
		return nil
	}
	if logger == nil {
		logger = spi.NopLogger{}
	}
	return &CanaryController{
		store: store, probes: append([]CanaryProbe(nil), probes...),
		pollInterval: DefaultCanaryPollInterval, logger: logger,
		auditor: auditor, wake: make(chan struct{}, 1),
	}
}

// ParseCanaryWindow validates the per-request duration. An empty value uses
// the safe default; false/absent canary requests never call this function.
func ParseCanaryWindow(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return DefaultCanaryWindow, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || d < MinCanaryWindow || d > MaxCanaryWindow {
		return 0, ErrInvalidCanaryWindow
	}
	return d, nil
}

// Start atomically applies a candidate and persists its observing state.
func (c *CanaryController) Start(ctx context.Context, v AppliedVersion, window time.Duration) (AppliedVersion, CanaryState, error) {
	if c == nil || c.store == nil {
		return AppliedVersion{}, CanaryState{}, ErrCanaryUnavailable
	}
	if window <= 0 {
		window = DefaultCanaryWindow
	}
	if window < MinCanaryWindow || window > MaxCanaryWindow {
		return AppliedVersion{}, CanaryState{}, ErrInvalidCanaryWindow
	}
	now := time.Now().UTC()
	state := CanaryState{
		Actor: v.Actor, Digest: v.Digest, Reason: v.Reason,
		StartedAt: now, Deadline: now.Add(window), Status: CanaryObserving,
	}
	got, state, err := c.store.BeginCanary(ctx, v, state)
	if err != nil {
		return AppliedVersion{}, CanaryState{}, err
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return got, state, nil
}

// Run starts the observation loop and returns its completion channel. A
// persisted observing record is recovered fail-safe before new observations.
func (c *CanaryController) Run(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	if c == nil {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		c.recoverActive(ctx)
		c.observe(ctx)
		ticker := time.NewTicker(c.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.observe(ctx)
			case <-c.wake:
				c.observe(ctx)
			}
		}
	}()
	return done
}

// PollInterval reports the effective observation cadence for diagnostics and
// tests.
func (c *CanaryController) PollInterval() time.Duration {
	if c == nil {
		return 0
	}
	return c.pollInterval
}

func normalizeCanaryState(state CanaryState, v, prev AppliedVersion) CanaryState {
	if state.ID == "" {
		state.ID = newEntryID()
	}
	state.VersionID = v.ID
	state.PreviousVersionID = prev.ID
	if state.StartedAt.IsZero() {
		state.StartedAt = v.AppliedAt
	}
	if state.Deadline.IsZero() {
		state.Deadline = state.StartedAt.Add(DefaultCanaryWindow)
	}
	state.Status = CanaryObserving
	return state
}

func (c *CanaryController) recoverActive(ctx context.Context) {
	state, err := c.store.Canary(ctx)
	if errors.Is(err, ErrNoCanary) {
		return
	}
	if err != nil {
		c.logger.Error("config canary: load recovery state failed", "error", err)
		return
	}
	if state.Status != CanaryObserving {
		return
	}
	reason := "canary interrupted by process restart"
	c.rollback(ctx, state, reason)
}

func (c *CanaryController) observe(ctx context.Context) {
	state, err := c.store.Canary(ctx)
	if errors.Is(err, ErrNoCanary) || err != nil || state.Status != CanaryObserving {
		if err != nil && !errors.Is(err, ErrNoCanary) {
			c.logger.Error("config canary: load observation state failed", "error", err)
		}
		return
	}
	if unhealthy := c.unhealthyProbes(ctx); len(unhealthy) > 0 {
		reason := "health failure: " + strings.Join(unhealthy, ", ")
		c.rollback(ctx, state, reason)
		return
	}
	if time.Now().UTC().Before(state.Deadline) {
		return
	}
	if err := c.store.ConfirmCanary(ctx, state.ID); err != nil {
		c.logger.Error("config canary: confirm failed", "canary_id", state.ID, "error", err)
		return
	}
	state.Status = CanaryConfirmed
	c.record(ctx, state, audit.EventConfigCanaryConfirmed)
	c.logger.Info("config canary confirmed", "canary_id", state.ID, "version_id", state.VersionID)
}

func (c *CanaryController) rollback(ctx context.Context, state CanaryState, reason string) {
	actor := state.Actor
	if actor == "" {
		actor = "system:config-canary"
	}
	_, updated, err := c.store.RollbackCanary(ctx, state.ID, actor, reason)
	if err != nil {
		c.logger.Error("config canary: automatic rollback failed", "canary_id", state.ID, "error", err)
		return
	}
	updated.Detail = reason
	c.record(ctx, updated, audit.EventConfigCanaryRolledBack)
	c.logger.Info("config canary rolled back", "canary_id", state.ID, "reason", reason)
}

func (c *CanaryController) unhealthyProbes(ctx context.Context) []string {
	var unhealthy []string
	for _, probe := range c.probes {
		if probe.Check == nil {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, c.probeTimeout())
		verdict := probe.Check(probeCtx)
		cancel()
		if verdict == CanaryUnhealthy {
			unhealthy = append(unhealthy, probe.Name)
			c.logger.Error("config canary: health probe unhealthy", "store", probe.Name)
		}
	}
	return unhealthy
}

func (c *CanaryController) probeTimeout() time.Duration {
	t := c.pollInterval / 2
	if t < 100*time.Millisecond {
		t = 100 * time.Millisecond
	}
	if t > 3*time.Second {
		t = 3 * time.Second
	}
	return t
}

func (c *CanaryController) record(ctx context.Context, state CanaryState, eventType audit.EventType) {
	if c.auditor == nil {
		return
	}
	e := &audit.Event{Type: eventType, Outcome: audit.OutcomeSuccess, ActorID: state.Actor}
	audit.SetMeta(e, "canary_id", state.ID)
	audit.SetMeta(e, "version_id", state.VersionID)
	audit.SetMeta(e, "prev_id", state.PreviousVersionID)
	audit.SetMeta(e, "peer_digest", state.Digest)
	audit.SetMeta(e, "reason", state.Reason)
	audit.SetMeta(e, "detail", state.Detail)
	c.auditor.Record(ctx, e)
}
