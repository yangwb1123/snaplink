// Package modules manages safe activation of modules already compiled into
// the host. It never discovers or loads executable code at runtime.
package modules

import (
	"context"
	"errors"
	"time"
)

var (
	ErrDefinitionInvalid    = errors.New("module lifecycle: invalid definition")
	ErrDefinitionDuplicate  = errors.New("module lifecycle: duplicate definition")
	ErrDependencyMissing    = errors.New("module lifecycle: dependency missing")
	ErrDependencyCycle      = errors.New("module lifecycle: dependency cycle")
	ErrDependencyInactive   = errors.New("module lifecycle: dependency inactive")
	ErrDependentsActive     = errors.New("module lifecycle: dependents active")
	ErrModuleUnknown        = errors.New("module lifecycle: module unknown")
	ErrModuleInactive       = errors.New("module lifecycle: module inactive")
	ErrModuleDraining       = errors.New("module lifecycle: module draining")
	ErrTransitionInProgress = errors.New("module lifecycle: transition in progress")
	ErrManagerClosed        = errors.New("module lifecycle: manager closed")
	ErrConfigTooLarge       = errors.New("module lifecycle: config too large")
	ErrDrainTimeout         = errors.New("module lifecycle: drain timeout")
)

type LeaseClass string

const (
	LeaseRequest    LeaseClass = "request"
	LeaseDependency LeaseClass = "dependency"
	LeaseBackground LeaseClass = "background"
)

func validLeaseClass(class LeaseClass) bool {
	return class == LeaseRequest || class == LeaseDependency || class == LeaseBackground
}

// Instance owns one prepared generation. Capability-specific interfaces may
// be added by concrete instances and recovered from Lease.Instance().
//
// Lifecycle methods must honor context cancellation.
type Instance interface {
	Start(context.Context) error
	Ready(context.Context) error
	Quiesce(context.Context) error
	Stop(context.Context) error
}

// Factory must honor context cancellation.
type Factory interface {
	Prepare(context.Context, PrepareRequest) (Instance, error)
}

type FactoryFunc func(context.Context, PrepareRequest) (Instance, error)

func (f FactoryFunc) Prepare(ctx context.Context, request PrepareRequest) (Instance, error) {
	return f(ctx, request)
}

// ExternalFactory creates a fresh external supervisor for each lifecycle
// generation. Its immutable launch policy is copied at construction;
// generation config cannot replace it implicitly.
type ExternalFactory struct {
	spec ExternalModuleSpec
}

// NewExternalFactory freezes one launch/transport policy for generation use.
func NewExternalFactory(spec ExternalModuleSpec) (*ExternalFactory, error) {
	supervisor, err := NewExternalSupervisor(spec)
	if err != nil {
		return nil, err
	}
	return &ExternalFactory{spec: supervisor.spec}, nil
}

func (f *ExternalFactory) Prepare(ctx context.Context, _ PrepareRequest) (Instance, error) {
	if f == nil {
		return nil, errors.New("external module: nil factory")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return NewExternalSupervisor(f.spec)
}

var _ Factory = (*ExternalFactory)(nil)

// BackgroundLease pins only the generation whose controller issued it.
type BackgroundLease interface {
	Generation() uint64
	Release()
}

// GenerationController lets an instance account for its own background work.
// Once its generation starts draining, new acquisitions fail with
// ErrModuleDraining.
type GenerationController interface {
	AcquireBackground() (BackgroundLease, error)
}

type TransitionEventType string

const (
	TransitionPrepareFailed         TransitionEventType = "prepare_failed"
	TransitionStartFailed           TransitionEventType = "start_failed"
	TransitionReadyFailed           TransitionEventType = "ready_failed"
	TransitionActivated             TransitionEventType = "activated"
	TransitionCandidateDrainStarted TransitionEventType = "candidate_drain_started"
	TransitionReplacementStarted    TransitionEventType = "replacement_drain_started"
	TransitionDisableStarted        TransitionEventType = "disable_drain_started"
	TransitionCloseStarted          TransitionEventType = "close_drain_started"
	TransitionDrainTimedOut         TransitionEventType = "drain_timed_out"
	TransitionQuiesceFailed         TransitionEventType = "quiesce_failed"
	TransitionStopFailed            TransitionEventType = "stop_failed"
	TransitionRetired               TransitionEventType = "retired"
)

// TransitionEvent is deliberately bounded. It never carries module config,
// arbitrary metadata, or underlying error text.
type TransitionEvent struct {
	Type              TransitionEventType `json:"type"`
	ModuleID          string              `json:"module_id"`
	Generation        uint64              `json:"generation"`
	RelatedGeneration uint64              `json:"related_generation,omitempty"`
	OccurredAt        time.Time           `json:"occurred_at"`
}

type TransitionObserver interface {
	Observe(context.Context, TransitionEvent) error
}

type TransitionObserverFunc func(context.Context, TransitionEvent) error

func (f TransitionObserverFunc) Observe(ctx context.Context, event TransitionEvent) error {
	return f(ctx, event)
}

type ObserverStatus struct {
	Pending  int    `json:"pending"`
	Dropped  uint64 `json:"dropped"`
	Failures uint64 `json:"failures"`
}

type PrepareRequest struct {
	ModuleID     string
	Generation   uint64
	Config       []byte
	Dependencies map[string]Instance
	Controller   GenerationController
}

type Definition struct {
	ID           string
	Dependencies []string
	Factory      Factory
}

type Options struct {
	MaxConfigBytes     int
	DrainTimeout       time.Duration
	LifecycleTimeout   time.Duration
	TransitionObserver TransitionObserver
	ObserverQueueSize  int
	ObserverTimeout    time.Duration
}

func defaultOptions() Options {
	return Options{
		MaxConfigBytes: 64 << 10, DrainTimeout: 30 * time.Second,
		LifecycleTimeout: 10 * time.Second, ObserverQueueSize: defaultObserverQueueSize,
		ObserverTimeout: time.Second,
	}
}

type State string

const (
	StateInactive State = "inactive"
	StateActive   State = "active"
	StateDraining State = "draining"
)

type Status struct {
	ModuleID      string               `json:"module_id"`
	Generation    uint64               `json:"generation,omitempty"`
	State         State                `json:"state"`
	ConfigDigest  string               `json:"config_digest,omitempty"`
	Leases        map[LeaseClass]int64 `json:"leases,omitempty"`
	ActivatedAt   time.Time            `json:"activated_at,omitempty"`
	LastError     string               `json:"last_error,omitempty"`
	Transitioning bool                 `json:"transitioning,omitempty"`
	Retiring      []RetiringStatus     `json:"retiring,omitempty"`
}

type RetiringStatus struct {
	Generation   uint64               `json:"generation"`
	State        State                `json:"state"`
	ConfigDigest string               `json:"config_digest,omitempty"`
	Leases       map[LeaseClass]int64 `json:"leases,omitempty"`
	ActivatedAt  time.Time            `json:"activated_at,omitempty"`
	LastError    string               `json:"last_error,omitempty"`
}
