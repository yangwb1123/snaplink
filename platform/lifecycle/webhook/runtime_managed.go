package webhook

import (
	"context"
	"errors"
	"sync"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
)

const managedModuleID = "audit-webhook-exporter"

// LifecycleFactory prepares one precompiled webhook engine generation. Config
// is bounded and copied by the lifecycle manager before it reaches this hook.
type LifecycleFactory func(context.Context, []byte, uint64) (*Engine, error)

// ManagedRuntime is a lifecycle-managed webhook Runtime. Its subscription and
// dead-letter stores are owned by the host and may survive policy replacement.
type ManagedRuntime struct {
	manager *modules.Manager
	factory LifecycleFactory

	candidateMu sync.Mutex
	candidate   *Engine
	currentMu   sync.RWMutex
	current     *Engine
}

// NewManagedRuntime builds the manager and activates its first generation.
func NewManagedRuntime(factory LifecycleFactory, initial []byte, options modules.Options) (*ManagedRuntime, error) {
	if factory == nil {
		return nil, errors.New("webhook runtime: nil factory")
	}
	runtime := &ManagedRuntime{factory: factory}
	manager, err := modules.New([]modules.Definition{{
		ID: managedModuleID, Factory: &managedFactoryAdapter{runtime: runtime},
	}}, options)
	if err != nil {
		return nil, err
	}
	runtime.manager = manager
	if err := runtime.Activate(context.Background(), initial); err != nil {
		_ = manager.Close(context.Background())
		return nil, err
	}
	if err := manager.WaitObserver(context.Background()); err != nil {
		_ = manager.Close(context.Background())
		return nil, err
	}
	return runtime, nil
}

// Activate prepares a generation and publishes it only after Start and Ready.
func (r *ManagedRuntime) Activate(ctx context.Context, config []byte) error {
	if r == nil || r.manager == nil {
		return modules.ErrManagerClosed
	}
	if _, err := r.manager.Activate(ctx, managedModuleID, config); err != nil {
		r.clearCandidate()
		return err
	}
	candidate := r.takeCandidate()
	if candidate == nil {
		return errors.New("webhook runtime: manager activated without a candidate")
	}
	r.currentMu.Lock()
	r.current = candidate
	r.currentMu.Unlock()
	return nil
}

// Disable removes the active generation after request leases drain.
func (r *ManagedRuntime) Disable(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return modules.ErrManagerClosed
	}
	retirement, err := r.manager.Disable(managedModuleID)
	if err != nil {
		return err
	}
	r.currentMu.Lock()
	r.current = nil
	r.currentMu.Unlock()
	return retirement.Wait(ctx)
}

// Record is a fail-open audit tap during generation replacement.
func (r *ManagedRuntime) Record(ctx context.Context, event *audit.Event) error {
	if r == nil || r.manager == nil || event == nil {
		return nil
	}
	lease, err := r.manager.Acquire(managedModuleID, modules.LeaseRequest)
	if err != nil {
		return nil
	}
	defer lease.Release()
	instance, ok := lease.Instance().(*managedEngineInstance)
	if !ok || instance.engine == nil {
		return nil
	}
	return instance.engine.Record(ctx, event)
}

func (r *ManagedRuntime) Get(ctx context.Context, id string) (*audit.Event, error) {
	engine := r.currentEngine()
	if engine == nil {
		return nil, audit.ErrSinkWriteOnly
	}
	return engine.Get(ctx, id)
}

func (r *ManagedRuntime) Query(ctx context.Context, query audit.Query) ([]*audit.Event, error) {
	engine := r.currentEngine()
	if engine == nil {
		return nil, audit.ErrSinkWriteOnly
	}
	return engine.Query(ctx, query)
}

func (r *ManagedRuntime) Subscriptions() SubscriptionStore {
	engine := r.currentEngine()
	if engine == nil {
		return nil
	}
	return engine.Subscriptions()
}

func (r *ManagedRuntime) DeadLetters() DeadLetterStore {
	engine := r.currentEngine()
	if engine == nil {
		return nil
	}
	return engine.DeadLetters()
}

func (r *ManagedRuntime) Replay(ctx context.Context, id string) (DeadLetterEntry, error) {
	engine := r.currentEngine()
	if engine == nil {
		return DeadLetterEntry{}, ErrDeadLetterNotFound
	}
	return engine.Replay(ctx, id)
}

// Ready reports manager health and requires one active generation.
func (r *ManagedRuntime) Ready(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return modules.ErrManagerClosed
	}
	if err := r.manager.Ready(ctx); err != nil {
		return err
	}
	if r.currentEngine() == nil {
		return modules.ErrModuleInactive
	}
	return nil
}

// CurrentEngine returns the concrete engine for source-compatible callers;
// lifecycle-aware callers should use ManagedRuntime itself.
func (r *ManagedRuntime) CurrentEngine() *Engine { return r.currentEngine() }

func (r *ManagedRuntime) Status() []modules.Status {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.Status()
}

func (r *ManagedRuntime) ObserverStatus() modules.ObserverStatus {
	if r == nil || r.manager == nil {
		return modules.ObserverStatus{}
	}
	return r.manager.ObserverStatus()
}

// Close drains all generations and transition-observer work.
func (r *ManagedRuntime) Close(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.Close(ctx)
}

func (r *ManagedRuntime) currentEngine() *Engine {
	r.currentMu.RLock()
	defer r.currentMu.RUnlock()
	return r.current
}

func (r *ManagedRuntime) clearCandidate() {
	r.candidateMu.Lock()
	r.candidate = nil
	r.candidateMu.Unlock()
}

func (r *ManagedRuntime) takeCandidate() *Engine {
	r.candidateMu.Lock()
	defer r.candidateMu.Unlock()
	candidate := r.candidate
	r.candidate = nil
	return candidate
}

type managedFactoryAdapter struct{ runtime *ManagedRuntime }

func (f *managedFactoryAdapter) Prepare(ctx context.Context, request modules.PrepareRequest) (modules.Instance, error) {
	if f == nil || f.runtime == nil || f.runtime.factory == nil {
		return nil, modules.ErrDefinitionInvalid
	}
	engine, err := f.runtime.factory(ctx, request.Config, request.Generation)
	if err != nil {
		return nil, err
	}
	if engine == nil {
		return nil, modules.ErrDefinitionInvalid
	}
	f.runtime.candidateMu.Lock()
	f.runtime.candidate = engine
	f.runtime.candidateMu.Unlock()
	return &managedEngineInstance{engine: engine}, nil
}

type managedEngineInstance struct{ engine *Engine }

func (i *managedEngineInstance) Start(context.Context) error   { return nil }
func (i *managedEngineInstance) Ready(context.Context) error   { return nil }
func (i *managedEngineInstance) Quiesce(context.Context) error { return nil }

func (i *managedEngineInstance) Stop(ctx context.Context) error {
	if i == nil || i.engine == nil {
		return nil
	}
	return i.engine.CloseGraceful(ctx)
}

var _ Runtime = (*ManagedRuntime)(nil)
var _ modules.Factory = (*managedFactoryAdapter)(nil)
var _ modules.Instance = (*managedEngineInstance)(nil)
