package rebac

import (
	"context"
	"net/http"
	"strconv"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	hotModuleID = "rebac-check"
	hotConfig   = "rebac-check-v1"
)

// Runtime owns the precompiled ReBAC business-check generation. Its route
// shape is fixed at host mount time; Activate and Disable publish or withdraw
// the generation behind that route slot.
type Runtime struct {
	manager *modules.Manager
	slot    *modules.RouteSlot
	engine  *Engine
}

// StartHotRuntime creates and activates the first ReBAC check generation.
// The supplied recorder receives only bounded lifecycle transition facts.
func (e *Engine) StartHotRuntime(recorder *audit.Recorder) error {
	if e == nil || e.store == nil {
		return ErrNoStore
	}
	e.runtimeMu.Lock()
	defer e.runtimeMu.Unlock()
	if e.runtime != nil {
		return nil
	}
	runtime, err := newRuntime(e, recorder)
	if err != nil {
		return err
	}
	e.runtime = runtime
	return nil
}

// HotRuntime returns the lifecycle controller installed by StartHotRuntime.
func (e *Engine) HotRuntime() *Runtime {
	if e == nil {
		return nil
	}
	e.runtimeMu.RLock()
	defer e.runtimeMu.RUnlock()
	return e.runtime
}

func newRuntime(engine *Engine, recorder *audit.Recorder) (*Runtime, error) {
	runtime := &Runtime{engine: engine}
	manager, err := modules.New([]modules.Definition{{
		ID: hotModuleID,
		Factory: modules.FactoryFunc(func(ctx context.Context, _ modules.PrepareRequest) (modules.Instance, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return &checkInstance{engine: engine}, nil
		}),
	}}, modules.Options{TransitionObserver: hotTransitionObserver(recorder)})
	if err != nil {
		return nil, err
	}
	runtime.manager = manager
	runtime.slot, err = modules.NewRouteSlot(manager, hotModuleID)
	if err != nil {
		_ = manager.Close(context.Background())
		return nil, err
	}
	if err := runtime.Activate(context.Background()); err != nil {
		_ = manager.Close(context.Background())
		return nil, err
	}
	if err := manager.WaitObserver(context.Background()); err != nil {
		_ = manager.Close(context.Background())
		return nil, err
	}
	return runtime, nil
}

// Activate publishes a fresh generation after its lifecycle callbacks pass.
// The compiled capability is configuration-free; Disable withdraws it rather
// than accepting arbitrary policy bytes at this host boundary.
func (r *Runtime) Activate(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return modules.ErrManagerClosed
	}
	_, err := r.manager.Activate(ctx, hotModuleID, []byte(hotConfig))
	return err
}

// Disable withdraws the check route and waits for matched requests to release
// their generation leases before returning.
func (r *Runtime) Disable(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return modules.ErrManagerClosed
	}
	retirement, err := r.manager.Disable(hotModuleID)
	if err != nil {
		return err
	}
	return retirement.Wait(ctx)
}

// RegisterCheckRoute binds the fixed product route to the generation slot.
// False means the host router lacks match-time lease support and should use
// its legacy cold registration path.
func (r *Runtime) RegisterCheckRoute(router core.Router, deps TupleDeps) bool {
	if r == nil || r.slot == nil || deps == nil {
		return false
	}
	err := r.slot.Register(router, http.MethodGet, core.PathAuthzCheck,
		func(ctx core.HandlerContext, instance modules.Instance) {
			current, ok := instance.(*checkInstance)
			if !ok || current.engine == nil {
				ctx.JSON(http.StatusServiceUnavailable, deps.ErrorBody(core.ErrInternal))
				return
			}
			HandleCheckAccess(generationDeps{TupleDeps: deps, engine: current.engine}, ctx)
		})
	return err == nil
}

// Ready requires manager health and an active generation. Manager health by
// itself intentionally permits a disabled module.
func (r *Runtime) Ready(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return modules.ErrManagerClosed
	}
	if err := r.manager.Ready(ctx); err != nil {
		return err
	}
	lease, err := r.manager.Acquire(hotModuleID, modules.LeaseRequest)
	if err != nil {
		return err
	}
	lease.Release()
	return nil
}

// Status exposes bounded generation state for operator views.
func (r *Runtime) Status() []modules.Status {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.Status()
}

// ObserverStatus exposes bounded transition-observer health.
func (r *Runtime) ObserverStatus() modules.ObserverStatus {
	if r == nil || r.manager == nil {
		return modules.ObserverStatus{}
	}
	return r.manager.ObserverStatus()
}

// Close drains active requests, lifecycle callbacks and transition audit work.
func (r *Runtime) Close(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.Close(ctx)
}

type checkInstance struct{ engine *Engine }

func (i *checkInstance) Start(context.Context) error   { return nil }
func (i *checkInstance) Ready(context.Context) error   { return nil }
func (i *checkInstance) Quiesce(context.Context) error { return nil }
func (i *checkInstance) Stop(context.Context) error    { return nil }

type generationDeps struct {
	TupleDeps
	engine *Engine
}

func (d generationDeps) RebacEngine() *Engine { return d.engine }

func hotTransitionObserver(recorder *audit.Recorder) modules.TransitionObserver {
	if recorder == nil {
		return nil
	}
	return modules.TransitionObserverFunc(func(ctx context.Context, event modules.TransitionEvent) error {
		auditEvent := &audit.Event{
			Type: audit.EventReBACLifecycleTransition, Outcome: audit.OutcomeSuccess,
			Timestamp: event.OccurredAt, Reason: string(event.Type),
		}
		audit.SetMeta(auditEvent, "module_id", event.ModuleID)
		audit.SetMeta(auditEvent, "generation", strconv.FormatUint(event.Generation, 10))
		if event.RelatedGeneration != 0 {
			audit.SetMeta(auditEvent, "related_generation", strconv.FormatUint(event.RelatedGeneration, 10))
		}
		recorder.Record(ctx, auditEvent)
		return nil
	})
}

var _ modules.Instance = (*checkInstance)(nil)
