package modules

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"sync/atomic"

	"github.com/yangwb1123/snaplink/shared/core"
)

var ErrRouteLeaseUnsupported = errors.New("module lifecycle: router cannot acquire route leases")

var routeSlotSequence atomic.Uint64

func (m *Manager) Status() []Status {
	if m == nil {
		return nil
	}
	retiring := m.retiringSnapshot()
	health := m.healthSnapshot()
	result := make([]Status, 0, len(m.slots))
	for id, slot := range m.slots {
		status := statusFor(id, slot.current.Load(), retiring[id], health)
		status.Transitioning = slot.transitionStatus()
		result = append(result, status)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].ModuleID < result[right].ModuleID
	})
	return result
}

func statusFor(
	id string, current *generation, retiring []*generation, health map[string]error,
) Status {
	status := Status{ModuleID: id, State: StateInactive}
	if current != nil {
		draining, counts := current.snapshot()
		status.Generation, status.State = current.number, StateActive
		status.ConfigDigest, status.Leases = current.digest, counts
		status.ActivatedAt = current.activatedAt
		if draining {
			status.State = StateDraining
		}
	}
	status.Retiring = retiringStatuses(retiring, health)
	if current == nil && len(status.Retiring) > 0 {
		status.State = StateDraining
	}
	status.LastError = lastModuleError(id, current, status.Retiring, health)
	return status
}

func retiringStatuses(generations []*generation, health map[string]error) []RetiringStatus {
	result := make([]RetiringStatus, 0, len(generations))
	for _, generation := range generations {
		_, counts := generation.snapshot()
		status := RetiringStatus{
			Generation: generation.number, State: StateDraining,
			ConfigDigest: generation.digest, Leases: counts, ActivatedAt: generation.activatedAt,
		}
		if err := health[generationHealthKey(generation)]; err != nil {
			status.LastError = err.Error()
		}
		result = append(result, status)
	}
	return result
}

func lastModuleError(
	id string, current *generation, retiring []RetiringStatus, health map[string]error,
) string {
	if current != nil {
		if err := health[generationHealthKey(current)]; err != nil {
			return err.Error()
		}
	}
	for _, status := range retiring {
		if status.LastError != "" {
			return status.LastError
		}
	}
	return remainingModuleError(id, health)
}

func remainingModuleError(id string, health map[string]error) string {
	keys := make([]string, 0)
	for key := range health {
		if len(key) > len(id) && key[:len(id)+1] == id+"/" {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return health[keys[len(keys)-1]].Error()
}

func (m *Manager) trackRetiring(g *generation) {
	m.retiringMu.Lock()
	defer m.retiringMu.Unlock()
	byGeneration := m.retiring[g.id]
	if byGeneration == nil {
		byGeneration = make(map[uint64]*generation)
		m.retiring[g.id] = byGeneration
	}
	byGeneration[g.number] = g
}

func (m *Manager) untrackRetiring(g *generation) {
	m.retiringMu.Lock()
	defer m.retiringMu.Unlock()
	delete(m.retiring[g.id], g.number)
	if len(m.retiring[g.id]) == 0 {
		delete(m.retiring, g.id)
	}
}

func (m *Manager) retiringSnapshot() map[string][]*generation {
	m.retiringMu.RLock()
	defer m.retiringMu.RUnlock()
	result := make(map[string][]*generation, len(m.retiring))
	for id, byGeneration := range m.retiring {
		for _, generation := range byGeneration {
			result[id] = append(result[id], generation)
		}
		sort.Slice(result[id], func(left, right int) bool {
			return result[id][left].number > result[id][right].number
		})
	}
	return result
}

func (m *Manager) healthSnapshot() map[string]error {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()
	result := make(map[string]error, len(m.health))
	for key, err := range m.health {
		result[key] = err
	}
	return result
}

// RouteSlot binds a statically registered HTTP route to one module slot.
// Matching pins exactly one generation before any middleware runs.
type RouteSlot struct {
	manager  *Manager
	moduleID string
	leaseKey string
}

func NewRouteSlot(manager *Manager, moduleID string) (*RouteSlot, error) {
	if manager == nil {
		return nil, ErrDefinitionInvalid
	}
	if _, ok := manager.catalog.definitions[moduleID]; !ok {
		return nil, ErrModuleUnknown
	}
	sequence := routeSlotSequence.Add(1)
	return &RouteSlot{
		manager: manager, moduleID: moduleID,
		leaseKey: "snaplink.module.route." + strconv.FormatUint(sequence, 10),
	}, nil
}

// Register mounts a route once at boot. The route is indistinguishable from
// an unknown route while its module has no active generation.
func (s *RouteSlot) Register(
	router core.Router, method, path string,
	handler func(core.HandlerContext, Instance),
) error {
	if s == nil || router == nil || method == "" || path == "" || handler == nil {
		return ErrDefinitionInvalid
	}
	registrar, ok := router.(core.LeasedRegistrar)
	if !ok {
		return ErrRouteLeaseUnsupported
	}
	registrar.RegisterLeased(method, path, s.wrap(handler), s.acquire)
	return nil
}

func (s *RouteSlot) acquire(ctx core.HandlerContext) (func(), bool) {
	lease, err := s.manager.Acquire(s.moduleID, LeaseRequest)
	if err != nil {
		return nil, false
	}
	ctx.Set(s.leaseKey, lease)
	return lease.Release, true
}

func (s *RouteSlot) wrap(
	handler func(core.HandlerContext, Instance),
) core.HandlerFunc {
	return func(ctx core.HandlerContext) {
		lease, ok := ctx.Get(s.leaseKey).(*Lease)
		if !ok || lease.Instance() == nil {
			ctx.JSON(http.StatusServiceUnavailable, core.ErrorBody(core.ErrInternal))
			return
		}
		handler(ctx, lease.Instance())
	}
}
