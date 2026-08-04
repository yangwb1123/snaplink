package modules

import (
	"errors"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/yangwb1123/snaplink/shared/core"
)

var ErrRouteLeaseUnsupported = errors.New("module lifecycle: router cannot acquire route leases")

var routeSlotSequence atomic.Uint64

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
