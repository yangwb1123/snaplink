package modules

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestRouteSlotPinsGenerationBeforeMiddlewareAndDrain(t *testing.T) {
	factory := newFakeFactory()
	manager := newTestManager(t, factory)
	t.Cleanup(func() { _ = manager.Close(context.Background()) })
	slot, err := NewRouteSlot(manager, "module-a")
	if err != nil {
		t.Fatalf("NewRouteSlot() error = %v", err)
	}

	router := core.NewStdRouter()
	var middlewareCalls atomic.Int64
	router.Use(func(core.HandlerContext) { middlewareCalls.Add(1) })
	entered := make(chan struct{})
	unblock := make(chan struct{})
	err = slot.Register(router, http.MethodGet, "/module", func(ctx core.HandlerContext, instance Instance) {
		generation := instance.(*fakeInstance).generation
		if generation == 1 {
			close(entered)
			<-unblock
		}
		ctx.JSON(http.StatusOK, map[string]uint64{"generation": generation})
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	assertInactiveRouteMatches404(t, router)
	if middlewareCalls.Load() != 0 {
		t.Fatal("inactive module route ran middleware")
	}
	first := activateForTest(t, manager, "module-a", nil)
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/module", nil))
		response <- recorder
	}()
	<-entered

	second := activateForTest(t, manager, "module-a", nil)
	if factory.instance(first.Generation).stopped.Load() {
		t.Fatal("old route generation stopped while request was running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := second.Retirement.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retirement before request release = %v", err)
	}
	close(unblock)
	if got := <-response; got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"generation":1`) {
		t.Fatalf("old request: status=%d body=%q", got.Code, got.Body.String())
	}
	if err := second.Retirement.Wait(context.Background()); err != nil {
		t.Fatalf("retirement error = %v", err)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/module", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"generation":2`) {
		t.Fatalf("new request: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if middlewareCalls.Load() != 2 {
		t.Fatalf("middleware calls = %d, want 2", middlewareCalls.Load())
	}
}

func assertInactiveRouteMatches404(t *testing.T, router core.Router) {
	t.Helper()
	baseline := httptest.NewRecorder()
	router.ServeHTTP(baseline, httptest.NewRequest(http.MethodGet, "/missing", nil))
	inactive := httptest.NewRecorder()
	router.ServeHTTP(inactive, httptest.NewRequest(http.MethodGet, "/module", nil))
	if inactive.Code != baseline.Code || inactive.Body.String() != baseline.Body.String() {
		t.Fatalf("inactive route = (%d, %q), baseline = (%d, %q)",
			inactive.Code, inactive.Body.String(), baseline.Code, baseline.Body.String())
	}
}

func TestRouteSlotRequiresMatchTimeLeaseCapability(t *testing.T) {
	manager := newTestManager(t, newFakeFactory())
	slot, err := NewRouteSlot(manager, "module-a")
	if err != nil {
		t.Fatalf("NewRouteSlot() error = %v", err)
	}
	router := core.NewGatedRouter(core.NewStdRouter(), func() bool { return true })
	err = slot.Register(router, http.MethodGet, "/module", func(core.HandlerContext, Instance) {})
	if !errors.Is(err, ErrRouteLeaseUnsupported) {
		t.Fatalf("Register() error = %v, want %v", err, ErrRouteLeaseUnsupported)
	}
}
