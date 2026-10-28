package ssotest

import (
	"context"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/internal/handler/tokengrant"
	"github.com/yangwb1123/snaplink/shared/core"
)

type inflightTraceClients struct {
	*defaultimpl.MemoryClientStore
	trace *inflightTrace
}

func (store *inflightTraceClients) ValidateSecret(ctx context.Context, id, secret string) error {
	defer store.trace.finish(store.trace.begin(inflightAuth))
	return store.MemoryClientStore.ValidateSecret(ctx, id, secret)
}

type inflightTraceGrace struct {
	store tokengrant.RefreshGraceStore
	trace *inflightTrace
}

func (store *inflightTraceGrace) Remember(token string, response map[string]any, now time.Time) {
	defer store.trace.finish(store.trace.begin(inflightGraceRemember))
	store.store.Remember(token, response, now)
}

func (store *inflightTraceGrace) Lookup(token string, now time.Time) (map[string]any, bool) {
	defer store.trace.finish(store.trace.begin(inflightGraceLookup))
	return store.store.Lookup(token, now)
}

type inflightTracePendingGrace struct {
	*inflightTraceGrace
	pending tokengrant.RefreshGracePendingStore
}

func (store *inflightTracePendingGrace) PreparePending(token string, response map[string]any, now time.Time) {
	defer store.trace.finish(store.trace.begin(inflightGracePrepare))
	store.pending.PreparePending(token, response, now)
}

// Preserve the optional method set: adding PreparePending to legacy stores
// would change strict reuse behavior rather than merely observe it.
func traceInflightGrace(store tokengrant.RefreshGraceStore, trace *inflightTrace) tokengrant.RefreshGraceStore {
	if store == nil {
		return nil
	}
	base := &inflightTraceGrace{store: store, trace: trace}
	if pending, ok := store.(tokengrant.RefreshGracePendingStore); ok {
		return &inflightTracePendingGrace{inflightTraceGrace: base, pending: pending}
	}
	return base
}

func traceInflightHandler(trace *inflightTrace, phase inflightPhase, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		defer trace.finish(trace.begin(phase))
		next.ServeHTTP(w, request)
	})
}

var _ core.ClientStore = (*inflightTraceClients)(nil)
var _ tokengrant.RefreshGraceStore = (*inflightTraceGrace)(nil)
var _ tokengrant.RefreshGracePendingStore = (*inflightTracePendingGrace)(nil)
