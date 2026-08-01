package sse

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// Query parameters for GET /api/v1/admin/events/stream.
const (
	QueryEventTypes = "event_types" // comma-separated event type allowlist
	QueryTenantID   = "tenant_id"
)

// Wire constants for the event-stream response.
const (
	HeaderLastEventID = "Last-Event-ID"
	// HeaderAccelBuffering disables nginx-style proxy response
	// buffering, which would otherwise hold SSE frames until the
	// buffer fills and defeat realtime delivery.
	HeaderAccelBuffering   = "X-Accel-Buffering"
	AccelBufferingOff      = "no"
	HeaderCacheControl     = "Cache-Control"
	HeaderPragma           = "Pragma"
	CacheControlNoStore    = "no-store"
	PragmaNoCache          = "no-cache"
	ContentTypeEventStream = "text/event-stream"
)

// ErrStreamBusy is the 503 error code when the broker is at
// MaxSubscribers. Admin-gated capacity signal, not a credential oracle.
const ErrStreamBusy = "event_stream_busy"

// DefaultHeartbeat spaces the comment keep-alive frames that stop
// intermediary proxies from idling out a quiet stream.
const DefaultHeartbeat = 15 * time.Second

// WriteTimeout bounds a single SSE frame write. A client that stalls
// mid-write poisons its connection deadline and unwinds the handler —
// the second slow-consumer backstop next to full-buffer eviction.
const WriteTimeout = 10 * time.Second

// HandleStream implements GET /api/v1/admin/events/stream. Admin
// auth (admin:read) is enforced by the admin middleware via the
// /api/v1/admin/ path prefix before this runs. Filters: ?event_types=
// a,b (comma-separated) and ?tenant_id=t. A Last-Event-ID header
// replays the missed ring-buffered events before going live.
func HandleStream(b *Broker, heartbeat time.Duration, ctx core.HandlerContext) {
	handleFilteredStream(b, filterFromRequest(ctx), heartbeat, ctx)
}

// HandleFilteredStream serves a caller-supplied, authorization-derived filter.
// It is used by user notification streams so request query parameters can never
// widen the authenticated subject boundary.
func HandleFilteredStream(b *Broker, filter Filter, heartbeat time.Duration, ctx core.HandlerContext) {
	handleFilteredStream(b, filter, heartbeat, ctx)
}

func handleFilteredStream(b *Broker, filter Filter, heartbeat time.Duration, ctx core.HandlerContext) {
	w, r := ctx.ResponseWriter(), ctx.Request()
	sub, err := b.Subscribe(filter)
	if err != nil {
		ctx.JSON(http.StatusServiceUnavailable, map[string]string{core.KeyError: ErrStreamBusy})
		return
	}
	defer sub.Close()
	writeStreamHeaders(w)
	rc := http.NewResponseController(w)
	last, alive := replayAfter(b, sub, w, rc, r)
	if !alive {
		return
	}
	// One flush before blocking so the client sees headers (and any
	// replay) immediately; a transport that cannot stream at all is
	// detected here instead of buffering silently forever.
	if err := rc.Flush(); err != nil {
		return
	}
	if heartbeat <= 0 {
		heartbeat = DefaultHeartbeat
	}
	streamLive(sub, w, rc, r, heartbeat, last)
}

// replayAfter writes the ring-buffered events newer than the client's
// Last-Event-ID (absent header = fresh stream, no replay). Returns the
// highest id written and alive=false when the client went away.
func replayAfter(b *Broker, sub *Subscriber, w http.ResponseWriter, rc *http.ResponseController, r *http.Request) (uint64, bool) {
	last, ok := lastEventID(r)
	if !ok {
		return 0, true
	}
	for _, ev := range b.Replay(last, sub.Filter()) {
		if !writeEvent(w, rc, ev) {
			return last, false
		}
		last = ev.ID
	}
	return last, true
}

// streamLive pumps broker events + heartbeat comments until the client
// disconnects, a write fails, or the broker closes the subscription
// (slow-consumer eviction or shutdown).
func streamLive(sub *Subscriber, w http.ResponseWriter, rc *http.ResponseController, r *http.Request, heartbeat time.Duration, last uint64) {
	tick := time.NewTicker(heartbeat)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-sub.C():
			if !ok {
				return
			}
			if ev.ID <= last {
				continue // replay overlap: already written from the ring
			}
			if !writeEvent(w, rc, ev) {
				return
			}
			last = ev.ID
		case <-tick.C:
			if !writeHeartbeat(w, rc) {
				return
			}
		}
	}
}

func writeStreamHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set(core.HeaderContentType, ContentTypeEventStream)
	// Bearer-gated endpoint: no-store like every credential surface.
	h.Set(HeaderCacheControl, CacheControlNoStore)
	h.Set(HeaderPragma, PragmaNoCache)
	h.Set(HeaderAccelBuffering, AccelBufferingOff)
	w.WriteHeader(http.StatusOK)
}

func writeEvent(w http.ResponseWriter, rc *http.ResponseController, ev Event) bool {
	// Best-effort deadline: a wrapper without SetWriteDeadline support
	// still gets the broker's full-buffer eviction backstop.
	_ = rc.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.ID, ev.Type, ev.Data); err != nil {
		return false
	}
	return rc.Flush() == nil
}

func writeHeartbeat(w http.ResponseWriter, rc *http.ResponseController) bool {
	_ = rc.SetWriteDeadline(time.Now().Add(WriteTimeout))
	// SSE comment frame — ignored by EventSource, keeps proxies warm.
	if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
		return false
	}
	return rc.Flush() == nil
}

func filterFromRequest(ctx core.HandlerContext) Filter {
	f := Filter{TenantID: ctx.Query(QueryTenantID)}
	for _, t := range strings.Split(ctx.Query(QueryEventTypes), ",") {
		if t = strings.TrimSpace(t); t != "" {
			f.Types = append(f.Types, t)
		}
	}
	return f
}

// lastEventID parses the Last-Event-ID reconnect header. Absent or
// non-numeric (e.g. an id minted by an older incompatible stream)
// means "start live" rather than erroring the reconnect.
func lastEventID(r *http.Request) (uint64, bool) {
	v := r.Header.Get(HeaderLastEventID)
	if v == "" {
		return 0, false
	}
	id, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}
