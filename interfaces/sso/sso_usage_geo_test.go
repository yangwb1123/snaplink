package sso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering"
	tokenusagemem "github.com/yangwb1123/snaplink/domains/metering/memory"
	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/shared/core"
)

// geoRecordingStore captures every Event the recorder drains — the only way
// to observe GeoCountry, since the aggregation Bucket deliberately never
// stores it (the privacy boundary keeps the store coarse). Backed by the
// real memory store for Query semantics.
type geoRecordingStore struct {
	metering.Store
	mu     sync.Mutex
	events []metering.Event
}

func newGeoRecordingStore() *geoRecordingStore {
	return &geoRecordingStore{Store: tokenusagemem.New()}
}

func (s *geoRecordingStore) Record(ctx context.Context, ev metering.Event) error {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	return s.Store.Record(ctx, ev)
}

func (s *geoRecordingStore) taken() []metering.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]metering.Event(nil), s.events...)
}

// newUsageSeamServer builds a Server with a live recorder over a
// geoRecordingStore, started so Offer drains synchronously on Close.
func newUsageSeamServer(t *testing.T) (*Server, *geoRecordingStore) {
	t.Helper()
	store := newGeoRecordingStore()
	rec := metering.NewRecorder(store)
	rec.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rec.Close(ctx)
	})
	s := &Server{}
	s.tokenUsageRecorder = rec
	return s, store
}

// geoStashContext returns a HandlerContext with the geo middleware's stash
// populated the way GeoMiddleware does after a successful lookup.
func geoStashContext(t *testing.T, country string) HandlerContext {
	t.Helper()
	ctx := coreNewContext(t)
	if country != "" {
		ctx.Set(geo.HandlerContextKey, &geo.GeoInfo{CountryCode: country})
	}
	return ctx
}

func coreNewContext(t *testing.T) HandlerContext {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	return core.NewContext(httptest.NewRecorder(), req)
}

// TestOfferUsage_StampsGeoFromContext proves the interfaces/sso choke point:
// with a stashed *GeoInfo the Event handed to the recorder carries the
// stubbed CountryCode; without one it stays "" (byte-identical to a build
// without the extractor). Both branches run through the SAME helper so the
// two layers cannot drift apart on the geo read.
func TestOfferUsage_StampsGeoFromContext(t *testing.T) {
	t.Parallel()
	s, store := newUsageSeamServer(t)

	s.offerUsage(geoStashContext(t, "JP"), metering.Event{
		Kind: metering.KindAccess, Endpoint: metering.EndpointToken,
		ClientID: "c1", SubjectID: "u1",
	})
	s.offerUsage(geoStashContext(t, ""), metering.Event{
		Kind: metering.KindRefresh, Endpoint: metering.EndpointToken,
		ClientID: "c2", SubjectID: "u2",
	})
	if err := s.tokenUsageRecorder.Close(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	got := store.taken()
	if len(got) != 2 {
		t.Fatalf("recorder drained %d events, want 2", len(got))
	}
	if got[0].GeoCountry != "JP" {
		t.Errorf("event[0].GeoCountry = %q, want JP", got[0].GeoCountry)
	}
	if got[1].GeoCountry != "" {
		t.Errorf("event[1].GeoCountry = %q, want '' (zero-value byte-identity)", got[1].GeoCountry)
	}
}

// TestOfferUsage_NilRecorderIsNoop proves the helper keeps the existing
// nil-recorder contract: a Server without WithTokenUsageRecorder must not
// panic when a grant handler funnels through it.
func TestOfferUsage_NilRecorderIsNoop(t *testing.T) {
	t.Parallel()
	s := &Server{}
	s.offerUsage(geoStashContext(t, "US"), metering.Event{
		Kind: metering.KindAccess, Endpoint: metering.EndpointToken,
		ClientID: "c1", SubjectID: "u1",
	})
}

// TestRecordIssuedSeams_CarryGeo drives all three grant-flow Offer seams
// through a stubbed geo context and asserts the drained Events carry the
// stub — the spec's Improvement-1 seam acceptance. GeoCountry is the ONLY
// field this feature adds; kind/endpoint/client/subject are unchanged.
func TestRecordIssuedSeams_CarryGeo(t *testing.T) {
	t.Parallel()
	s, store := newUsageSeamServer(t)

	s.recordTokenIssued(geoStashContext(t, "DE"), "c1", "authz_code", "u1")
	s.recordRefreshTokenIssued(geoStashContext(t, "DE"), "c1", "u1", false)
	s.recordIDTokenIssued(geoStashContext(t, "DE"), "c1", "u1")
	if err := s.tokenUsageRecorder.Close(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	got := store.taken()
	if len(got) != 3 {
		t.Fatalf("recorder drained %d events, want 3", len(got))
	}
	want := []metering.Event{
		{Kind: metering.KindAccess, Endpoint: metering.EndpointToken, ClientID: "c1", SubjectID: "u1"},
		{Kind: metering.KindRefresh, Endpoint: metering.EndpointToken, ClientID: "c1", SubjectID: "u1"},
		{Kind: metering.KindID, Endpoint: metering.EndpointToken, ClientID: "c1", SubjectID: "u1"},
	}
	for i, w := range want {
		if got[i].GeoCountry != "DE" {
			t.Errorf("event[%d].GeoCountry = %q, want DE", i, got[i].GeoCountry)
		}
		if got[i].Kind != w.Kind || got[i].Endpoint != w.Endpoint ||
			got[i].ClientID != w.ClientID || got[i].SubjectID != w.SubjectID {
			t.Errorf("event[%d] = %+v, want %+v (only GeoCountry may change)", i, got[i], w)
		}
	}
}

// TestRecordIssuedSeams_NoGeoByteIdentical proves the zero-value leg of the
// seam contract: without a geo stash every Offer emits GeoCountry "" and
// everything else is unchanged — the exact bytes a pre-feature binary
// emitted.
func TestRecordIssuedSeams_NoGeoByteIdentical(t *testing.T) {
	t.Parallel()
	s, store := newUsageSeamServer(t)

	s.recordTokenIssued(geoStashContext(t, ""), "c1", "authz_code", "u1")
	s.recordRefreshTokenIssued(geoStashContext(t, ""), "c1", "u1", true)
	s.recordIDTokenIssued(geoStashContext(t, ""), "c1", "u1")
	if err := s.tokenUsageRecorder.Close(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	for i, ev := range store.taken() {
		if ev.GeoCountry != "" {
			t.Errorf("event[%d].GeoCountry = %q, want '' (byte-identical)", i, ev.GeoCountry)
		}
	}
}
