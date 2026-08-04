package memory_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering"
	"github.com/yangwb1123/snaplink/domains/metering/memory"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// HandleAdminPortfolio is exercised against a REAL memory usage store (no
// mocks). External test package so it can import both tokenusage and its
// memory store.

func TestHandleAdminPortfolio_AggregatesFromStore(t *testing.T) {
	store := memory.New()
	m0 := time.Date(2026, time.July, 3, 10, 0, 0, 0, time.UTC)
	rec := func(client string, kind metering.Kind, ep metering.Endpoint, at time.Time) {
		if err := store.Record(context.Background(), metering.Event{
			ClientID: client, Kind: kind, Endpoint: ep, At: at,
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	rec("c1", metering.KindAccess, metering.EndpointToken, m0)
	rec("c1", metering.KindAccess, metering.EndpointToken, m0)
	rec("c2", metering.KindRefresh, metering.EndpointToken, m0.Add(time.Minute))
	rec("c1", metering.KindAccess, metering.EndpointIntrospect, m0)

	w := httptest.NewRecorder()
	ctx := core.NewContext(w, httptest.NewRequest(http.MethodGet, "/admin/tokens/portfolio", nil))
	metering.HandleAdminPortfolio(store, spi.NopLogger{}, ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Status    string                 `json:"status"`
		Portfolio metering.PortfolioView `json:"portfolio"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Status != core.StatusOK {
		t.Errorf("status = %q", out.Status)
	}
	p := out.Portfolio
	if p.IssuedTotal != 3 || p.Introspections != 1 {
		t.Errorf("issued=%d introspections=%d, want 3/1", p.IssuedTotal, p.Introspections)
	}
	if p.ByClient[0].ClientID != "c1" || p.ByClient[0].Issued != 2 {
		t.Errorf("top client = %+v, want c1/2", p.ByClient)
	}
}
