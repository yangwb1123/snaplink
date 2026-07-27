package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestTokenNoStoreHeaders_SetsCorrectValues(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/token", nil)
	ctx := core.NewContext(rec, req)

	TokenNoStoreHeaders(ctx)

	headers := rec.Header()
	if cc := headers.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("expected 'no-store', got %q", cc)
	}
	if pragma := headers.Get("Pragma"); pragma != "no-cache" {
		t.Errorf("expected 'no-cache', got %q", pragma)
	}
}

func TestClearSiteData(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/logout", nil)
	ctx := core.NewContext(rec, req)

	ClearSiteData(ctx)

	csd := rec.Header().Get("Clear-Site-Data")
	if csd == "" {
		t.Fatal("expected Clear-Site-Data header")
	}
	if csd != `"cache", "cookies", "storage"` {
		t.Errorf("unexpected Clear-Site-Data value: %q", csd)
	}
}
