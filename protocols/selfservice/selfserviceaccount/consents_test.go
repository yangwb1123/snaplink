package selfserviceaccount

import (
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestHandleMyConsents_ListsOwnGrantsOnly(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.consents.RecordConsent(t.Context(), core.ConsentGrant{UserID: "user-1", ClientID: "client-a", GrantedAt: time.Now()})
	_ = d.consents.RecordConsent(t.Context(), core.ConsentGrant{UserID: "user-1", ClientID: "client-b", GrantedAt: time.Now()})
	_ = d.consents.RecordConsent(t.Context(), core.ConsentGrant{UserID: "someone-else", ClientID: "client-c", GrantedAt: time.Now()})

	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMyConsents(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	resp := decodeBody(t, rec)
	consents, _ := resp["consents"].([]any)
	if len(consents) != 2 {
		t.Fatalf("got %d consents, want 2 (own only)", len(consents))
	}
}

func TestHandleDeleteMyConsent(t *testing.T) {
	t.Parallel()
	t.Run("happy path", func(t *testing.T) {
		d := newTestDeps()
		_ = d.consents.RecordConsent(t.Context(), core.ConsentGrant{UserID: "user-1", ClientID: "client-a", GrantedAt: time.Now()})
		rec := servePath(http.MethodDelete, "/consents/me/:client_id", "/consents/me/client-a", "",
			func(ctx core.HandlerContext) { HandleDeleteMyConsent(d, ctx) })
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204, body=%s", rec.Code, rec.Body.String())
		}
		if _, err := d.consents.GetConsent(t.Context(), "user-1", "client-a"); err == nil {
			t.Error("consent should be revoked")
		}
	})

	t.Run("unknown client 404", func(t *testing.T) {
		d := newTestDeps()
		rec := servePath(http.MethodDelete, "/consents/me/:client_id", "/consents/me/ghost", "",
			func(ctx core.HandlerContext) { HandleDeleteMyConsent(d, ctx) })
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
