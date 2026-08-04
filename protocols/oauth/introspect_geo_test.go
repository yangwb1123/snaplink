package oauth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering"
	tokenusagemem "github.com/yangwb1123/snaplink/domains/metering/memory"
	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/shared/core"
)

// introspectGeoStore captures every drained Event so the tests can assert
// GeoCountry / Thumbprint before aggregation (the Bucket never stores them).
type introspectGeoStore struct {
	metering.Store
	mu     sync.Mutex
	events []metering.Event
}

func (s *introspectGeoStore) Record(ctx context.Context, ev metering.Event) error {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	return s.Store.Record(ctx, ev)
}

func (s *introspectGeoStore) taken() []metering.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]metering.Event(nil), s.events...)
}

// newIntrospectGeoDeps wires introspectDeps with a live recorder over a
// capturing store.
func newIntrospectGeoDeps(t *testing.T) (*introspectDeps, *introspectGeoStore) {
	t.Helper()
	store := &introspectGeoStore{Store: tokenusagemem.New()}
	rec := metering.NewRecorder(store)
	rec.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rec.Close(ctx)
	})
	d := newIntrospectDeps(newMemClientStore(), newMemRefreshStore())
	d.usageRecorder = rec
	return d, store
}

// stashGeo populates the HandlerContext value bag the way GeoMiddleware
// does after a successful lookup.
func stashGeo(t *testing.T, country string) *core.Context {
	t.Helper()
	ctx, _ := newCtx(http.MethodPost, ctFormURLEncoded, "token=x&client_id=c&client_secret=s")
	if country != "" {
		ctx.Set(geo.HandlerContextKey, &core.GeoInfo{CountryCode: country})
	}
	return ctx
}

// TestRecordIntrospectionUsage_StampsGeo proves the access-token introspect
// seam reads the request's geo and carries it on the Offer, with the
// existing client-id fallback and thumbprint untouched.
func TestRecordIntrospectionUsage_StampsGeo(t *testing.T) {
	t.Parallel()
	d, store := newIntrospectGeoDeps(t)
	claims := &core.TokenClaims{JTI: "jti-abc", Subject: "user-1", ClientID: "rp"}

	recordIntrospectionUsage(d, stashGeo(t, "FR"), claims)
	if err := d.usageRecorder.Close(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	got := store.taken()
	if len(got) != 1 {
		t.Fatalf("drained %d events, want 1", len(got))
	}
	if got[0].GeoCountry != "FR" {
		t.Errorf("GeoCountry = %q, want FR", got[0].GeoCountry)
	}
	if got[0].Thumbprint != metering.Thumbprint("jti-abc") {
		t.Errorf("Thumbprint = %q, want %q", got[0].Thumbprint, metering.Thumbprint("jti-abc"))
	}
	if got[0].Kind != metering.KindAccess || got[0].Endpoint != metering.EndpointIntrospect ||
		got[0].ClientID != "rp" || got[0].SubjectID != "user-1" {
		t.Errorf("event = %+v, want access/introspect rp/user-1", got[0])
	}
}

// TestRecordIntrospectionUsage_NoGeoByteIdentical proves the zero-value leg:
// without a stash the Event's GeoCountry stays "" — byte-identical to a
// build without the extractor.
func TestRecordIntrospectionUsage_NoGeoByteIdentical(t *testing.T) {
	t.Parallel()
	d, store := newIntrospectGeoDeps(t)

	recordIntrospectionUsage(d, stashGeo(t, ""), &core.TokenClaims{JTI: "jti-x", Subject: "user-1"})
	if err := d.usageRecorder.Close(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	for _, ev := range store.taken() {
		if ev.GeoCountry != "" {
			t.Errorf("GeoCountry = %q, want ''", ev.GeoCountry)
		}
	}
}

// TestIntrospectRefresh_OfferCarriesThumbprintAndGeo proves the
// refresh-introspection hole is closed: an ACTIVE refresh token with a
// stamped JTI produces an Offer with Thumbprint == SHA-256(jti) — the same
// discipline the access-token seam already uses — plus the request geo.
// Without a JTI (legacy row) the thumbprint stays "" (no observation).
func TestIntrospectRefresh_OfferCarriesThumbprintAndGeo(t *testing.T) {
	t.Parallel()
	now := time.Now()
	for _, tc := range []struct {
		name    string
		jti     string
		country string
		wantTP  bool
	}{
		{name: "stamped jti + geo", jti: "rt-jti-1", country: "SG", wantTP: true},
		{name: "legacy row without jti", jti: "", country: "SG", wantTP: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := newMemClientStore()
			cs.put(activeClient("rp"), "s")
			rs := newMemRefreshStore()
			_ = rs.Issue(context.Background(), "rtok", &RefreshToken{
				UserID: "user-9", ClientID: "rp", Scopes: []string{"offline_access"},
				IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour), JTI: tc.jti,
			})
			d, store := newIntrospectGeoDeps(t)
			d.clients = cs
			d.refresh = rs

			ctx, rec := newCtx(http.MethodPost, ctFormURLEncoded,
				"token=rtok&token_type_hint=refresh_token&client_id=rp&client_secret=s")
			ctx.Set(geo.HandlerContextKey, &core.GeoInfo{CountryCode: tc.country})
			HandleIntrospect(d, ctx)
			body := decodeBody(t, rec)
			if body["active"] != true {
				t.Fatalf("active = %v, want true (wire body untouched)", body["active"])
			}
			if err := d.usageRecorder.Close(context.Background()); err != nil {
				t.Fatalf("drain: %v", err)
			}

			got := store.taken()
			if len(got) != 1 {
				t.Fatalf("drained %d events, want 1", len(got))
			}
			if got[0].GeoCountry != tc.country {
				t.Errorf("GeoCountry = %q, want %q", got[0].GeoCountry, tc.country)
			}
			wantTP := ""
			if tc.wantTP {
				wantTP = metering.Thumbprint(tc.jti)
			}
			if got[0].Thumbprint != wantTP {
				t.Errorf("Thumbprint = %q, want %q", got[0].Thumbprint, wantTP)
			}
			if got[0].Kind != metering.KindRefresh || got[0].Endpoint != metering.EndpointIntrospect {
				t.Errorf("event = %+v, want refresh/introspect", got[0])
			}
		})
	}
}
