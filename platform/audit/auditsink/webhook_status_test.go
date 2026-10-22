package auditsink

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

type closeTrackingBody struct {
	io.ReadCloser
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return b.ReadCloser.Close()
}

type closeTrackingTransport struct {
	base http.RoundTripper
	body *closeTrackingBody
}

func (t *closeTrackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	t.body = &closeTrackingBody{ReadCloser: resp.Body}
	resp.Body = t.body
	return resp, nil
}

func TestWebhookSink_RequiresFinal2xxAcknowledgement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"ok", http.StatusOK, false},
		{"created", http.StatusCreated, false},
		{"no-content", http.StatusNoContent, false},
		{"last-2xx", 299, false},
		{"multiple-choices", http.StatusMultipleChoices, true},
		{"moved-permanently", http.StatusMovedPermanently, true},
		{"found", http.StatusFound, true},
		{"not-modified", http.StatusNotModified, true},
		{"temporary-redirect", http.StatusTemporaryRedirect, true},
		{"last-3xx", 399, true},
		{"bad-request", http.StatusBadRequest, true},
		{"unauthorized", http.StatusUnauthorized, true},
		{"too-many-requests", http.StatusTooManyRequests, true},
		{"server-error", http.StatusInternalServerError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(srv.Close)

			err := NewWebhookSink(srv.URL).Record(t.Context(), &auditspi.Event{})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Record accepted status %d as delivered", tc.status)
				}
				if !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
					t.Errorf("delivery error lacks numeric status %d", tc.status)
				}
				return
			}
			if err != nil {
				t.Errorf("Record rejected status %d: %v", tc.status, err)
			}
		})
	}
}

func TestWebhookSink_DefaultClientRejectsRedirectWithoutFollowing(t *testing.T) {
	t.Parallel()
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	var originHits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		http.Redirect(w, r, target.URL+"/delivery-target", http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	err := NewWebhookSink(origin.URL).Record(t.Context(), &auditspi.Event{})
	if err == nil {
		t.Fatal("Record accepted a 302 redirect as delivered")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(http.StatusFound)) {
		t.Error("delivery error lacks numeric 302 status")
	}
	if got := targetHits.Load(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0", got)
	}
	if got := originHits.Load(); got != 1 {
		t.Errorf("origin received %d requests, want 1", got)
	}
	if strings.Contains(err.Error(), target.URL) {
		t.Error("delivery error exposed the redirect destination")
	}
}

func TestWebhookSink_ResponseBodyClosedOnSuccessAndFailure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"ok", http.StatusOK, false},
		{"not-modified", http.StatusNotModified, true},
		{"server-error", http.StatusInternalServerError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const bodyMarker = "response-body-marker"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, bodyMarker)
			}))
			t.Cleanup(srv.Close)

			rt := &closeTrackingTransport{base: http.DefaultTransport}
			client := &http.Client{Transport: rt, Timeout: 2 * time.Second}
			sink := NewWebhookSink(srv.URL, WithWebhookHTTPClient(client))
			err := sink.Record(t.Context(), &auditspi.Event{})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Record accepted status %d as delivered", tc.status)
				}
				if strings.Contains(err.Error(), bodyMarker) {
					t.Error("delivery error exposed the response body")
				}
			} else if err != nil {
				t.Fatalf("Record rejected status %d: %v", tc.status, err)
			}
			if rt.body == nil {
				t.Fatal("no response body reached the sink")
			}
			if !rt.body.closed {
				t.Error("Record returned without closing the response body")
			}
		})
	}
}

func TestWebhookSink_ErrorReportsOnlyNumericStatus(t *testing.T) {
	t.Parallel()
	const (
		authFixture = "Bearer fixture-auth-value"
		bodyMarker  = "fixture-response-body"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, bodyMarker)
	}))
	t.Cleanup(srv.Close)

	sink := NewWebhookSink(srv.URL, WithWebhookHeader("Authorization", authFixture))
	err := sink.Record(t.Context(), &auditspi.Event{})
	if err == nil {
		t.Fatal("Record accepted a 502 response as delivered")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(http.StatusBadGateway)) {
		t.Error("delivery error lacks numeric 502 status")
	}
	leaks := []struct {
		name  string
		value string
	}{
		{"body", bodyMarker},
		{"credential", authFixture},
		{"destination", srv.URL},
	}
	for _, leak := range leaks {
		if strings.Contains(err.Error(), leak.value) {
			t.Errorf("delivery error exposed %s details", leak.name)
		}
	}
}

type retryObservation struct {
	id  string
	err error
}

func TestWebhookSink_RetryingSinkRetriesRedirectThenSucceeds(t *testing.T) {
	t.Parallel()
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	var attempts atomic.Int32
	observed := make(chan retryObservation, 2)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		var e auditspi.Event
		decodeErr := json.NewDecoder(r.Body).Decode(&e)
		observed <- retryObservation{id: e.ID, err: decodeErr}
		if attempt == 1 {
			http.Redirect(w, r, target.URL, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)

	const eventID = "evt-retry-constant"
	sink := NewRetryingSink(NewWebhookSink(origin.URL),
		WithRetryMaxAttempts(2),
		WithRetryInitialBackoff(time.Millisecond),
		WithRetryMaxBackoff(time.Millisecond),
	)
	if err := sink.Record(t.Context(), &auditspi.Event{ID: eventID}); err != nil {
		t.Fatalf("RetryingSink.Record: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("origin received %d attempts, want 2", got)
	}
	if got := targetHits.Load(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0", got)
	}
	for i := 0; i < 2; i++ {
		got := <-observed
		if got.err != nil {
			t.Fatalf("posted event decode: %v", got.err)
		}
		if got.id != eventID {
			t.Errorf("attempt %d event ID = %q, want %q", i+1, got.id, eventID)
		}
	}
}
