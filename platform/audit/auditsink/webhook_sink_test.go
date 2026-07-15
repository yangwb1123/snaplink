package auditsink

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit/auditspi"
	"github.com/snaplink/sso/shared/security/securityverify"
)

// captured records the shape of one inbound POST the test HTTP server saw,
// so assertions run after the WebhookSink call returns instead of racing the
// handler goroutine.
type captured struct {
	body    []byte
	headers http.Header
}

func startCapturingServer(t *testing.T, status int) (*httptest.Server, chan captured) {
	t.Helper()
	ch := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ch <- captured{body: body, headers: r.Header.Clone()}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

func TestWebhookSink_RecordSuccess_AssignsIDAndPostsJSON(t *testing.T) {
	t.Parallel()
	srv, ch := startCapturingServer(t, http.StatusOK)
	w := NewWebhookSink(srv.URL)

	e := &auditspi.Event{Type: auditspi.EventLogin, Outcome: auditspi.OutcomeSuccess}
	if err := w.Record(t.Context(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if e.ID == "" {
		t.Fatal("Record must assign an ID when the caller left it empty")
	}

	got := <-ch
	if ct := got.headers.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var decoded auditspi.Event
	if err := json.Unmarshal(got.body, &decoded); err != nil {
		t.Fatalf("posted body did not decode as an Event: %v", err)
	}
	if decoded.ID != e.ID || decoded.Type != auditspi.EventLogin {
		t.Errorf("posted event = %+v, want ID=%s Type=%s", decoded, e.ID, auditspi.EventLogin)
	}
}

func TestWebhookSink_RecordFailure_ServerErrorStatus(t *testing.T) {
	t.Parallel()
	srv, _ := startCapturingServer(t, http.StatusInternalServerError)
	w := NewWebhookSink(srv.URL)

	err := w.Record(t.Context(), &auditspi.Event{})
	if err == nil {
		t.Fatal("Record must return an error when the endpoint responds >= 400")
	}
}

func TestWebhookSink_WithWebhookHeader_AppliesStaticHeader(t *testing.T) {
	t.Parallel()
	srv, ch := startCapturingServer(t, http.StatusOK)
	w := NewWebhookSink(srv.URL, WithWebhookHeader("Authorization", "Bearer static-token"))

	if err := w.Record(t.Context(), &auditspi.Event{}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got := <-ch
	if v := got.headers.Get("Authorization"); v != "Bearer static-token" {
		t.Errorf("Authorization header = %q, want %q", v, "Bearer static-token")
	}
}

func TestWebhookSink_WithSigningSecret_SetsVerifiableSignature(t *testing.T) {
	t.Parallel()
	srv, ch := startCapturingServer(t, http.StatusOK)
	secret := []byte("shared-secret")
	w := NewWebhookSink(srv.URL, WithWebhookSigningSecret(string(secret)))

	if err := w.Record(t.Context(), &auditspi.Event{Type: auditspi.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got := <-ch
	sig := got.headers.Get(securityverify.WebhookSignatureHeader)
	if sig == "" {
		t.Fatal("signing secret configured but no signature header was sent")
	}
	if err := securityverify.VerifyWebhookSignature(secret, sig, got.body, time.Now(), 5*time.Minute); err != nil {
		t.Errorf("VerifyWebhookSignature failed: %v", err)
	}
}

func TestWebhookSink_NoSigningSecret_OmitsSignatureHeader(t *testing.T) {
	t.Parallel()
	srv, ch := startCapturingServer(t, http.StatusOK)
	w := NewWebhookSink(srv.URL)

	if err := w.Record(t.Context(), &auditspi.Event{}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got := <-ch
	if sig := got.headers.Get(securityverify.WebhookSignatureHeader); sig != "" {
		t.Errorf("signature header present (%q) with no secret configured", sig)
	}
}

// TestWebhookSink_RotatingSecretTakesPrecedence pins the documented ordering
// in WithWebhookRotatingSecret: when both a static and a rotating secret are
// configured, every send must sign with the rotating secret's CURRENT
// version, never falling back to the static one.
func TestWebhookSink_RotatingSecretTakesPrecedence(t *testing.T) {
	t.Parallel()
	srv, ch := startCapturingServer(t, http.StatusOK)
	rotating, err := securityverify.NewRotatingWebhookSecret([]byte("rotating-secret-000000000000000"))
	if err != nil {
		t.Fatalf("NewRotatingWebhookSecret: %v", err)
	}
	w := NewWebhookSink(srv.URL,
		WithWebhookSigningSecret("static-secret-should-be-ignored"),
		WithWebhookRotatingSecret(rotating),
	)

	if err := w.Record(t.Context(), &auditspi.Event{}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got := <-ch
	sig := got.headers.Get(securityverify.WebhookSignatureHeader)
	if err := securityverify.VerifyWebhookSignature(rotating.Current(), sig, got.body, time.Now(), 5*time.Minute); err != nil {
		t.Errorf("signature does not verify against the rotating secret's current version: %v", err)
	}
	if err := securityverify.VerifyWebhookSignature([]byte("static-secret-should-be-ignored"), sig, got.body, time.Now(), 5*time.Minute); err == nil {
		t.Error("signature verifies against the static secret; rotating secret should have taken precedence")
	}
}

func TestWebhookSink_GetAndQuery_AreWriteOnly(t *testing.T) {
	t.Parallel()
	w := NewWebhookSink("http://unused.invalid")
	if _, err := w.Get(t.Context(), "any"); err != ErrSinkWriteOnly {
		t.Errorf("Get() err = %v, want ErrSinkWriteOnly", err)
	}
	if _, err := w.Query(t.Context(), auditspi.Query{}); err != ErrSinkWriteOnly {
		t.Errorf("Query() err = %v, want ErrSinkWriteOnly", err)
	}
}

func TestWebhookSink_WithHTTPClient_Injected(t *testing.T) {
	t.Parallel()
	srv, ch := startCapturingServer(t, http.StatusOK)
	custom := &http.Client{Timeout: 2 * time.Second}
	w := NewWebhookSink(srv.URL, WithWebhookHTTPClient(custom))
	if w.client != custom {
		t.Fatal("WithWebhookHTTPClient did not install the injected client")
	}
	if err := w.Record(t.Context(), &auditspi.Event{}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	<-ch
}

func TestWebhookSink_WithHTTPClient_Nil_IsNoOp(t *testing.T) {
	t.Parallel()
	w := NewWebhookSink("http://unused.invalid", WithWebhookHTTPClient(nil))
	if w.client == nil {
		t.Fatal("WithWebhookHTTPClient(nil) must not clear the default client")
	}
}

// TestWebhookSink_DoesNotFollowRedirect proves NewWebhookSink's own default
// client (no WithWebhookHTTPClient override) never follows a redirect: a
// configured url that later 302s (compromised or misconfigured receiver)
// must not have the request silently forwarded to the redirect target --
// the same SSRF-via-redirect class already closed for CAEP/CIBA push/the
// generic webhook Engine. Since http.Client follows redirects synchronously
// within a single Do() call, redirectTargetHit is race-free to read right
// after Record returns.
func TestWebhookSink_DoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	var redirectTargetHit bool
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(redirectTarget.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	w := NewWebhookSink(srv.URL)
	_ = w.Record(t.Context(), &auditspi.Event{})
	if redirectTargetHit {
		t.Fatal("redirect target received a request: CheckRedirect failed to block the follow")
	}
}
