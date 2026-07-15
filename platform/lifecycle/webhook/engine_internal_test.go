package webhook

import (
	"context"
	"net/http"
	"testing"
)

// TestNewEngine_DefaultClientBlocksRedirects proves NewEngine's own default
// client (no WithHTTPClient override) carries a CheckRedirect that treats
// any 3xx as terminal. Without this, a subscription URL that later 302s
// (compromised or misconfigured receiver, past validateHTTPSURL's shape
// check) would have Go's default http.Client silently follow it -- the same
// SSRF-via-redirect class already closed for CAEP/CIBA push. This is a
// package-internal (white-box) test, unlike this package's other _test.go
// files (package webhook_test), because it needs to read the unexported
// client field directly -- an end-to-end redirect-following proof already
// exists one layer down in auditsink.TestWebhookSink_DoesNotFollowRedirect,
// since newWebhookSink (engine_delivery.go) hands this exact client to
// audit.WebhookSink via WithWebhookHTTPClient for every real delivery.
func TestNewEngine_DefaultClientBlocksRedirects(t *testing.T) {
	e := NewEngine(nil, nil)
	defer func() { _ = e.Close(context.Background()) }()

	if e.client.CheckRedirect == nil {
		t.Fatal("default client has no CheckRedirect: a 3xx subscription response would be silently followed")
	}
	if err := e.client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect(...) = %v, want http.ErrUseLastResponse", err)
	}
}
