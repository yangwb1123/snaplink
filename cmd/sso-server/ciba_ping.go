package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildsign"
	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/config"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// --- CIBA Push Delivery (CIBA Core §10.3) ---
//
// Folded into this file (rather than a separate ciba_push.go) to respect
// cmd/sso-server's frozen directory_fanout_test.go file-count ceiling —
// push notification wiring is the direct sibling of ping's, above.

// cibaPushEndpointResolver adapts the cmd-config clientID -> endpoint map
// into the getDeliveryURI callback oauth.NewCIBAPushNotifier needs.
// Endpoints live in cmd config (not core.Client) for the same reason
// httpCIBAPingNotifier's endpoints do: keeps the SDK Client model minimal.
// The map is copied so later config mutation can't race the notifier.
func cibaPushEndpointResolver(cfg config.CIBAPushConfig) func(context.Context, string) (string, error) {
	eps := make(map[string]string, len(cfg.Endpoints))
	maps.Copy(eps, cfg.Endpoints)
	return func(_ context.Context, clientID string) (string, error) {
		return eps[clientID], nil
	}
}

// newHTTPCIBAPushNotifier wires the SDK's reference oauth.NewCIBAPushNotifier
// with cmd-config endpoints, timeout, retry count, and the dead-letter store
// serverbuildstore.BuildCIBAPushDeadLetter built.
func newHTTPCIBAPushNotifier(cfg config.CIBAConfig, deadLetter oauth.CIBAPushDeadLetterStore, logger spi.Logger) oauth.CIBAPushNotifier {
	opts := []oauth.CIBAPushNotifierOption{
		oauth.WithCIBAPushDeadLetterStore(deadLetter),
		oauth.WithCIBAPushLogger(logger),
	}
	if cfg.Push.Timeout > 0 {
		opts = append(opts, oauth.WithCIBAPushHTTPClient(&http.Client{Timeout: cfg.Push.Timeout}))
	}
	if cfg.Push.MaxRetries > 0 {
		opts = append(opts, oauth.WithCIBAPushMaxRetries(cfg.Push.MaxRetries))
	}
	return oauth.NewCIBAPushNotifier(cibaPushEndpointResolver(cfg.Push), opts...)
}

// wireCIBAPushDelivery wires CIBA push delivery (the dead-letter store +
// HTTP notifier) when cfg.Push.Enabled, appending options to b and
// registering the dead-letter store's schema-check/readiness/health when
// it's SQLite-backed. Returns the "+push" mode suffix (or "" when push is
// disabled) for wireCIBA's log line. Extracted (build_app_oauth.go) to keep
// wireCIBA under the function-length budget.
func (b *appBuilder) wireCIBAPushDelivery(cfg config.CIBAConfig, logger spi.Logger) (string, error) {
	if !cfg.Push.Enabled {
		return "", nil
	}
	dl, sqliteDL, err := serverbuildstore.BuildCIBAPushDeadLetter(cfg)
	if err != nil {
		return "", fmt.Errorf("ciba push: %w", err)
	}
	if sqliteDL != nil {
		if err := serverbuildsign.CheckSQLiteSchema(b.schemaCtx, sqliteDL, "ciba_push_deadletters", sqlitestores.CIBAPushDeadLettersMaxVersion()); err != nil {
			return "", fmt.Errorf("schema check ciba_push_deadletters: %w", err)
		}
		b.opts = serverbuildsign.AppendReadyCheck(b.opts, "sqlite-ciba-push-deadletter", sqliteDL)
		b.storageHealthSources = serverbuildsign.AppendStorageHealthSource(b.storageHealthSources, "sqlite-ciba-push-deadletter", sqliteDL)
	}
	b.opts = append(b.opts, sso.WithCIBAPushNotifier(newHTTPCIBAPushNotifier(cfg, dl, logger)))
	return "+push", nil
}

// defaultCIBAPingTimeout bounds a single ping POST. Kept short: the ping
// is best-effort UX (the client can still poll), so a slow/unreachable
// endpoint must not tie up the resolution goroutine.
const defaultCIBAPingTimeout = 5 * time.Second

// httpCIBAPingNotifier is the reference oauth.CIBAPingNotifier: on
// resolution it POSTs {"auth_req_id": "..."} to the client's registered
// notification endpoint, authenticating with the per-request
// client_notification_token as a bearer (CIBA Core §10.2). Endpoints are
// a clientID → URL map from cmd config, so core.Client stays minimal.
//
// Best-effort by contract: a client absent from the map degrades to poll
// (returns nil, no error), and a transport/status failure returns an
// error the Server logs but does not surface to the client.
type httpCIBAPingNotifier struct {
	endpoints map[string]string
	client    *http.Client
	logger    spi.Logger
}

func newHTTPCIBAPingNotifier(cfg config.CIBAPingConfig, logger spi.Logger) *httpCIBAPingNotifier {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultCIBAPingTimeout
	}
	// Copy the map so later config mutation can't race the notifier.
	eps := make(map[string]string, len(cfg.Endpoints))
	maps.Copy(eps, cfg.Endpoints)
	return &httpCIBAPingNotifier{
		endpoints: eps,
		client:    &http.Client{Timeout: timeout},
		logger:    logger,
	}
}

var _ oauth.CIBAPingNotifier = (*httpCIBAPingNotifier)(nil)

func (n *httpCIBAPingNotifier) Notify(ctx context.Context, clientID, authReqID, token string) error {
	endpoint := n.endpoints[clientID]
	if endpoint == "" {
		// No registered endpoint: the client uses poll. Not an error.
		n.logger.Info("ciba ping skipped: no notification endpoint for client", "client_id", clientID)
		return nil
	}
	body, err := json.Marshal(map[string]string{"auth_req_id": authReqID})
	if err != nil {
		return fmt.Errorf("ciba ping: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ciba ping: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("ciba ping: post to %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ciba ping: endpoint %s returned %d", endpoint, resp.StatusCode)
	}
	return nil
}
