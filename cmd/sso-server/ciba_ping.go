package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/spi"
)

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
