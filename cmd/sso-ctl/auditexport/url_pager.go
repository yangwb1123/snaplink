package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// urlRedirectHint is the operator remediation hint for --from-url mode:
// audit-export reads no env vars, so --from-url is the only knob (the
// SSO_ADMIN_ADDR hint would be wrong here).
const urlRedirectHint = "point --from-url at the canonical audit API origin"

// urlPager is a QueryPager adapter over the live /api/v1/audit/events
// API: it returns exactly ONE newest-first page per Query call, so
// BuildExportBundle's pageAll drives q.Offset/q.Limit and owns the final
// reversal — the adapter must NOT reverse (pre-reversing would break
// pagination). It forwards the populated filter params in the API's own
// vocabulary (type, outcome, actor_id, client_id, tenant_id, provider,
// request_id, trace_id, since, until — RFC3339 UTC), sends the bearer
// token, and names the failing offset in every non-2xx diagnostic.
//
// The http.Client is pinned with the shared RejectRedirect policy: the
// bearer (and a 307/308-replayed body) must never be forwarded to a
// redirect target. Close releases idle connections; audit-export defers
// it over every source (the same path the store sinks use).
type urlPager struct {
	base   *url.URL
	bearer string
	client *http.Client
}

// newURLPager parses base (a trailing slash is tolerated) and builds the
// bearer-carrying client with the shared no-redirect policy.
func newURLPager(base, bearer string, timeout time.Duration) (*urlPager, error) {
	parsed, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: apiclient.RejectRedirect}
	return &urlPager{base: parsed, bearer: bearer, client: client}, nil
}

// Close releases idle connections; satisfies the Closer audit-export
// defers over every source.
func (p *urlPager) Close() error {
	if p == nil || p.client == nil {
		return nil
	}
	p.client.CloseIdleConnections()
	return nil
}

// Query fetches one /api/v1/audit/events page at q.Offset. q.Limit is
// always exportPageSize (= audit.MaxQueryLimit) when driven by pageAll,
// so the adapter forwards it verbatim; q.Offset advances per page.
func (p *urlPager) Query(ctx context.Context, q audit.Query) ([]*audit.Event, error) {
	u := *p.base
	u.Path = p.base.Path + "/api/v1/audit/events"
	params := u.Query()
	params.Set("limit", strconv.Itoa(q.Limit))
	params.Set("offset", strconv.Itoa(q.Offset))
	setURLParam(params, "type", string(q.Type))
	setURLParam(params, "outcome", string(q.Outcome))
	setURLParam(params, "actor_id", q.ActorID)
	setURLParam(params, "client_id", q.ClientID)
	setURLParam(params, "tenant_id", q.TenantID)
	setURLParam(params, "provider", q.Provider)
	setURLParam(params, "request_id", q.RequestID)
	setURLParam(params, "trace_id", q.TraceID)
	if !q.Since.IsZero() {
		params.Set("since", q.Since.UTC().Format(time.RFC3339))
	}
	if !q.Until.IsZero() {
		params.Set("until", q.Until.UTC().Format(time.RFC3339))
	}
	u.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request (offset=%d): %w", q.Offset, err)
	}
	req.Header.Set("Authorization", "Bearer "+p.bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch page (offset=%d): %w", q.Offset, err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read page body (offset=%d): %w", q.Offset, readErr)
	}
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return nil, errors.New(apiclient.StatusMessage(progName, fmt.Sprintf("fetch page (offset=%d)", q.Offset), urlRedirectHint, resp, body))
		}
		return nil, fmt.Errorf("page (offset=%d) http %d: %s", q.Offset, resp.StatusCode, string(body))
	}
	page, err := parseEventPage(body)
	if err != nil {
		return nil, fmt.Errorf("parse page (offset=%d): %w", q.Offset, err)
	}
	return page, nil
}

// setURLParam adds v to params under key unless v is empty, so unset
// filters are wildcards exactly as the server's parseQuery treats them.
func setURLParam(params url.Values, key, v string) {
	if v == "" {
		return
	}
	params.Set(key, v)
}

// parseEventPage accepts both the raw JSON array shape and the
// {"events":[...]} envelope the live API returns, so an operator can
// point --from-url at any compatible endpoint.
func parseEventPage(raw []byte) ([]*audit.Event, error) {
	var arr []*audit.Event
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	var env struct {
		Events []*audit.Event `json:"events"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && env.Events != nil {
		return env.Events, nil
	}
	return nil, errors.New("response is neither a JSON array nor an {events: [...]} object")
}
