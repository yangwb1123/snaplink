package auditverify

import (
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

// auditRedirectHint is the operator remediation hint for --from-url mode:
// auditverify reads no env vars, so --from-url is the only knob (the
// SSO_ADMIN_ADDR hint would be wrong here).
const auditRedirectHint = "point --from-url at the canonical audit API origin"

// readFromURL pages through /api/v1/audit/events newest-first, then
// returns them reversed (oldest first) so audit.VerifyChain accepts
// them directly. Stops when the server returns fewer events than
// the page size (no more pages) or when we've collected `limit`.
// The truncated flag reports a --limit cap that cut the chain short:
// over-capture (the final page carried more events than needed) is
// already truncation; an exact fill probes one extra page at the next
// offset to decide whether the chain continues (fail-closed for
// anchored runs). --limit 0 never truncates.
func readFromURL(base, bearer string, limit, pageSize int, timeout time.Duration) ([]*audit.Event, bool, error) {
	if pageSize <= 0 {
		pageSize = 500
	}
	if pageSize > audit.MaxQueryLimit {
		pageSize = audit.MaxQueryLimit
	}
	parsed, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return nil, false, fmt.Errorf("parse base URL: %w", err)
	}
	// The raw client is pinned with the shared RejectRedirect policy: the
	// bearer (and a 307/308-replayed body) must never be forwarded to a
	// redirect target.
	client := &http.Client{Timeout: timeout, CheckRedirect: apiclient.RejectRedirect}
	var collected []*audit.Event
	truncated := false
	offset := 0
	for {
		page, err := fetchEventPage(client, parsed, bearer, pageSize, offset)
		if err != nil {
			return nil, false, err
		}
		collected = append(collected, page...)
		if limit > 0 && len(collected) >= limit {
			truncated = len(collected) > limit
			if !truncated {
				// Exactly `limit` events: one probe page at the next
				// offset decides whether more exist (+1 request max).
				probe, perr := fetchEventPage(client, parsed, bearer, pageSize, offset)
				if perr != nil {
					return nil, false, perr
				}
				truncated = len(probe) > 0
			}
			collected = collected[:limit]
			break
		}
		if len(page) < pageSize {
			break
		}
		offset += len(page)
	}
	// API returns newest-first; flip for chain-order verification.
	reverseEvents(collected)
	return collected, truncated, nil
}

// fetchEventPage retrieves one /api/v1/audit/events page at the given offset.
// Errors carry the offset so a multi-page failure pinpoints where it stopped.
// A 3xx response is a redirect that was observed, never followed; it renders
// the shared redirect diagnostic (redacted Location + --from-url hint).
func fetchEventPage(client *http.Client, base *url.URL, bearer string, pageSize, offset int) ([]*audit.Event, error) {
	u := *base
	u.Path = base.Path + "/api/v1/audit/events"
	q := u.Query()
	q.Set("limit", strconv.Itoa(pageSize))
	q.Set("offset", strconv.Itoa(offset))
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch page (offset=%d): %w", offset, err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read page body (offset=%d): %w", offset, readErr)
	}
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return nil, errors.New(apiclient.StatusMessage(progName, fmt.Sprintf("fetch page (offset=%d)", offset), auditRedirectHint, resp, body))
		}
		return nil, fmt.Errorf("page (offset=%d) http %d: %s", offset, resp.StatusCode, string(body))
	}
	page, err := parseEventList(body)
	if err != nil {
		return nil, fmt.Errorf("parse page (offset=%d): %w", offset, err)
	}
	return page, nil
}

func reverseEvents(s []*audit.Event) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
