// sso-audit-verify reads audit events (from a JSON file or the live
// /api/v1/audit/events API) and runs them through audit.VerifyChain
// to confirm the tamper-evident hash chain is intact.
//
// Usage:
//
//	sso-audit-verify --from-file events.json
//	sso-audit-verify --from-url https://sso.example.com --bearer $ADMIN_TOKEN
//
// Either source is mutually exclusive. URL mode pages through
// /api/v1/audit/events newest-first and reverses the buffer before
// verifying — the chain runs oldest-first per audit.VerifyChain
// semantics. The query API caps each page at
// audit.MaxQueryLimit (1000); --page-size lets operators tune.
//
// Exit code: 0 on a clean chain, 1 on a break / error.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
)

func main() {
	fromFile := flag.String("from-file", "", "path to JSON array of audit events (mutually exclusive with --from-url)")
	fromURL := flag.String("from-url", "", "base URL of the SSO server (mutually exclusive with --from-file)")
	bearer := flag.String("bearer", "", "admin bearer token for the /api/v1/audit/events API (required with --from-url)")
	limit := flag.Int("limit", 10_000, "max events to load")
	pageSize := flag.Int("page-size", 500, "URL-mode pagination batch size (caps at audit.MaxQueryLimit=1000)")
	timeoutSec := flag.Int("timeout-sec", 30, "URL-mode HTTP timeout in seconds")
	flag.Parse()

	if *fromFile == "" && *fromURL == "" {
		fail("one of --from-file or --from-url is required")
	}
	if *fromFile != "" && *fromURL != "" {
		fail("--from-file and --from-url are mutually exclusive")
	}

	var events []*audit.Event
	var err error
	if *fromFile != "" {
		events, err = readFromFile(*fromFile, *limit)
	} else {
		if *bearer == "" {
			fail("--bearer is required with --from-url")
		}
		events, err = readFromURL(*fromURL, *bearer, *limit, *pageSize, time.Duration(*timeoutSec)*time.Second)
	}
	if err != nil {
		fail("load events: " + err.Error())
	}
	if len(events) == 0 {
		fmt.Println("no events to verify")
		os.Exit(0)
	}

	if err := audit.VerifyChain(events); err != nil {
		fmt.Fprintf(os.Stderr, "chain BROKEN: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("chain verified: %d event(s), head=%s\n", len(events), events[len(events)-1].Hash)
}

// readFromFile reads a JSON file containing an array of Events.
// Accepts either the raw array OR an object with an "events" field
// (mirrors the /api/v1/audit/events response shape so operators
// can `curl > events.json` and feed it back in unmodified).
// Returns events in CHAIN ORDER (oldest first).
func readFromFile(path string, limit int) ([]*audit.Event, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	events, err := parseEventList(raw)
	if err != nil {
		return nil, err
	}
	// API-shaped responses come back newest-first; arrays from a
	// file might be either order. Detect by looking at the first
	// two PrevHashes: oldest-first puts the genesis (PrevHash=="")
	// at [0]; newest-first puts it at [len-1].
	if len(events) > 1 && events[0].PrevHash != "" && events[len(events)-1].PrevHash == "" {
		reverseEvents(events)
	}
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func parseEventList(raw []byte) ([]*audit.Event, error) {
	// Try array first.
	var arr []*audit.Event
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	// Try {events: [...]} envelope.
	var env struct {
		Events []*audit.Event `json:"events"`
	}
	if err := json.Unmarshal(raw, &env); err == nil && env.Events != nil {
		return env.Events, nil
	}
	return nil, errors.New("input is neither a JSON array nor an {events: [...]} object")
}

// readFromURL pages through /api/v1/audit/events newest-first, then
// returns them reversed (oldest first) so audit.VerifyChain accepts
// them directly. Stops when the server returns fewer events than
// the page size (no more pages) or when we've collected `limit`.
func readFromURL(base, bearer string, limit, pageSize int, timeout time.Duration) ([]*audit.Event, error) {
	if pageSize <= 0 {
		pageSize = 500
	}
	if pageSize > audit.MaxQueryLimit {
		pageSize = audit.MaxQueryLimit
	}
	parsed, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	client := &http.Client{Timeout: timeout}
	var collected []*audit.Event
	offset := 0
	for {
		u := *parsed
		u.Path = parsed.Path + "/api/v1/audit/events"
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
			return nil, fmt.Errorf("page (offset=%d) http %d: %s", offset, resp.StatusCode, string(body))
		}
		page, err := parseEventList(body)
		if err != nil {
			return nil, fmt.Errorf("parse page (offset=%d): %w", offset, err)
		}
		collected = append(collected, page...)
		if limit > 0 && len(collected) >= limit {
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
	return collected, nil
}

func reverseEvents(s []*audit.Event) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func fail(msg string) {
	fmt.Fprintf(os.Stderr, "sso-audit-verify: %s\n", msg)
	flag.Usage()
	os.Exit(2)
}
