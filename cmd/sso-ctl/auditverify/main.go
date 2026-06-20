// Package auditverify reads audit events (from a JSON file or the live
// /api/v1/audit/events API) and runs them through audit.VerifyChain
// to confirm the tamper-evident hash chain is intact.
//
// Usage:
//
//	sso-ctl audit-verify --from-file events.json
//	sso-ctl audit-verify --from-url https://sso.example.com --bearer $ADMIN_TOKEN
//
// Either source is mutually exclusive. URL mode pages through
// /api/v1/audit/events newest-first and reverses the buffer before
// verifying — the chain runs oldest-first per audit.VerifyChain
// semantics. The query API caps each page at
// audit.MaxQueryLimit (1000); --page-size lets operators tune.
//
// Exit code: 0 on a clean chain, 1 on a break / error.
package auditverify

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

	"github.com/snaplink/sso/platform/audit"
)

const progName = "sso-ctl audit-verify"

// usage prints the standard "<prog> — <desc> / Usage / Flags" banner.
// Wired as the FlagSet's Usage so -h and parse errors render it. The
// flag defaults come from the FlagSet built in Run; usageFlags holds
// that set so the standalone banner (also exercised directly in tests)
// stays self-contained.
var usageFlags *flag.FlagSet

func usage() {
	fmt.Fprint(os.Stderr, progName+` — verify the tamper-evident audit hash chain offline.

Usage:
  `+progName+` --from-file events.json
  `+progName+` --from-url https://sso.example.com --bearer $ADMIN_TOKEN

Flags:
`)
	if usageFlags != nil {
		usageFlags.PrintDefaults()
	}
}

// Run executes the audit-verify subcommand over args (the argument
// slice WITHOUT the leading program name). It returns the process exit
// code: 0 on a clean chain / empty input, 1 on a chain break or load
// error. CLI-misuse paths (usageErr) and runtime load errors (errorf)
// exit the process directly, preserving the original main() behavior.
func Run(args []string) int {
	fs := flag.NewFlagSet("sso-ctl audit-verify", flag.ExitOnError)
	usageFlags = fs
	fs.Usage = usage
	fromFile := fs.String("from-file", "", "path to JSON array of audit events (mutually exclusive with --from-url)")
	fromURL := fs.String("from-url", "", "base URL of the SSO server (mutually exclusive with --from-file)")
	bearer := fs.String("bearer", "", "admin bearer token for the /api/v1/audit/events API (required with --from-url)")
	limit := fs.Int("limit", 10_000, "max events to load")
	pageSize := fs.Int("page-size", 500, "URL-mode pagination batch size (caps at audit.MaxQueryLimit=1000)")
	timeoutSec := fs.Int("timeout-sec", 30, "URL-mode HTTP timeout in seconds")
	_ = fs.Parse(args)

	if *fromFile == "" && *fromURL == "" {
		usageErr("one of --from-file or --from-url is required")
	}
	if *fromFile != "" && *fromURL != "" {
		usageErr("--from-file and --from-url are mutually exclusive")
	}

	var events []*audit.Event
	var err error
	if *fromFile != "" {
		events, err = readFromFile(*fromFile, *limit)
	} else {
		if *bearer == "" {
			usageErr("--bearer is required with --from-url")
		}
		events, err = readFromURL(*fromURL, *bearer, *limit, *pageSize, time.Duration(*timeoutSec)*time.Second)
	}
	if err != nil {
		errorf("load events: %v", err)
	}
	if len(events) == 0 {
		fmt.Println("no events to verify")
		return 0
	}

	if err := audit.VerifyChain(events); err != nil {
		fmt.Fprintf(os.Stderr, "chain BROKEN: %v\n", err)
		return 1
	}
	fmt.Printf("chain verified: %d event(s), head=%s\n", len(events), events[len(events)-1].Hash)
	return 0
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
		page, err := fetchEventPage(client, parsed, bearer, pageSize, offset)
		if err != nil {
			return nil, err
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

// fetchEventPage retrieves one /api/v1/audit/events page at the given offset.
// Errors carry the offset so a multi-page failure pinpoints where it stopped.
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

// usageErr prints "<prog>: <msg>", the usage banner, and exits 2 (CLI misuse).
func usageErr(format string, args ...any) {
	fmt.Fprintf(os.Stderr, progName+": "+format+"\n", args...)
	usage()
	os.Exit(2)
}

// errorf prints "<prog>: <msg>" and exits 1 (runtime error).
func errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, progName+": "+format+"\n", args...)
	os.Exit(1)
}
