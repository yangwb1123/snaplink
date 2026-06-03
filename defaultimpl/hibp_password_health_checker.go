package defaultimpl

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/spi"
)

// Default HIBP range-API surface. Overridable for tests / self-hosted
// mirrors via WithHIBPBaseURL.
const (
	defaultHIBPBaseURL   = "https://api.pwnedpasswords.com/range/"
	defaultHIBPTimeout   = 5 * time.Second
	defaultHIBPUserAgent = "snaplink-sso-password-health/1"
	// hibpPrefixLen is the SHA-1 hex prefix length the k-anonymity range
	// API keys on. This is the ONLY part of the hash that ever leaves the
	// process — the model's entire privacy guarantee rests on it being 5.
	hibpPrefixLen = 5
)

// HIBPPasswordHealthChecker is a dependency-free [spi.PasswordHealthChecker]
// that checks a just-verified plaintext password against the Have I Been
// Pwned breached-password corpus via its k-anonymity range API.
//
// k-anonymity / privacy: the password is SHA-1'd locally, then ONLY the
// first 5 hex characters of that hash are sent to the API as a range
// query (GET <baseURL><prefix>). The API answers with every breached-hash
// SUFFIX sharing that prefix (plus a breach count); the suffix comparison
// is done entirely in-process. The full hash and the plaintext NEVER leave
// this process, and the request additionally carries `Add-Padding: true`
// so the response size cannot fingerprint which prefix was queried (HIBP
// pads short ranges with random count-0 entries). This is why we must
// never widen the prefix, never log the suffix/full-hash/password, and
// never put the breach detail on the wire.
//
// Discipline (mirrors [DictionaryPasswordHealthChecker] + the password
// authenticator's contract): the check runs ONLY after the password has
// already verified (login is this server's sole plaintext touchpoint), is
// non-blocking, and is strictly fail-OPEN. Any failure — network error,
// non-200 status, timeout, malformed body — yields (nil, nil): no signal,
// no error, login proceeds. Failing closed on an HIBP outage would lock
// every password user out, far worse than skipping one advisory. A hit
// rides back as a Compromised [core.CredentialHealth] whose Reason (the
// breach count) lands in audit metadata only; the orchestrator turns it
// into a password_compromised audit event + the
// sso_credential_health_signals_total{compromised} metric, and AuthResult.
// CredentialHealth is json:"-" so it never reaches a token.
type HIBPPasswordHealthChecker struct {
	baseURL   string
	userAgent string
	minCount  int64
	client    *http.Client
	// logger is optional. The fail-open contract is enforced HERE (Check
	// never returns a blocking error), so the only way an HIBP outage is
	// observable is if the checker logs it itself — the authenticator's
	// error-path logging never fires because we return nil error.
	logger spi.Logger
}

var _ spi.PasswordHealthChecker = (*HIBPPasswordHealthChecker)(nil)

// HIBPOption configures [NewHIBPPasswordHealthChecker].
type HIBPOption func(*HIBPPasswordHealthChecker)

// WithHIBPBaseURL overrides the range-API base URL (default
// https://api.pwnedpasswords.com/range/). The prefix is appended directly,
// so the value MUST end in a trailing slash. Used for tests (httptest) and
// self-hosted HIBP mirrors. An empty string is ignored (default kept).
func WithHIBPBaseURL(url string) HIBPOption {
	return func(c *HIBPPasswordHealthChecker) {
		if url != "" {
			c.baseURL = url
		}
	}
}

// WithHIBPHTTPClient overrides the default *http.Client (default a client
// with a few-second Timeout). Useful for threading a custom transport
// (proxy, TLS pin, dialer). A nil client is ignored (default kept). When a
// custom client carries its own Timeout, prefer this over WithHIBPTimeout.
func WithHIBPHTTPClient(client *http.Client) HIBPOption {
	return func(c *HIBPPasswordHealthChecker) {
		if client != nil {
			c.client = client
		}
	}
}

// WithHIBPTimeout sets the per-request timeout on the default client
// (default 5s). Ignored when a custom client was supplied via
// WithHIBPHTTPClient (that client owns its own timeout) and ignored for
// non-positive durations. The lookup is on the synchronous login path, so
// keep this small — it caps how long a slow/hung HIBP endpoint can delay a
// login before the fail-open path kicks in.
func WithHIBPTimeout(d time.Duration) HIBPOption {
	return func(c *HIBPPasswordHealthChecker) {
		if d > 0 {
			c.client.Timeout = d
		}
	}
}

// WithHIBPMinCount only flags a password as compromised when its breach
// count is >= n (default 1, i.e. flag any appearance). Raising it lets an
// operator ignore very-rarely-seen hashes. n <= 0 is normalized to 1.
func WithHIBPMinCount(n int) HIBPOption {
	return func(c *HIBPPasswordHealthChecker) {
		if n < 1 {
			n = 1
		}
		c.minCount = int64(n)
	}
}

// WithHIBPUserAgent overrides the User-Agent the range request carries
// (default snaplink-sso-password-health/1). HIBP recommends a descriptive
// UA; some mirrors require a non-empty one. Empty is ignored.
func WithHIBPUserAgent(ua string) HIBPOption {
	return func(c *HIBPPasswordHealthChecker) {
		if ua != "" {
			c.userAgent = ua
		}
	}
}

// WithHIBPLogger attaches an optional logger used ONLY to surface fail-open
// HIBP outages (network error, non-200, parse error) at Error level —
// matching the fail-open logging convention used elsewhere (risk scorer,
// geo, audit sink). It NEVER changes the outcome: the check still returns
// (nil, nil) on failure. nil keeps the checker silent.
func WithHIBPLogger(l spi.Logger) HIBPOption {
	return func(c *HIBPPasswordHealthChecker) { c.logger = l }
}

// NewHIBPPasswordHealthChecker builds the checker with the default range
// API and a 5s-timeout client, then applies opts. It never returns an
// error (there is no operator file to misread, unlike the dictionary
// checker) but keeps the (value, error) shape for symmetry and future
// validation.
func NewHIBPPasswordHealthChecker(opts ...HIBPOption) (*HIBPPasswordHealthChecker, error) {
	c := &HIBPPasswordHealthChecker{
		baseURL:   defaultHIBPBaseURL,
		userAgent: defaultHIBPUserAgent,
		minCount:  1,
		client:    &http.Client{Timeout: defaultHIBPTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Check reports a Compromised signal when the password's SHA-1 suffix
// appears in the HIBP range for its prefix with a count >= MinCount, else
// (nil, nil). Every failure mode is fail-open: (nil, nil), no error.
func (c *HIBPPasswordHealthChecker) Check(ctx context.Context, password string) (*core.CredentialHealth, error) {
	// SHA-1 of the plaintext. SHA-1 is used because that is the corpus
	// HIBP indexes — this is a breach-corpus lookup key, NOT a password
	// hash for storage (storage hashing is bcrypt, done by the verifier
	// before this ever runs).
	sum := sha1.Sum([]byte(password))
	hexHash := strings.ToUpper(hex.EncodeToString(sum[:])) // 40 hex chars
	prefix := hexHash[:hibpPrefixLen]
	suffix := hexHash[hibpPrefixLen:]

	count, err := c.lookup(ctx, prefix, suffix)
	if err != nil {
		// Fail-open: never block a login on an HIBP outage. Logged (if a
		// logger is wired) for observability; the password and hash are
		// deliberately NOT logged. Only the queried prefix is non-secret.
		if c.logger != nil {
			c.logger.Error("hibp password health check failed (fail-open)", "prefix", prefix, "error", err)
		}
		return nil, nil
	}
	if count >= c.minCount {
		return &core.CredentialHealth{
			Compromised: true,
			// Operator-facing only (audit metadata, never on the wire).
			// The count is breach-corpus prevalence, useful triage signal.
			Reason: fmt.Sprintf("found in HaveIBeenPwned breach corpus (count %d)", count),
		}, nil
	}
	return nil, nil
}

// lookup performs the k-anonymity range request for prefix and scans the
// response for suffix, returning its breach count (0 when absent). Any
// transport/HTTP/parse failure returns an error for the fail-open caller.
func (c *HIBPPasswordHealthChecker) lookup(ctx context.Context, prefix, suffix string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+prefix, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	// Add-Padding asks HIBP to pad the response with random count-0 entries
	// so the response length cannot reveal which prefix was queried — extra
	// privacy on top of k-anonymity. We must therefore IGNORE count-0 lines
	// when matching (they are padding, never real breach hits).
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("http GET range: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("http GET range: status %d", resp.StatusCode)
	}

	// Body lines are "<SUFFIX>:<COUNT>", one per breached hash sharing the
	// prefix, typically CRLF-terminated. bufio.Scanner's ScanLines strips
	// the trailing \r, so CRLF and LF both parse cleanly.
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		sfx, cnt, ok := strings.Cut(line, ":")
		if !ok {
			continue // tolerate stray/blank lines rather than fail the lookup
		}
		// Suffix match is case-insensitive: our suffix is upper-hex, but a
		// mirror could return lower-hex. Trim guards stray surrounding
		// whitespace.
		if !strings.EqualFold(strings.TrimSpace(sfx), suffix) {
			continue
		}
		n, perr := strconv.ParseInt(strings.TrimSpace(cnt), 10, 64)
		if perr != nil {
			return 0, fmt.Errorf("parse count for matched suffix: %w", perr)
		}
		// A count-0 line is Add-Padding noise, not a real hit; ignore it
		// and keep scanning in case a real entry follows.
		if n <= 0 {
			continue
		}
		return n, nil
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("read range body: %w", err)
	}
	return 0, nil // suffix not present (or only as padding) → not breached
}
