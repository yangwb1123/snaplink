package sms

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Stable literals — no literal leaks (AGENTS.md §4). messagesPathTemplate is
// Twilio's documented Messages resource path: POST
// /2010-04-01/Accounts/{AccountSid}/Messages.json.
const (
	defaultBaseURL         = "https://api.twilio.com"
	messagesPathTemplate   = "/2010-04-01/Accounts/%s/Messages.json"
	defaultMessageTemplate = "Your verification code is: {code}"
	defaultHTTPTimeout     = 10 * time.Second
	codePlaceholder        = "{code}"

	formFieldTo   = "To"
	formFieldFrom = "From"
	formFieldBody = "Body"

	hdrContentType  = "Content-Type"
	contentTypeForm = "application/x-www-form-urlencoded"
)

// Sender is a generic HTTP REST SMS sender compatible with Twilio's Messages
// API contract. It structurally satisfies domains/authenticators.SMSSender
// (Send(ctx, phone, code string) error) without importing that package:
// domains/ authenticators sits above infrastructure/ in this repo's
// dependency direction (see Config's doc comment) — the interface guard
// instead lives at the cmd wiring site (cmd/sso-server/serverbuildauthn),
// matching infrastructure/defaultimpl/emailsmtp.Sender's structural-only
// satisfaction of domains/authenticators.EmailSender.
type Sender struct {
	cfg    Config
	client *http.Client
}

// New validates cfg and builds a Sender. AccountSID, AuthToken, and
// FromNumber are required: a misconfigured "http" SMS provider must fail
// loud at boot (the caller's error to propagate) rather than silently drop
// every SMS delivery in production.
func New(cfg Config) (*Sender, error) {
	if strings.TrimSpace(cfg.AccountSID) == "" {
		return nil, errors.New("sms: account_sid required")
	}
	if strings.TrimSpace(cfg.AuthToken) == "" {
		return nil, errors.New("sms: auth_token required")
	}
	if strings.TrimSpace(cfg.FromNumber) == "" {
		return nil, errors.New("sms: from_number required")
	}
	if cfg.MessageTemplate == "" {
		cfg.MessageTemplate = defaultMessageTemplate
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = defaultHTTPTimeout
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	return &Sender{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.HTTPTimeout},
	}, nil
}

// Send renders the message template and POSTs it to the configured
// Messages resource with HTTP Basic Auth (AccountSID/AuthToken) and a
// form-encoded To/From/Body body, honoring ctx cancellation/timeout via
// http.NewRequestWithContext. Any non-2xx response becomes an error —
// deliberately WITHOUT the response body: a provider's error payload can
// echo account-identifying detail, and the oracle-leak-hardening principle
// (AGENTS.md) applies to outbound transports too, not only inbound
// endpoints, so only the status code is surfaced.
func (s *Sender) Send(ctx context.Context, phone, code string) error {
	body := strings.ReplaceAll(s.cfg.MessageTemplate, codePlaceholder, code)
	form := url.Values{
		formFieldTo:   {phone},
		formFieldFrom: {s.cfg.FromNumber},
		formFieldBody: {body},
	}
	endpoint := s.cfg.BaseURL + fmt.Sprintf(messagesPathTemplate, s.cfg.AccountSID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("sms: build request: %w", err)
	}
	req.Header.Set(hdrContentType, contentTypeForm)
	req.SetBasicAuth(s.cfg.AccountSID, s.cfg.AuthToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sms: send request: %w", err)
	}
	defer resp.Body.Close()
	// Drain (never log) the body — see the doc comment above on why the raw
	// response is not surfaced.
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sms: provider returned unexpected status %d", resp.StatusCode)
	}
	return nil
}
