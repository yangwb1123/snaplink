package snaplink

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	activationPreparePath = "/api/v1/activation/prepare"
	activationClaimPath   = "/api/v1/me/activation/claim"
	accountContextPath    = "/api/v1/me/account-context"
)

// SetupOptions prepares a one-time license or invitation activation. The
// credential is sent in an HTTPS JSON body and is never included in login
// state, redirect URLs, or the SDK's state store.
type SetupOptions struct {
	BaseURL                         string
	ClientID                        string
	ProductID                       string
	LicenseKey                      string
	InvitationCode                  string
	TenantHint                      string
	Locale                          string
	AppVersion                      string
	AllowInsecureHTTPForDevelopment bool
}

// ActivationPreparation is the short-lived ticket returned by setup.
type ActivationPreparation struct {
	ActivationTicket string `json:"activation_ticket"`
	ExpiresIn        int    `json:"expires_in"`
	ProductID        string `json:"product_id"`
}

// AccountContext is server-derived product, tenant, entitlement, and quota
// information. Clients cannot submit or override these fields.
type AccountContext struct {
	ProductID   string         `json:"product_id"`
	TenantID    string         `json:"tenant_id"`
	Entitlement map[string]any `json:"entitlement,omitempty"`
}

type activationContextResponse struct {
	Context AccountContext `json:"context"`
}

type activationPrepareRequest struct {
	ClientID       string `json:"client_id"`
	ProductID      string `json:"product_id"`
	LicenseKey     string `json:"license_key,omitempty"`
	InvitationCode string `json:"invitation_code,omitempty"`
	TenantHint     string `json:"tenant_hint,omitempty"`
	Locale         string `json:"locale,omitempty"`
	AppVersion     string `json:"app_version,omitempty"`
}

type activationClaimRequest struct {
	ActivationTicket string `json:"activation_ticket"`
	ProductID        string `json:"product_id"`
}

type pendingSetup struct {
	BaseURL   string
	ClientID  string
	ProductID string
	Ticket    string
}

// Setup prepares an activation ticket for a subsequent Login call. It is
// safe to call with the same Client before redirecting to hosted login.
func (c *Client) Setup(ctx context.Context, options SetupOptions) (ActivationPreparation, error) {
	baseURL, err := normalizeHTTP(options.BaseURL, "base_url", options.AllowInsecureHTTPForDevelopment, false)
	if err != nil {
		return ActivationPreparation{}, err
	}
	clientID := strings.TrimSpace(options.ClientID)
	productID := strings.TrimSpace(options.ProductID)
	if clientID == "" || productID == "" {
		return ActivationPreparation{}, &Error{Status: 0, Code: "invalid_request", Description: "client_id and product_id are required"}
	}
	if (strings.TrimSpace(options.LicenseKey) == "") == (strings.TrimSpace(options.InvitationCode) == "") {
		return ActivationPreparation{}, &Error{Status: 0, Code: "invalid_request", Description: "exactly one of license_key or invitation_code is required"}
	}
	c.ensure()
	c.configureSession(baseURL, clientID)
	request := activationPrepareRequest{
		ClientID: clientID, ProductID: productID, LicenseKey: options.LicenseKey,
		InvitationCode: options.InvitationCode, TenantHint: options.TenantHint,
		Locale: options.Locale, AppVersion: options.AppVersion,
	}
	var preparation ActivationPreparation
	if err := c.requestJSON(ctx, http.MethodPost, baseURL+activationPreparePath, request, "", &preparation); err != nil {
		return ActivationPreparation{}, err
	}
	if strings.TrimSpace(preparation.ActivationTicket) == "" || preparation.ProductID != productID {
		return ActivationPreparation{}, &Error{Status: 0, Code: "invalid_response", Description: "activation endpoint returned an invalid ticket"}
	}
	c.pending = &pendingSetup{BaseURL: baseURL, ClientID: clientID, ProductID: productID, Ticket: preparation.ActivationTicket}
	return preparation, nil
}

// GetAccountContext returns the server-derived account context for a product.
func (c *Client) GetAccountContext(ctx context.Context, productID string) (AccountContext, error) {
	if c.tokens == nil || strings.TrimSpace(c.tokens.AccessToken) == "" {
		return AccountContext{}, &Error{Status: http.StatusUnauthorized, Code: "login_required", Description: "login is required"}
	}
	if strings.TrimSpace(c.baseURL) == "" || strings.TrimSpace(productID) == "" {
		return AccountContext{}, &Error{Status: 0, Code: "invalid_request", Description: "product_id is required"}
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + accountContextPath
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return AccountContext{}, err
	}
	query := parsed.Query()
	query.Set("product_id", productID)
	parsed.RawQuery = query.Encode()
	var response activationContextResponse
	if err := c.requestJSON(ctx, http.MethodGet, parsed.String(), nil, c.tokens.AccessToken, &response); err != nil {
		return AccountContext{}, err
	}
	c.context = &response.Context
	return response.Context, nil
}

func (c *Client) configureSession(baseURL, clientID string) {
	if c.baseURL == baseURL && c.clientID == clientID {
		return
	}
	c.tokens, c.pending, c.context = nil, nil, nil
	c.baseURL, c.clientID = baseURL, clientID
}

func (c *Client) claimPending(ctx context.Context, config loginConfig) error {
	if c.pending == nil {
		return nil
	}
	if c.pending.BaseURL != config.baseURL || c.pending.ClientID != config.clientID {
		c.pending = nil
		return nil
	}
	return c.claimActivation(ctx, config.baseURL, config.clientID, c.pending.Ticket, c.pending.ProductID)
}

func (c *Client) claimActivation(ctx context.Context, baseURL, clientID, ticket, productID string) error {
	if c.tokens == nil || strings.TrimSpace(c.tokens.AccessToken) == "" {
		return &Error{Status: http.StatusUnauthorized, Code: "login_required", Description: "login is required"}
	}
	var response activationContextResponse
	err := c.requestJSON(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+activationClaimPath, activationClaimRequest{
		ActivationTicket: ticket, ProductID: productID,
	}, c.tokens.AccessToken, &response)
	if err != nil {
		return err
	}
	c.context = &response.Context
	if c.pending != nil && c.pending.Ticket == ticket && c.pending.ClientID == clientID {
		c.pending = nil
	}
	return nil
}

func (c *Client) requestJSON(ctx context.Context, method, endpoint string, body any, bearer string, target any) error {
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Pragma", "no-cache")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return decodeError(resp)
	}
	if target == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode snaplink response: %w", err)
	}
	return nil
}
