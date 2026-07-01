// Package apiclient provides a lightweight HTTP client for the SSO admin API
// (gRPC gateway JSON REST endpoints). Used by sso-ctl subcommands to talk to
// a running server's admin bindings.
//
// Authentication is via the `Authorization: Bearer <token>` header. The caller
// sets the token via [WithToken] on construction or by setting an env var.
//
// All methods return the full HTTP response; the caller inspects the status
// code and decodes the body.
package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultAddr is the default admin API base URL.
const DefaultAddr = "http://127.0.0.1:8443"

// EnvAddr is the env var that overrides the admin API base URL.
const EnvAddr = "SSO_ADMIN_ADDR"

// EnvToken is the env var that supplies the admin bearer token.
const EnvToken = "SSO_ADMIN_TOKEN"

// Client is a lightweight admin API client.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New returns a new admin API client. The token is loaded from:
//  1. The WithToken option
//  2. The SSO_ADMIN_TOKEN env var
//
// The base URL is loaded from:
//  1. The WithAddr option
//  2. The SSO_ADMIN_ADDR env var
//  3. DefaultAddr
func New(opts ...Option) *Client {
	c := &Client{
		baseURL: DefaultAddr,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, o := range opts {
		o(c)
	}
	if c.token == "" {
		c.token = os.Getenv(EnvToken)
	}
	if addr := os.Getenv(EnvAddr); addr != "" {
		c.baseURL = addr
	}
	return c
}

// Option configures a Client.
type Option func(*Client)

// WithToken sets the bearer token for admin API auth.
func WithToken(token string) Option {
	return func(c *Client) { c.token = token }
}

// WithAddr sets the admin API base URL.
func WithAddr(addr string) Option {
	return func(c *Client) { c.baseURL = addr }
}

// Do sends an authenticated HTTP request and returns the response.
// The caller must close resp.Body.
func (c *Client) Do(method, path string, body any) (*http.Response, error) {
	url := c.baseURL + path

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	return resp, nil
}

// Get is a convenience wrapper for GET requests.
func (c *Client) Get(path string) (*http.Response, error) {
	return c.Do(http.MethodGet, path, nil)
}

// Post is a convenience wrapper for POST requests.
func (c *Client) Post(path string, body any) (*http.Response, error) {
	return c.Do(http.MethodPost, path, body)
}

// Delete is a convenience wrapper for DELETE requests.
func (c *Client) Delete(path string) (*http.Response, error) {
	return c.Do(http.MethodDelete, path, nil)
}

// Patch is a convenience wrapper for PATCH requests.
func (c *Client) Patch(path string, body any) (*http.Response, error) {
	return c.Do(http.MethodPatch, path, body)
}

// ReadBody reads and returns the response body as a byte slice. Closes resp.Body.
func ReadBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return b, nil
}

// WriteJSON outputs a formatted JSON response to stdout.
func WriteJSON(data any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// WriteTable outputs a simple aligned table to stdout.
func WriteTable(header []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Println("(none)")
		return
	}
	// Compute column widths
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	// Print header
	for i, h := range header {
		fmt.Printf(" %-*s ", widths[i], h)
	}
	fmt.Println()
	for i := range header {
		fmt.Printf(" %s ", dashes(widths[i]))
	}
	fmt.Println()
	// Print rows
	for _, row := range rows {
		for i, cell := range row {
			fmt.Printf(" %-*s ", widths[i], cell)
		}
		fmt.Println()
	}
}

func dashes(n int) string {
	return strings.Repeat("-", n)
}
