package snaplink

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This file is the explicit session lifecycle: refresh, logout, and the
// predicates around them.
//
// Refresh is an explicit call rather than something that happens behind the
// scenes. An implicit renewal makes "which request fired, and when"
// unobservable, which costs both test determinism and debuggability, so a
// caller renews when it decides to. Every SDK in the registry exposes the same
// three operations with the same meaning:
//
//   - Refresh renews the access token and rotates the refresh token.
//   - Logout revokes server-side state and then drops local state.
//   - Clear drops local state only, without pretending the server session ended.
//
// Logout and Clear are deliberately distinct. A caller must be able to forget a
// token locally without claiming the server session is gone, and must be able
// to end the server session without pretending it did not have a local copy.

// ExpiresAt returns when the current access token expires, relative to when it
// was issued. It is zero when no access token is held.
//
// The absolute deadline is issued-at plus ExpiresIn, so a caller that stores
// the token can compare against its own clock rather than trusting the SDK's.
func (c *Client) ExpiresAt() time.Duration {
	if c.tokens == nil || c.tokens.ExpiresIn <= 0 {
		return 0
	}
	return time.Duration(c.tokens.ExpiresIn) * time.Second
}

// IsLoggedIn reports whether this client holds a usable access token.
//
// It performs no request: it answers whether a bearer exists, not whether the
// server still considers it valid.
func (c *Client) IsLoggedIn() bool {
	return c != nil && c.tokens != nil && c.tokens.AccessToken != ""
}

// CanRefresh reports whether a refresh token is held, which is the precondition
// for Refresh. A token without one cannot be renewed and must re-login.
func (c *Client) CanRefresh() bool {
	return c != nil && c.tokens != nil && c.tokens.RefreshToken != ""
}

// Refresh renews the access token using the refresh token grant.
//
// The server rotates refresh tokens, so the returned TokenResponse carries the
// replacement and the client adopts it. A refresh never carries a code verifier.
//
// An expired, revoked, or reused refresh token fails with the server's
// invalid_grant; the caller should treat that as terminal for the session and
// log in again rather than retrying.
func (c *Client) Refresh(ctx context.Context) (TokenResponse, error) {
	if c == nil || c.tokens == nil || c.tokens.RefreshToken == "" {
		return TokenResponse{}, &Error{Status: 0, Code: "login_required", Description: "no refresh token is held"}
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {c.clientID},
		"refresh_token": {c.tokens.RefreshToken},
	}
	tokens, err := c.postToken(ctx, form)
	if err != nil {
		return TokenResponse{}, err
	}
	// A server may omit the refresh token when it does not rotate. Adopt the
	// previous one rather than silently losing the ability to refresh again.
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = c.tokens.RefreshToken
	}
	c.tokens = &tokens
	return tokens, nil
}

// Logout revokes the server-side session and then clears local state.
//
// The server call is best-effort: the local session is cleared even when the
// network call fails, because a caller asking to log out must end up logged out
// locally regardless. The returned error reports the server outcome so a caller
// that needs to know can retry or report it.
func (c *Client) Logout(ctx context.Context) error {
	if c == nil || c.tokens == nil || c.tokens.AccessToken == "" {
		c.Clear()
		return nil
	}
	err := c.postLogout(ctx, c.tokens.AccessToken)
	c.Clear()
	return err
}

// Clear removes the in-memory session without contacting the server.
//
// Use this when the local copy must be forgotten but the server session should
// survive, for example when handing a session to another process. Use Logout
// when the session should actually end.
func (c *Client) Clear() {
	if c == nil {
		return
	}
	c.tokens = nil
	c.context = nil
}

func (c *Client) postLogout(ctx context.Context, bearer string) error {
	endpoint := strings.TrimRight(c.baseURL, "/") + "/logout"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return decodeError(resp)
	}
	return nil
}
