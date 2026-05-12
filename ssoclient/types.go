package ssoclient

import (
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/permissions"
)

// Re-export the SDK's domain types so App code and local/remote
// implementations share a single vocabulary. Type aliases (=) preserve
// identity, so a value built by ssoclient/local can be passed wherever the
// underlying SDK type is expected.
type (
	Permission = permissions.Permission
	Role       = permissions.Role
	MenuItem   = permissions.MenuItem
	MenuTree   = permissions.MenuTree
	Button     = permissions.Button
	Event      = audit.Event
	EventType  = audit.EventType
	Outcome    = audit.Outcome
)

// Subject is the authenticated identity returned by ValidateToken. It is a
// dedicated client-facing type (not aliased from sso.Subject) so it can
// carry both standard claims (Sub, Aud) and propagation metadata (Scopes,
// ExpiresAt) without leaking server-side internals.
type Subject struct {
	ID        string            // "sub" claim
	Audience  []string          // "aud" claim — typically a Client.ID
	Scopes    []string          // OAuth-style scopes
	ExpiresAt int64             // unix seconds; 0 if not set
	Attrs     map[string]string // extra claims (email, etc.)
}

// CheckRequest is the input to AuthzClient.Check. Permission follows the
// "<domain>:<action>" convention with "*" and "<domain>:*" wildcards.
type CheckRequest struct {
	SubjectID  string
	ClientID   string
	Permission string
}

// LogoutRequest is the input to AuthClient.Logout. Either SessionID or
// AccessToken (or both) must be set.
type LogoutRequest struct {
	SessionID   string
	AccessToken string
}
