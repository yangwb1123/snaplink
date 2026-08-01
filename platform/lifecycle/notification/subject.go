package notification

import (
	"context"
	"errors"
	"strings"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

// WithUserProvider enables asynchronous resolution of an account-lockout key
// back to its local user. The login path intentionally records the canonical
// lock key, not an unverified claimed subject, so this lookup belongs here.
func WithUserProvider(users core.UserProvider) Option {
	return func(r *Router) { r.users = users }
}

func (r *Router) eventSubject(ctx context.Context, event *audit.Event) string {
	for _, key := range []string{"subject_id", "user_id", "target_user_id"} {
		if value := event.Metadata[key]; value != "" {
			return value
		}
	}
	if target := event.Metadata["target_user"]; target != "" {
		if event.Type == audit.EventAdminAccountUnlocked {
			subject, err := r.resolveUserIdentity(ctx, "", target)
			if err != nil {
				r.log.Error("notification account-unlock subject resolution failed", "error", err)
			}
			return subject
		}
		return target
	}
	if event.Type != audit.EventAccountLocked {
		return event.ActorID
	}
	identity, encoded := lockIdentity(event)
	if !encoded {
		return event.ActorID
	}
	subject, err := r.resolveUserIdentity(ctx, event.Provider, identity)
	if err != nil {
		r.log.Error("notification account-lock subject resolution failed", "provider", event.Provider, "error", err)
	}
	return subject
}

func lockIdentity(event *audit.Event) (string, bool) {
	if event.ClientID == "" {
		return "", false
	}
	prefix := event.ClientID + ":"
	if !strings.HasPrefix(event.ActorID, prefix) {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(event.ActorID, prefix)), true
}

func (r *Router) resolveUserIdentity(ctx context.Context, provider, identity string) (string, error) {
	if r.users == nil || identity == "" {
		return "", nil
	}
	if user, err := r.users.GetByID(ctx, identity); err == nil && user != nil {
		return user.ID, nil
	} else if err != nil && !errors.Is(err, core.ErrNoSuchUser) {
		return "", err
	}
	if user, err := indexedIdentityLookup(ctx, r.users, provider, identity); user != nil {
		return user.ID, nil
	} else if err != nil && !errors.Is(err, core.ErrNoSuchUser) {
		return "", err
	}
	users, err := r.users.List(ctx)
	if err != nil {
		return "", err
	}
	return uniqueIdentityMatch(users, provider, identity), nil
}

func indexedIdentityLookup(ctx context.Context, users core.UserProvider, provider, identity string) (*core.User, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "email", "magic_link":
		if lookup, ok := users.(core.UserByEmailProvider); ok {
			return lookup.GetByEmail(ctx, identity)
		}
	case "password":
		if lookup, ok := users.(core.UserByUsernameProvider); ok {
			return lookup.GetByUsername(ctx, identity)
		}
	}
	return nil, core.ErrNoSuchUser
}

func uniqueIdentityMatch(users []*core.User, provider, identity string) string {
	match := ""
	for _, user := range users {
		if user == nil || !userMatchesIdentity(user, provider, identity) {
			continue
		}
		if match != "" && match != user.ID {
			return ""
		}
		match = user.ID
	}
	return match
}

func userMatchesIdentity(user *core.User, provider, identity string) bool {
	equal := func(value string) bool { return strings.EqualFold(strings.TrimSpace(value), identity) }
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "password":
		return equal(user.ID) || equal(user.Username) || equal(user.Attributes["username"])
	case "email", "magic_link":
		return equal(user.Email) || equal(user.Attributes["email"])
	case "phone":
		return equal(user.Attributes["phone"])
	default:
		return equal(user.ID) || equal(user.Username) || equal(user.Email) || equal(user.ExternalID) ||
			equal(user.Attributes["username"]) || equal(user.Attributes["email"]) || equal(user.Attributes["phone"])
	}
}
