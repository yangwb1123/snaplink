package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

func (h *Helper) persistSession(ctx context.Context, session *gw.SessionData) (string, error) {
	id, err := newSessionID()
	if err != nil {
		return "", fmt.Errorf("webauthn: random session id: %w", err)
	}
	if err := h.sessions.Put(ctx, id, session, h.sessionTTL); err != nil {
		return "", fmt.Errorf("webauthn: persist session: %w", err)
	}
	return id, nil
}

func (h *Helper) userFromSession(ctx context.Context, session *gw.SessionData) (*User, error) {
	user, err := h.users.GetByName(ctx, string(session.UserID))
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, ErrUserUnknown) {
		return nil, err
	}
	// Fallback: the user ID inside the session is the raw user
	// handle. Walk every stored user looking for the matching
	// handle. Most stores would index by handle directly; this
	// fallback exists for the minimal MemoryUserStore.
	if walker, ok := h.users.(handleResolver); ok {
		return walker.GetByHandle(ctx, session.UserID)
	}
	return nil, err
}

type handleResolver interface {
	GetByHandle(ctx context.Context, handle []byte) (*User, error)
}

func newSessionID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
