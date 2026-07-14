package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
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

// registrationExtensions builds the BeginRegistration extensions map from
// the Helper's opt-in Config flags. Returns nil (not merely empty) when
// neither flag is set, so BeginRegistration's `len(ext) > 0` guard adds no
// option — byte-identical wire to a pre-extension build.
func registrationExtensions(h *Helper) protocol.AuthenticationExtensions {
	var ext protocol.AuthenticationExtensions
	if h.requestCredProps {
		ext = protocol.AuthenticationExtensions{extensionCredProps: true}
	}
	if h.requestLargeBlobSupport {
		if ext == nil {
			ext = protocol.AuthenticationExtensions{}
		}
		ext[extensionLargeBlob] = map[string]any{"support": "preferred"}
	}
	return ext
}

// extensionsFromCreation maps go-webauthn's raw clientExtensionResults (a
// generic map[string]any — the library has no typed credProps/largeBlob
// support as of v0.17.x) to this package's typed, nil-means-unknown
// [CredentialExtensions]. A missing or malformed entry leaves the
// corresponding field nil rather than false.
func extensionsFromCreation(results protocol.AuthenticationExtensionsClientOutputs) CredentialExtensions {
	var out CredentialExtensions
	if m, ok := results[extensionCredProps].(map[string]any); ok {
		if rk, ok := m["rk"].(bool); ok {
			out.Discoverable = &rk
		}
	}
	if m, ok := results[extensionLargeBlob].(map[string]any); ok {
		if supported, ok := m["supported"].(bool); ok {
			out.LargeBlobSupported = &supported
		}
	}
	return out
}

// persistCredentialExtensions best-effort persists ext against credentialID
// when the configured UserStore opts into [credentialExtensionSetter] AND
// there is anything captured. A store that doesn't implement it — or an ext
// with everything nil (extension not requested / not echoed) — is a silent
// no-op: this is enrichment metadata, never a ceremony decision, so it fails
// open (cf. AGENTS.md Fail Modes).
func (h *Helper) persistCredentialExtensions(ctx context.Context, name string, credentialID []byte, ext CredentialExtensions) {
	if ext == (CredentialExtensions{}) {
		return
	}
	setter, ok := h.users.(credentialExtensionSetter)
	if !ok {
		return
	}
	_ = setter.SetCredentialExtensions(ctx, name, credentialID, ext)
}

// BeginLoginLargeBlob is [Helper.BeginLogin] plus a WebAuthn Level 3
// largeBlob extension request (§10.7) for the asserted credential. Neither
// req.Read nor req.Write set behaves exactly like BeginLogin — no
// extensions key, byte-identical. Pair with [Helper.FinishLoginLargeBlob].
//
// This is a documented CAPABILITY SEAM, not a built-in feature: no code in
// this repo currently reads or writes a largeBlob (mirrors the identitylink
// package's "extension point, not built in" convention) — a future
// recovery-key / key-escrow feature can consume it without further ceremony
// changes.
func (h *Helper) BeginLoginLargeBlob(ctx context.Context, name string, req LargeBlobRequest) (*protocol.CredentialAssertion, string, error) {
	if req.Read && req.Write != nil {
		return nil, "", errors.New("webauthn: largeBlob read and write are mutually exclusive")
	}
	var opts []gw.LoginOption
	switch {
	case req.Write != nil:
		opts = append(opts, gw.WithAssertionExtensions(protocol.AuthenticationExtensions{
			extensionLargeBlob: map[string]any{"write": protocol.URLEncodedBase64(req.Write)},
		}))
	case req.Read:
		opts = append(opts, gw.WithAssertionExtensions(protocol.AuthenticationExtensions{
			extensionLargeBlob: map[string]any{"read": true},
		}))
	}
	return h.beginLogin(ctx, name, h.requireUserVerification, opts...)
}

// FinishLoginLargeBlob is [Helper.FinishLogin] plus the largeBlob
// extension's client output, when a [Helper.BeginLoginLargeBlob] request
// was answered. Verification is IDENTICAL to FinishLogin (including the
// CloneWarning gate — see [ErrClonedAuthenticator]): this calls the same
// ParseCredentialRequestResponse + ValidateLogin pair go-webauthn's
// FinishLogin wraps, so clientExtensionResults survive past ValidateLogin
// for [extractLargeBlobResult]. The returned *LargeBlobResult has both
// fields nil when no extension was requested or the client omitted the
// output.
func (h *Helper) FinishLoginLargeBlob(ctx context.Context, sessionID string, r *http.Request) (*User, *gw.Credential, *LargeBlobResult, error) {
	session, err := h.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, nil, nil, err
	}
	user, err := h.userFromSession(ctx, session)
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn: finish login: %w", err)
	}
	cred, err := h.core.ValidateLogin(user, *session, parsed)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn: finish login: %w", err)
	}
	if cred.Authenticator.CloneWarning {
		return nil, nil, nil, ErrClonedAuthenticator
	}
	if err := h.users.UpdateCredential(ctx, user.Name, cred); err != nil {
		return nil, nil, nil, fmt.Errorf("webauthn: persist updated credential: %w", err)
	}
	return user, cred, extractLargeBlobResult(parsed.ClientExtensionResults), nil
}

// extractLargeBlobResult maps the raw largeBlob clientExtensionResults entry
// to a typed [LargeBlobResult]. Returns nil (not a zero-value struct) when
// the response carries no largeBlob entry at all, so the caller can tell
// "extension not requested/honored" apart from "honored but empty".
func extractLargeBlobResult(results protocol.AuthenticationExtensionsClientOutputs) *LargeBlobResult {
	m, ok := results[extensionLargeBlob].(map[string]any)
	if !ok {
		return nil
	}
	out := &LargeBlobResult{}
	if blobB64, ok := m["blob"].(string); ok {
		if raw, err := base64.RawURLEncoding.DecodeString(blobB64); err == nil {
			out.Read = raw
		}
	}
	if written, ok := m["written"].(bool); ok {
		out.Written = &written
	}
	return out
}
