package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

const (
	opSessionProvider = "op-session"
	opSessionCookie   = "snaplink_op_session"
	opSessionTTL      = 8 * time.Hour
	opSessionBytes    = 32
)

var errInvalidOPSession = errors.New("op session invalid")

type opSessionStore struct {
	mu       sync.Mutex
	sessions map[[sha256.Size]byte]opSession
	user     userSeed
}

type opSession struct {
	authenticatedAt time.Time
	expiresAt       time.Time
}

func newOPSessionStore(user userSeed) *opSessionStore {
	return &opSessionStore{
		sessions: make(map[[sha256.Size]byte]opSession),
		user:     user,
	}
}

func (s *opSessionStore) create() (string, error) {
	raw := make([]byte, opSessionBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	s.mu.Lock()
	s.sessions[sha256.Sum256([]byte(token))] = opSession{
		authenticatedAt: now,
		expiresAt:       now.Add(opSessionTTL),
	}
	s.mu.Unlock()
	return token, nil
}

func (s *opSessionStore) resolve(token string) (opSession, bool) {
	if token == "" {
		return opSession{}, false
	}
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[key]
	if ok && time.Now().Before(session.expiresAt) {
		return session, true
	}
	delete(s.sessions, key)
	return opSession{}, false
}

func (s *opSessionStore) delete(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, sha256.Sum256([]byte(token)))
	s.mu.Unlock()
}

type opSessionAuthenticator struct {
	sessions *opSessionStore
}

func newOPSessionAuthenticator(sessions *opSessionStore) sso.Authenticator {
	return &opSessionAuthenticator{sessions: sessions}
}

func (a *opSessionAuthenticator) Name() string { return opSessionProvider }

func (a *opSessionAuthenticator) Authenticate(
	_ context.Context,
	req *sso.AuthRequest,
) (*sso.AuthResult, error) {
	session, ok := a.sessions.resolve(req.Credential["token"])
	if !ok {
		return nil, errInvalidOPSession
	}
	user := a.sessions.user
	return &sso.AuthResult{
		UserID:      user.ID,
		ExternalID:  user.Username,
		Provider:    opSessionProvider,
		AuthMethods: []string{"sso"},
		AuthTime:    session.authenticatedAt,
		Attributes:  userClaims(user),
	}, nil
}

func (a *opSessionAuthenticator) Callback(
	context.Context,
	*sso.CallbackState,
) (*sso.AuthResult, error) {
	return nil, errInvalidOPSession
}

func (a *opSessionAuthenticator) LoginURL(string) string { return "" }

type opSessionHandler struct {
	next     http.Handler
	sessions *opSessionStore
	secure   bool
}

func newOPSessionHandler(next http.Handler, sessions *opSessionStore, issuer string) http.Handler {
	parsed, _ := url.Parse(issuer)
	return &opSessionHandler{
		next:     next,
		sessions: sessions,
		secure:   parsed != nil && parsed.Scheme == "https",
	}
}

func (h *opSessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isLogoutRequest(r) {
		h.clearSession(w, r)
		h.next.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != sso.PathLogin {
		h.next.ServeHTTP(w, r)
		return
	}
	h.serveLogin(w, r)
}

func (h *opSessionHandler) serveLogin(w http.ResponseWriter, r *http.Request) {
	payload, raw, ok := readLoginPayload(r)
	if !ok {
		h.next.ServeHTTP(w, r)
		return
	}
	cookieToken := sessionCookieToken(r)
	session, active := h.sessions.resolve(cookieToken)
	if shouldResume(payload, session, active) {
		payload["provider"] = opSessionProvider
		payload["credential"] = map[string]string{"token": cookieToken}
		normalizeSessionPrompt(payload)
		raw, _ = json.Marshal(payload)
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	response := newBufferedResponse()
	h.next.ServeHTTP(response, r)
	if successfulPasswordCode(payload, response.body.Bytes()) {
		h.setFreshSession(response)
	}
	response.flushTo(w)
}

func readLoginPayload(r *http.Request) (map[string]any, []byte, bool) {
	if r.ContentLength < 0 || r.ContentLength > maxBodyBytes {
		return nil, nil, false
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	payload := map[string]any{}
	if json.Unmarshal(raw, &payload) != nil {
		return nil, raw, false
	}
	return payload, raw, true
}

func shouldResume(payload map[string]any, session opSession, active bool) bool {
	if !active {
		return false
	}
	if _, hasCredential := payload["credential"]; hasCredential {
		return false
	}
	prompt, _ := payload["prompt"].(string)
	prompts := strings.Fields(prompt)
	for _, value := range prompts {
		if value == "login" {
			return false
		}
	}
	if contains(prompts, "none") && len(prompts) != 1 {
		return false
	}
	responseType, _ := payload["response_type"].(string)
	return responseType == "code" && sessionWithinMaxAge(payload, session)
}

func sessionWithinMaxAge(payload map[string]any, session opSession) bool {
	raw, set := payload["max_age"]
	if !set {
		return true
	}
	seconds, ok := raw.(float64)
	if !ok || seconds <= 0 {
		return false
	}
	return time.Since(session.authenticatedAt) <= time.Duration(seconds)*time.Second
}

func normalizeSessionPrompt(payload map[string]any) {
	if prompt, _ := payload["prompt"].(string); prompt == "none" {
		delete(payload, "prompt")
	}
}

func successfulPasswordCode(payload map[string]any, response []byte) bool {
	provider, _ := payload["provider"].(string)
	if provider != "password" {
		return false
	}
	body := map[string]any{}
	if json.Unmarshal(response, &body) != nil {
		return false
	}
	code, _ := body["code"].(string)
	return code != ""
}

func (h *opSessionHandler) setFreshSession(w http.ResponseWriter) {
	token, err := h.sessions.create()
	if err != nil {
		return
	}
	http.SetCookie(w, h.cookie(token, int(opSessionTTL.Seconds())))
}

func (h *opSessionHandler) clearSession(w http.ResponseWriter, r *http.Request) {
	h.sessions.delete(sessionCookieToken(r))
	http.SetCookie(w, h.cookie("", -1))
}

func (h *opSessionHandler) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     opSessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func sessionCookieToken(r *http.Request) string {
	cookie, err := r.Cookie(opSessionCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func isLogoutRequest(r *http.Request) bool {
	return r.URL.Path == sso.PathLogout || r.URL.Path == sso.PathEndSession
}

type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header), status: http.StatusOK}
}

func (w *bufferedResponse) Header() http.Header { return w.header }

func (w *bufferedResponse) WriteHeader(status int) {
	if w.status == http.StatusOK {
		w.status = status
	}
}

func (w *bufferedResponse) Write(p []byte) (int, error) {
	return w.body.Write(p)
}

func (w *bufferedResponse) flushTo(dst http.ResponseWriter) {
	for key, values := range w.header {
		dst.Header()[key] = append([]string(nil), values...)
	}
	dst.WriteHeader(w.status)
	_, _ = dst.Write(w.body.Bytes())
}
