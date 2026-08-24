package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	opSessionProvider = "op-session"
	opSessionCookie   = "snaplink_op_session"
	opSessionTTL      = 8 * time.Hour
)

var errInvalidOPSession = errors.New("op session invalid")

// OpSessionGate is the edition's browser-side handle on the CANONICAL
// session lifecycle: the OP-session cookie IS the canonical session ID,
// and every create/resolve/destroy goes through the server's
// SessionManager (wired via WithSessionManager). There is no parallel
// session state here — the session record, its sid in the auth code and
// the id_token sid claim all come from the canonical store. The gate only
// exists because the manager is constructed inside sso.NewServer, so the
// middleware/authenticator capture it via SetMgr right after.
type OpSessionGate struct {
	mu  sync.RWMutex
	mgr core.SessionManager
}

func NewOPSessionGate() *OpSessionGate {
	return &OpSessionGate{}
}

// SetMgr wires the canonical SessionManager once the server is built.
func (g *OpSessionGate) SetMgr(mgr core.SessionManager) {
	g.mu.Lock()
	g.mgr = mgr
	g.mu.Unlock()
}

// Manager returns the wired canonical SessionManager (nil before the server
// is built).
func (g *OpSessionGate) Manager() core.SessionManager {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.mgr
}

// resolve returns the live (unrevoked, unexpired) session for the cookie
// token, or nil. A dead session is dropped from the manager's view and
// reports nil so a stale cookie behaves exactly like no cookie (the login
// falls back to visible authentication — never an oracle about why).
func (g *OpSessionGate) resolve(ctx context.Context, token string) *core.Session {
	if token == "" {
		return nil
	}
	mgr := g.Manager()
	if mgr == nil {
		return nil
	}
	sess, err := mgr.Get(ctx, token)
	if err != nil || sess == nil || sess.Revoked || sess.IsExpired() {
		return nil
	}
	return sess
}

// destroy terminates the canonical session behind the cookie. Logout must
// end the session at the OP, not just drop the browser cookie — the sid
// bound into outstanding refresh tokens dies with it (refresh rotation
// refuses dead sessions).
func (g *OpSessionGate) destroy(ctx context.Context, token string) {
	if token == "" {
		return
	}
	if mgr := g.Manager(); mgr != nil {
		_ = mgr.Destroy(ctx, token)
	}
}

type opSessionAuthenticator struct {
	gate *OpSessionGate
	user UserSeed
}

func newOPSessionAuthenticator(gate *OpSessionGate, user UserSeed) sso.Authenticator {
	return &opSessionAuthenticator{gate: gate, user: user}
}

func (a *opSessionAuthenticator) Name() string { return opSessionProvider }

func (a *opSessionAuthenticator) Authenticate(
	ctx context.Context,
	req *sso.AuthRequest,
) (*sso.AuthResult, error) {
	session := a.gate.resolve(ctx, req.Credential["session"])
	if session == nil {
		return nil, errInvalidOPSession
	}
	if session.UserID != a.user.ID {
		return nil, errInvalidOPSession
	}
	return &sso.AuthResult{
		UserID:      a.user.ID,
		ExternalID:  a.user.Username,
		Provider:    opSessionProvider,
		AuthMethods: []string{"sso"},
		AuthTime:    session.CreatedAt,
		Attributes:  userClaims(a.user),
		SessionID:   session.ID,
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
	next   http.Handler
	gate   *OpSessionGate
	secure bool
}

func newOPSessionHandler(next http.Handler, gate *OpSessionGate, issuer string) http.Handler {
	parsed, _ := url.Parse(issuer)
	return &opSessionHandler{
		next:   next,
		gate:   gate,
		secure: parsed != nil && parsed.Scheme == "https",
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
	session := h.gate.resolve(r.Context(), cookieToken)
	if shouldResume(payload, session, cookieToken) {
		payload["provider"] = opSessionProvider
		payload["credential"] = map[string]string{"session": cookieToken}
		normalizeSessionPrompt(payload)
		raw, _ = json.Marshal(payload)
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	response := newBufferedResponse()
	h.next.ServeHTTP(response, r)
	if successfulPasswordCode(payload, response.body.Bytes()) {
		h.setFreshSession(response, response.body.Bytes())
	}
	response.flushTo(w)
}

func readLoginPayload(r *http.Request) (map[string]any, []byte, bool) {
	if r.ContentLength < 0 || r.ContentLength > MaxBodyBytes {
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

func shouldResume(payload map[string]any, session *core.Session, cookieToken string) bool {
	if session == nil || cookieToken == "" {
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

func sessionWithinMaxAge(payload map[string]any, session *core.Session) bool {
	raw, set := payload["max_age"]
	if !set {
		return true
	}
	seconds, ok := raw.(float64)
	if !ok || seconds <= 0 {
		return false
	}
	return time.Since(session.CreatedAt) <= time.Duration(seconds)*time.Second
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

// setFreshSession binds the browser cookie to the canonical session the
// login just created: the code-flow response carries session_id (the same
// canonical ID that rides the auth code into the id_token sid claim). If
// the server returned no session_id (no SessionManager, or creation
// failed), no cookie is set and the next login re-authenticates — the
// wire login itself already succeeded, so this is strictly best-effort.
func (h *opSessionHandler) setFreshSession(w http.ResponseWriter, response []byte) {
	body := map[string]any{}
	if json.Unmarshal(response, &body) != nil {
		return
	}
	sessionID, _ := body["session_id"].(string)
	if sessionID == "" {
		return
	}
	http.SetCookie(w, h.cookie(sessionID, int(opSessionTTL.Seconds())))
}

func (h *opSessionHandler) clearSession(w http.ResponseWriter, r *http.Request) {
	token := sessionCookieToken(r)
	h.gate.destroy(r.Context(), token)
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
