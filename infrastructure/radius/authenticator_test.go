package radiusauth

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
)

// newTestAuth builds an Authenticator wired to a fake Exchanger. cfg supplies
// only the operator-facing fields; a shared secret + one server satisfy Validate
// without any network I/O (the fake Exchanger replaces the real transport).
func newTestAuth(t *testing.T, fake *fakeExchanger, cfg Config) *Authenticator {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "test-radius"
	}
	if len(cfg.Servers) == 0 {
		cfg.Servers = []string{"radius.example.com:1812"}
	}
	if cfg.SharedSecret == "" {
		cfg.SharedSecret = "test-secret"
	}
	a, err := New(cfg, WithExchanger(fake))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func authReq(username, password string) *sso.AuthRequest {
	return &sso.AuthRequest{Credential: map[string]string{"username": username, "password": password}}
}

// --- Happy path: Access-Accept => a Subject is minted ----------------------

func TestAuthenticate_AccessAccept_MintsSubject(t *testing.T) {
	t.Parallel()
	fake := &fakeExchanger{accept: true}
	a := newTestAuth(t, fake, Config{})

	res, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.ExternalID != "alice" {
		t.Errorf("ExternalID = %q, want alice", res.ExternalID)
	}
	if res.Provider != "test-radius" {
		t.Errorf("Provider = %q, want test-radius", res.Provider)
	}
	if len(res.AuthMethods) != 1 || res.AuthMethods[0] != AuthMethodRADIUS {
		t.Errorf("AuthMethods = %v, want [%s]", res.AuthMethods, AuthMethodRADIUS)
	}

	// The exchange must have received the real credentials.
	calls := fake.recorded()
	if len(calls) != 1 {
		t.Fatalf("got %d exchange calls, want 1", len(calls))
	}
	if calls[0].username != "alice" || calls[0].password != "s3cret" {
		t.Errorf("exchange got (%q,%q), want (alice,s3cret)", calls[0].username, calls[0].password)
	}
}

// --- Reply-attribute mapping (Filter-Id / Class -> Subject attrs) ----------

func TestAuthenticate_AccessAccept_MapsReplyAttributes(t *testing.T) {
	t.Parallel()
	fake := &fakeExchanger{
		accept: true,
		// The exchanger has already projected the configured RADIUS reply
		// attributes onto local keys (see exchange.go); the authenticator just
		// carries them onto the AuthResult.
		attrs: map[string]string{
			"filter_id":    "Enterprise-VPN",
			"radius_class": "cG9saWN5LTQy",
		},
	}
	a := newTestAuth(t, fake, Config{})

	res, err := a.Authenticate(context.Background(), authReq("bob", "pw"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.Attributes["filter_id"] != "Enterprise-VPN" {
		t.Errorf("filter_id = %q, want Enterprise-VPN", res.Attributes["filter_id"])
	}
	if res.Attributes["radius_class"] != "cG9saWN5LTQy" {
		t.Errorf("radius_class = %q, want the Class value", res.Attributes["radius_class"])
	}
}

// --- Access-Reject: unknown-user and wrong-password are the SAME error ------

func TestAuthenticate_AccessReject_WrongPassword_ErrAuthFailed(t *testing.T) {
	t.Parallel()
	fake := &fakeExchanger{accept: false} // clean Reject, err == nil
	a := newTestAuth(t, fake, Config{})

	_, err := a.Authenticate(context.Background(), authReq("alice", "WRONG"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("wrong password err = %v, want ErrAuthFailed", err)
	}
}

// THE anti-enumeration contract: a RADIUS server returns Access-Reject for an
// unknown user AND a wrong password. Both MUST surface as the IDENTICAL wire
// error — no probe can tell "no such user" from "wrong password".
func TestAuthenticate_AccessReject_UnknownUser_SameErrorAsWrongPassword(t *testing.T) {
	t.Parallel()
	// Same fake (clean Reject) models both: the server gives Reject regardless of
	// whether the account exists.
	fakeWrong := &fakeExchanger{accept: false}
	fakeUnknown := &fakeExchanger{accept: false}
	aWrong := newTestAuth(t, fakeWrong, Config{})
	aUnknown := newTestAuth(t, fakeUnknown, Config{})

	_, wrongErr := aWrong.Authenticate(context.Background(), authReq("alice", "WRONG"))
	_, unknownErr := aUnknown.Authenticate(context.Background(), authReq("nobody", "whatever"))

	if !errors.Is(wrongErr, ErrAuthFailed) {
		t.Fatalf("wrong-password err = %v, want ErrAuthFailed", wrongErr)
	}
	if !errors.Is(unknownErr, ErrAuthFailed) {
		t.Fatalf("unknown-user err = %v, want ErrAuthFailed", unknownErr)
	}
	if wrongErr.Error() != unknownErr.Error() {
		t.Errorf("wrong-password err %q != unknown-user err %q (enumeration oracle)", wrongErr, unknownErr)
	}
}

// --- Transport / server-down: a DISTINCT error, no existence leak ----------

func TestAuthenticate_TransportError_ErrServerUnavailable(t *testing.T) {
	t.Parallel()
	fake := &fakeExchanger{err: errors.New("dial udp radius.example.com:1812: i/o timeout")}
	a := newTestAuth(t, fake, Config{})

	_, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if !errors.Is(err, ErrServerUnavailable) {
		t.Fatalf("transport err = %v, want ErrServerUnavailable", err)
	}
	// And it must NOT be confused with an auth failure (distinct error classes).
	if errors.Is(err, ErrAuthFailed) {
		t.Error("transport failure leaked as ErrAuthFailed — must be the distinct ErrServerUnavailable")
	}
	// The raw transport reason must NOT escape onto the wire error (no detail /
	// enumeration leak); only the generic sentinel surfaces.
	if err.Error() != ErrServerUnavailable.Error() {
		t.Errorf("server-unavailable err = %q, want the bare generic %q (no detail leak)", err, ErrServerUnavailable)
	}
}

// A non-authentic (forged) response also arrives as an exchange error and must
// map to ErrServerUnavailable, NEVER to a false-positive accept.
func TestAuthenticate_NonAuthenticResponse_ErrServerUnavailable(t *testing.T) {
	t.Parallel()
	fake := &fakeExchanger{err: errors.New("radius: non-authentic response")}
	a := newTestAuth(t, fake, Config{})

	_, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if !errors.Is(err, ErrServerUnavailable) {
		t.Fatalf("forged-response err = %v, want ErrServerUnavailable (never a login)", err)
	}
}

// --- Empty password: rejected BEFORE any exchange (no anonymous bypass) -----

func TestAuthenticate_EmptyPassword_RejectedPreExchange(t *testing.T) {
	t.Parallel()
	fake := &fakeExchanger{accept: true} // would ACCEPT if ever called
	a := newTestAuth(t, fake, Config{})

	_, err := a.Authenticate(context.Background(), authReq("alice", ""))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("empty-password err = %v, want ErrAuthFailed", err)
	}
	// CRITICAL: the exchange must NEVER have run — an empty password must not
	// reach the server (a permissive policy could otherwise treat it as a bypass).
	if calls := fake.recorded(); len(calls) != 0 {
		t.Errorf("empty password triggered %d exchange(s): %v, want 0 (must be rejected pre-exchange)", len(calls), calls)
	}
}

func TestAuthenticate_EmptyUsername_RejectedPreExchange(t *testing.T) {
	t.Parallel()
	fake := &fakeExchanger{accept: true}
	a := newTestAuth(t, fake, Config{})

	_, err := a.Authenticate(context.Background(), authReq("", "s3cret"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("empty-username err = %v, want ErrAuthFailed", err)
	}
	if calls := fake.recorded(); len(calls) != 0 {
		t.Errorf("empty username triggered %d exchange(s), want 0", len(calls))
	}
}

// --- Interface conformance + the non-credential surface --------------------

func TestAuthenticator_LoginURL_Empty(t *testing.T) {
	t.Parallel()
	a := newTestAuth(t, &fakeExchanger{}, Config{})
	if got := a.LoginURL("state"); got != "" {
		t.Errorf("LoginURL = %q, want empty (direct credential auth)", got)
	}
}

func TestAuthenticator_Callback_NotApplicable(t *testing.T) {
	t.Parallel()
	a := newTestAuth(t, &fakeExchanger{}, Config{})
	_, err := a.Callback(context.Background(), &sso.CallbackState{})
	if !errors.Is(err, ErrCallbackNotApplicable) {
		t.Errorf("Callback err = %v, want ErrCallbackNotApplicable", err)
	}
}

func TestAuthenticator_Name(t *testing.T) {
	t.Parallel()
	a := newTestAuth(t, &fakeExchanger{}, Config{Name: "corp-nps"})
	if a.Name() != "corp-nps" {
		t.Errorf("Name = %q, want corp-nps", a.Name())
	}
}

// New surfaces a Validate error (boot fails closed) when the shared secret is
// missing — the security anchor must be present.
func TestNew_MissingSharedSecret_FailsClosed(t *testing.T) {
	t.Parallel()
	_, err := New(Config{Name: "x", Servers: []string{"h:1812"}})
	if err == nil {
		t.Fatal("New accepted a config with no shared secret — must fail closed")
	}
}

// --- Public WithExchanger seam (the CHAP-extensibility contract) ------------

// stubExchanger is a stand-in for an operator-supplied custom Exchanger (e.g. a
// CHAP implementation). It is deliberately SEPARATE from fakeExchanger and
// returns a sentinel attribute so the test can prove the verdict came from THIS
// injected exchanger and not the stock PAP one. It owns no real transport — it
// is just the narrow interface the module exposes.
type stubExchanger struct {
	called bool
}

func (s *stubExchanger) Exchange(_ context.Context, _, _ string) (bool, map[string]string, error) {
	s.called = true
	return true, map[string]string{"via": "custom-exchanger"}, nil
}

var _ Exchanger = (*stubExchanger)(nil)

// The PUBLIC WithExchanger option must actually replace the stock exchanger so
// Authenticate routes the verdict through the operator-supplied one. This is the
// reachability config.go's CHAP rejection promises: a custom Exchanger wired via
// the exported New(cfg, WithExchanger(...)) API is genuinely used.
func TestNew_WithExchanger_Public_IsUsedByAuthenticate(t *testing.T) {
	t.Parallel()
	stub := &stubExchanger{}
	a, err := New(Config{
		Name:         "corp-nps",
		Servers:      []string{"radius.example.com:1812"},
		SharedSecret: "test-secret",
	}, WithExchanger(stub))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !stub.called {
		t.Fatal("custom Exchanger supplied via public WithExchanger was NOT invoked — the seam is unreachable")
	}
	if res.Attributes["via"] != "custom-exchanger" {
		t.Errorf("verdict did not come from the injected exchanger: via = %q, want custom-exchanger", res.Attributes["via"])
	}
}

// A nil Exchanger must be ignored (the stock one kept), so passing it cannot
// accidentally disarm the authenticator.
func TestNew_WithExchanger_Nil_KeepsStockExchanger(t *testing.T) {
	t.Parallel()
	a, err := New(Config{
		Name:         "corp-nps",
		Servers:      []string{"radius.example.com:1812"},
		SharedSecret: "test-secret",
	}, WithExchanger(nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := a.exch.(*radiusExchanger); !ok {
		t.Errorf("nil WithExchanger replaced the stock exchanger with %T, want the stock *radiusExchanger", a.exch)
	}
}
