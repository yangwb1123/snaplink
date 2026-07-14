package authenticators

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------- MagicLinkAuthenticator ----------
//
// captureEmail (defined in authenticators_test.go, shared with
// TestEmailAuthenticator_RoundTrip) is reused here as the real, non-mock
// EmailSender double — it just records the (to, code) pair Send received,
// matching AGENTS.md's "no mocks — real stores/fakes" convention.

// extractMagicLinkToken pulls the opaque token back out of a link built by
// MagicLinkAuthenticator.SendCode ("baseURL?token=<token>#email=<email>"), so
// tests can drive Authenticate the same way the landing-page JS would after
// parsing location.search.
func extractMagicLinkToken(t *testing.T, link string) string {
	t.Helper()
	q := strings.SplitN(link, "?token=", 2)
	if len(q) != 2 {
		t.Fatalf("link %q missing ?token=", link)
	}
	token := strings.SplitN(q[1], "#", 2)[0]
	if token == "" {
		t.Fatalf("link %q: empty token", link)
	}
	return token
}

func TestMagicLinkAuthenticator_Name(t *testing.T) {
	t.Parallel()
	a := NewMagicLinkAuthenticator(NewMemoryCodeStore(), &captureEmail{}, "https://sso.example.com/login/")
	if a.Name() != MethodMagicLink {
		t.Fatalf("Name = %q, want %q", a.Name(), MethodMagicLink)
	}
}

func TestMagicLinkAuthenticator_SendCode_GeneratesStoresAndSendsURL(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStore()
	em := &captureEmail{}
	a := NewMagicLinkAuthenticator(store, em, "https://sso.example.com/login/",
		WithMagicLinkTokenLength(16), WithMagicLinkTTL(2*time.Minute))

	if err := a.SendCode(context.Background(), "  Alice@Example.COM  "); err != nil {
		t.Fatalf("SendCode: %v", err)
	}

	// Normalized to lowercase + trimmed, like EmailAuthenticator.
	if em.to != "alice@example.com" {
		t.Fatalf("email captured = %q, want alice@example.com", em.to)
	}
	if !strings.HasPrefix(em.code, "https://sso.example.com/login/?token=") {
		t.Fatalf("link = %q, want the baseURL + ?token= prefix", em.code)
	}
	wantFragment := "#email=" + url.QueryEscape("alice@example.com")
	if !strings.Contains(em.code, wantFragment) {
		t.Fatalf("link = %q, want it to contain %q", em.code, wantFragment)
	}
	// The link must never contain a literal "&": it would be HTML-escaped to
	// "&amp;" by emailsmtp's html/template-based plain-text renderer,
	// corrupting the link for real recipients (see SendCode's doc comment).
	if strings.Contains(em.code, "&") {
		t.Fatalf("link = %q must not contain a literal '&'", em.code)
	}

	token := extractMagicLinkToken(t, em.code)
	if len(token) == 0 {
		t.Fatal("extracted empty token")
	}

	// The token must actually be the value the CodeStore holds (i.e. it
	// round-trips through Verify) — checked properly in the Authenticate
	// test below; here just confirm the store key was written under the
	// magiclink namespace, distinct from plain email-OTP's.
	if err := store.Verify(context.Background(), keyPrefixMagicLink+"alice@example.com", token); err != nil {
		t.Fatalf("store.Verify(magiclink key): %v", err)
	}
}

func TestMagicLinkAuthenticator_Authenticate_Success(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStore()
	em := &captureEmail{}
	a := NewMagicLinkAuthenticator(store, em, "https://sso.example.com/login/")

	if err := a.SendCode(context.Background(), "bob@example.com"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	token := extractMagicLinkToken(t, em.code)

	res, err := a.Authenticate(context.Background(), req(map[string]string{
		"email": "BOB@example.com", "code": token,
	}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != subjectPrefixEmail+"bob@example.com" {
		t.Errorf("UserID = %q, want %q", res.UserID, subjectPrefixEmail+"bob@example.com")
	}
	if res.ExternalID != "bob@example.com" {
		t.Errorf("ExternalID = %q", res.ExternalID)
	}
	if res.Provider != MethodMagicLink {
		t.Errorf("Provider = %q, want %q", res.Provider, MethodMagicLink)
	}
	if len(res.AuthMethods) != 1 || res.AuthMethods[0] != AuthMethodOTPLink {
		t.Errorf("AuthMethods = %v, want [%q]", res.AuthMethods, AuthMethodOTPLink)
	}
}

func TestMagicLinkAuthenticator_Authenticate_WrongToken(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStore()
	em := &captureEmail{}
	a := NewMagicLinkAuthenticator(store, em, "https://sso.example.com/login/")

	if err := a.SendCode(context.Background(), "carol@example.com"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"email": "carol@example.com", "code": "not-the-right-token",
	})); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("Authenticate wrong token err = %v, want ErrCodeInvalid", err)
	}

	// The real token must still work — a wrong attempt must not consume it
	// (matches TestMemoryCodeStore_WrongCodeDoesNotConsume).
	token := extractMagicLinkToken(t, em.code)
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"email": "carol@example.com", "code": token,
	})); err != nil {
		t.Errorf("Authenticate real token after a bad attempt: %v", err)
	}
}

func TestMagicLinkAuthenticator_Authenticate_SingleUse(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStore()
	em := &captureEmail{}
	a := NewMagicLinkAuthenticator(store, em, "https://sso.example.com/login/")

	if err := a.SendCode(context.Background(), "dave@example.com"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	token := extractMagicLinkToken(t, em.code)
	creds := req(map[string]string{"email": "dave@example.com", "code": token})

	if _, err := a.Authenticate(context.Background(), creds); err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}
	// Single-use: CodeStore.Verify consumes on success (matches
	// TestMemoryCodeStore_ConsumesOnSuccess) — a replayed magic-link click
	// (e.g. a second tab, or an email-security-scanner prefetch racing the
	// real user) must NOT authenticate twice.
	if _, err := a.Authenticate(context.Background(), creds); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("second Authenticate err = %v, want ErrCodeInvalid (single-use)", err)
	}
}

func TestMagicLinkAuthenticator_Authenticate_Expired(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStore()
	em := &captureEmail{}
	a := NewMagicLinkAuthenticator(store, em, "https://sso.example.com/login/", WithMagicLinkTTL(time.Nanosecond))

	if err := a.SendCode(context.Background(), "erin@example.com"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	token := extractMagicLinkToken(t, em.code)
	time.Sleep(2 * time.Millisecond)

	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"email": "erin@example.com", "code": token,
	})); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("Authenticate after TTL expiry err = %v, want ErrCodeInvalid", err)
	}
}

func TestMagicLinkAuthenticator_SendCode_InvalidEmail(t *testing.T) {
	t.Parallel()
	a := NewMagicLinkAuthenticator(NewMemoryCodeStore(), &captureEmail{}, "https://sso.example.com/login/")
	for _, bad := range []string{"", "no-at-sign", "   "} {
		if err := a.SendCode(context.Background(), bad); err == nil {
			t.Errorf("SendCode(%q) should fail", bad)
		}
	}
}

func TestMagicLinkAuthenticator_AuthenticateMissingCreds(t *testing.T) {
	t.Parallel()
	a := NewMagicLinkAuthenticator(NewMemoryCodeStore(), &captureEmail{}, "https://sso.example.com/login/")
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"email": "a@b.co"})); err == nil {
		t.Error("expected error on missing code")
	}
	if _, err := a.Authenticate(context.Background(), req(map[string]string{"code": "tok"})); err == nil {
		t.Error("expected error on missing email")
	}
}

func TestMagicLinkAuthenticator_LockoutIdentity(t *testing.T) {
	t.Parallel()
	a := NewMagicLinkAuthenticator(NewMemoryCodeStore(), &captureEmail{}, "https://sso.example.com/login/")
	got := a.LockoutIdentity(map[string]string{"email": "  Frank@Example.COM "})
	if got != "frank@example.com" {
		t.Errorf("LockoutIdentity = %q, want normalized email", got)
	}
}

func TestMagicLinkAuthenticator_CallbackUnsupported(t *testing.T) {
	t.Parallel()
	a := NewMagicLinkAuthenticator(NewMemoryCodeStore(), &captureEmail{}, "https://sso.example.com/login/")
	if _, err := a.Callback(context.Background(), nil); err == nil {
		t.Error("Callback should not be supported")
	}
	if u := a.LoginURL(""); u != "" {
		t.Errorf("LoginURL = %q", u)
	}
}

// TestMagicLinkAuthenticator_SendCode_AntiEnumeration proves SendCode gives
// the SAME success outcome for an address regardless of any prior state that
// would reveal whether an account exists — there is no UserProvider
// dependency at all in this authenticator (structurally: NewMagicLinkAuthenticator
// takes only a CodeStore + EmailSender + baseURL, nothing that could look up
// a user), so "exists" vs "does not exist" is not even representable input;
// SendCode always saves + sends for any syntactically valid address. This
// mirrors how EmailAuthenticator.SendCode behaves (AGENTS.md §3
// Anti-Enumeration).
func TestMagicLinkAuthenticator_SendCode_AntiEnumeration(t *testing.T) {
	t.Parallel()
	store := NewMemoryCodeStoreWithCooldown(0) // disable cooldown: isolate the existence question
	em := &captureEmail{}
	a := NewMagicLinkAuthenticator(store, em, "https://sso.example.com/login/")

	// "brand-new" address: never seen before.
	freshErr := a.SendCode(context.Background(), "never-seen@example.com")

	// "known" address: pre-populate BOTH a prior magic-link request AND a
	// completed (consumed) authentication, i.e. every kind of prior state
	// that could distinguish "has an account" from "does not" if this
	// authenticator leaked it.
	knownEmail := "known@example.com"
	if err := a.SendCode(context.Background(), knownEmail); err != nil {
		t.Fatalf("seed SendCode: %v", err)
	}
	seedToken := extractMagicLinkToken(t, em.code)
	if _, err := a.Authenticate(context.Background(), req(map[string]string{
		"email": knownEmail, "code": seedToken,
	})); err != nil {
		t.Fatalf("seed Authenticate: %v", err)
	}
	knownErr := a.SendCode(context.Background(), knownEmail)

	if freshErr != nil || knownErr != nil {
		t.Fatalf("SendCode must always succeed regardless of prior state: fresh=%v known=%v", freshErr, knownErr)
	}
	// Both sends must have actually dispatched a link (never silently
	// skipped for either case).
	if em.to != knownEmail || !strings.Contains(em.code, "?token=") {
		t.Fatalf("last captured send = (%q,%q), want a link sent to %q", em.to, em.code, knownEmail)
	}
}

// ---------- GenerateOpaqueToken ----------

func TestGenerateOpaqueToken_LengthAndUniqueness(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for range 20 {
		tok, err := GenerateOpaqueToken(DefaultMagicLinkTokenBytes)
		if err != nil {
			t.Fatalf("GenerateOpaqueToken: %v", err)
		}
		// base64.RawURLEncoding of 32 bytes = ceil(32*8/6) = 43 chars, no padding.
		if len(tok) != 43 {
			t.Errorf("token length = %d, want 43", len(tok))
		}
		if strings.ContainsAny(tok, "+/=&<>\"' ") {
			t.Errorf("token %q contains a non-URL-safe or HTML-special character", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate token generated: %q", tok)
		}
		seen[tok] = true
	}
}

func TestGenerateOpaqueToken_RejectsNonPositiveLength(t *testing.T) {
	t.Parallel()
	if _, err := GenerateOpaqueToken(0); err == nil {
		t.Error("GenerateOpaqueToken(0) should fail")
	}
	if _, err := GenerateOpaqueToken(-1); err == nil {
		t.Error("GenerateOpaqueToken(-1) should fail")
	}
}
