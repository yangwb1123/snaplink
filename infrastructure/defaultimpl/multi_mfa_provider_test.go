package defaultimpl_test

import "github.com/yangwb1123/snaplink/shared/spi"

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

// stubMFAProvider is a minimal MFAProvider for composite-dispatch
// tests — same role-share as the test-only stubs in mfa_test.go but
// in defaultimpl_test scope to avoid pulling the root package into
// defaultimpl's test cycle.
type stubMFAProvider struct {
	methods   []string
	verifyErr error
	calls     int
}

func (s *stubMFAProvider) SupportedMethods() []string { return s.methods }
func (s *stubMFAProvider) Verify(_ context.Context, _, _ string, _ map[string]string) error {
	s.calls++
	return s.verifyErr
}

// stubBeginnerProvider extends stubMFAProvider with an MFABeginner
// surface so dispatch through the optional interface can be tested.
type stubBeginnerProvider struct {
	stubMFAProvider
	beginData  map[string]string
	beginErr   error
	beginCalls int
}

func (s *stubBeginnerProvider) Begin(_ context.Context, _, _ string) (map[string]string, error) {
	s.beginCalls++
	return s.beginData, s.beginErr
}

func TestMultiMFAProvider_RejectsEmptyProviders(t *testing.T) {
	t.Parallel()
	_, err := defaultimpl.NewMultiMFAProvider()
	if !errors.Is(err, defaultimpl.ErrMFANoProviders) {
		t.Fatalf("got %v, want ErrMFANoProviders", err)
	}
}

func TestMultiMFAProvider_RejectsNilProvider(t *testing.T) {
	t.Parallel()
	good := &stubMFAProvider{methods: []string{"totp"}}
	_, err := defaultimpl.NewMultiMFAProvider(good, nil)
	if err == nil {
		t.Fatal("want error on nil provider")
	}
}

func TestMultiMFAProvider_RejectsProviderWithNoMethods(t *testing.T) {
	t.Parallel()
	bad := &stubMFAProvider{methods: nil}
	_, err := defaultimpl.NewMultiMFAProvider(bad)
	if err == nil {
		t.Fatal("want error when provider declares no methods")
	}
}

func TestMultiMFAProvider_RejectsEmptyMethodName(t *testing.T) {
	t.Parallel()
	bad := &stubMFAProvider{methods: []string{""}}
	_, err := defaultimpl.NewMultiMFAProvider(bad)
	if err == nil {
		t.Fatal("want error when provider declares empty method name")
	}
}

func TestMultiMFAProvider_RejectsMethodConflict(t *testing.T) {
	t.Parallel()
	a := &stubMFAProvider{methods: []string{"totp"}}
	b := &stubMFAProvider{methods: []string{"totp"}}
	_, err := defaultimpl.NewMultiMFAProvider(a, b)
	if !errors.Is(err, defaultimpl.ErrMFAMethodConflict) {
		t.Fatalf("got %v, want ErrMFAMethodConflict", err)
	}
}

func TestMultiMFAProvider_SupportedMethodsAggregatesInOrder(t *testing.T) {
	t.Parallel()
	a := &stubMFAProvider{methods: []string{"totp"}}
	b := &stubMFAProvider{methods: []string{"webauthn", "push"}}
	m, err := defaultimpl.NewMultiMFAProvider(a, b)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.SupportedMethods()
	want := []string{"totp", "webauthn", "push"}
	if len(got) != len(want) {
		t.Fatalf("SupportedMethods = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("SupportedMethods[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestMultiMFAProvider_SupportedMethodsReturnsCopy(t *testing.T) {
	t.Parallel()
	// Anti-aliasing: caller mutating the returned slice mustn't
	// poison subsequent calls. SDK readers (the SSO server's
	// /auth/login handler) marshal into a JSON response, but
	// embedders writing custom middleware might iterate + mutate.
	a := &stubMFAProvider{methods: []string{"totp"}}
	m, _ := defaultimpl.NewMultiMFAProvider(a)
	first := m.SupportedMethods()
	first[0] = "MUTATED"
	second := m.SupportedMethods()
	if second[0] == "MUTATED" {
		t.Fatalf("caller mutation leaked into stored state: %v", second)
	}
}

func TestMultiMFAProvider_VerifyDispatchesByMethod(t *testing.T) {
	t.Parallel()
	a := &stubMFAProvider{methods: []string{"totp"}}
	b := &stubMFAProvider{methods: []string{"webauthn"}}
	m, _ := defaultimpl.NewMultiMFAProvider(a, b)

	if err := m.Verify(context.Background(), "alice", "totp", nil); err != nil {
		t.Fatalf("Verify totp: %v", err)
	}
	if a.calls != 1 || b.calls != 0 {
		t.Fatalf("call counts: a=%d b=%d, want a=1 b=0", a.calls, b.calls)
	}

	if err := m.Verify(context.Background(), "alice", "webauthn", nil); err != nil {
		t.Fatalf("Verify webauthn: %v", err)
	}
	if a.calls != 1 || b.calls != 1 {
		t.Fatalf("call counts: a=%d b=%d, want a=1 b=1", a.calls, b.calls)
	}
}

func TestMultiMFAProvider_VerifyUnknownMethod(t *testing.T) {
	t.Parallel()
	a := &stubMFAProvider{methods: []string{"totp"}}
	m, _ := defaultimpl.NewMultiMFAProvider(a)
	err := m.Verify(context.Background(), "alice", "fido2", nil)
	if !errors.Is(err, defaultimpl.ErrMFAUnknownMethod) {
		t.Fatalf("got %v, want ErrMFAUnknownMethod", err)
	}
}

func TestMultiMFAProvider_VerifyPropagatesInnerError(t *testing.T) {
	t.Parallel()
	innerErr := errors.New("totp: code mismatch")
	a := &stubMFAProvider{methods: []string{"totp"}, verifyErr: innerErr}
	m, _ := defaultimpl.NewMultiMFAProvider(a)
	err := m.Verify(context.Background(), "alice", "totp", nil)
	if !errors.Is(err, innerErr) {
		t.Fatalf("got %v, want wrapped innerErr", err)
	}
}

func TestMultiMFAProvider_BeginRoutesToBeginnerProvider(t *testing.T) {
	t.Parallel()
	totp := &stubMFAProvider{methods: []string{"totp"}}
	webauthn := &stubBeginnerProvider{
		stubMFAProvider: stubMFAProvider{methods: []string{"webauthn"}},
		beginData:       map[string]string{"options": "{}", "session": "sess-123"},
	}
	m, err := defaultimpl.NewMultiMFAProvider(totp, webauthn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Beginner method: data flows through
	data, err := m.Begin(context.Background(), "alice", "webauthn")
	if err != nil {
		t.Fatalf("Begin webauthn: %v", err)
	}
	if data["session"] != "sess-123" {
		t.Fatalf("Begin webauthn data: got %v want session=sess-123", data)
	}
	if webauthn.beginCalls != 1 {
		t.Errorf("webauthn.beginCalls = %d, want 1", webauthn.beginCalls)
	}

	// Non-beginner method: (nil, nil) fall-through
	data, err = m.Begin(context.Background(), "alice", "totp")
	if err != nil {
		t.Fatalf("Begin totp: %v", err)
	}
	if data != nil {
		t.Fatalf("Begin totp data should be nil for non-Beginner provider; got %v", data)
	}
}

func TestMultiMFAProvider_BeginUnknownMethod(t *testing.T) {
	t.Parallel()
	a := &stubMFAProvider{methods: []string{"totp"}}
	m, _ := defaultimpl.NewMultiMFAProvider(a)
	_, err := m.Begin(context.Background(), "alice", "ghost")
	if !errors.Is(err, defaultimpl.ErrMFAUnknownMethod) {
		t.Fatalf("got %v, want ErrMFAUnknownMethod", err)
	}
}

func TestMultiMFAProvider_BeginPropagatesInnerError(t *testing.T) {
	t.Parallel()
	innerErr := errors.New("webauthn: helper down")
	b := &stubBeginnerProvider{
		stubMFAProvider: stubMFAProvider{methods: []string{"webauthn"}},
		beginErr:        innerErr,
	}
	m, _ := defaultimpl.NewMultiMFAProvider(b)
	_, err := m.Begin(context.Background(), "alice", "webauthn")
	if !errors.Is(err, innerErr) {
		t.Fatalf("got %v, want wrapped innerErr", err)
	}
}

func TestMultiMFAProvider_SatisfiesBothInterfaces(t *testing.T) {
	t.Parallel()
	a := &stubMFAProvider{methods: []string{"totp"}}
	m, _ := defaultimpl.NewMultiMFAProvider(a)
	// Type assertions are also enforced at package-level via interface
	// guards; this test is a behavioral check that the SDK can use
	// the composite identically to a leaf provider.
	var _ spi.MFAProvider = m
	if _, ok := any(m).(spi.MFABeginner); !ok {
		t.Fatal("MultiMFAProvider should implement MFABeginner so single-call providers in the mix don't break Begin dispatch")
	}
}

func TestMultiMFAProvider_MultiMethodProviderClaimSurvivesReuse(t *testing.T) {
	t.Parallel()
	// Defensive case: same provider declares two methods (push +
	// push-fallback). The byMethod map should hold the same pointer
	// for both keys, not duplicate the entries in SupportedMethods.
	multi := &stubMFAProvider{methods: []string{"push", "push-fallback"}}
	m, err := defaultimpl.NewMultiMFAProvider(multi)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.SupportedMethods()
	if len(got) != 2 {
		t.Fatalf("SupportedMethods = %v, want both methods listed exactly once", got)
	}
	if err := m.Verify(context.Background(), "alice", "push-fallback", nil); err != nil {
		t.Fatalf("Verify push-fallback: %v", err)
	}
}
