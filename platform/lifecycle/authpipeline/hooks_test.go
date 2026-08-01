package authpipeline

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/lifecycle/wasmauthz"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestIPSkipMFAHook(t *testing.T) {
	hook, err := NewIPSkipMFAHook([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	inside, err := hook.Execute(context.Background(), &core.HookInput{IP: "10.2.3.4"})
	if err != nil || inside == nil || !inside.SkipMFA {
		t.Fatalf("inside output=%#v err=%v", inside, err)
	}
	outside, err := hook.Execute(context.Background(), &core.HookInput{IP: "192.0.2.1"})
	if err != nil || outside != nil {
		t.Fatalf("outside output=%#v err=%v", outside, err)
	}
	if _, err := NewIPSkipMFAHook([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected invalid CIDR error")
	}
}

func TestProfileCompletionHook(t *testing.T) {
	hook := NewProfileCompletionHook([]string{"email", "department"})
	complete := &core.HookInput{AuthResult: &core.AuthResult{Attributes: map[string]string{"email": "a@example.com", "department": "eng"}}}
	if _, err := hook.Execute(context.Background(), complete); err != nil {
		t.Fatal(err)
	}
	incomplete := &core.HookInput{AuthResult: &core.AuthResult{Attributes: map[string]string{"email": "a@example.com"}}}
	_, err := hook.Execute(context.Background(), incomplete)
	status, code, ok := core.AuthHookHTTPError(err)
	if !ok || status != 403 || code != core.ErrProfileIncomplete {
		t.Fatalf("error=(%d,%q,%v) %v", status, code, ok, err)
	}
}

func TestSIEMFailureHookReturnsBeforeNotificationCompletes(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	hook := NewSIEMFailureHook(func(context.Context, *core.HookInput) error {
		close(started)
		<-release
		return nil
	}, 1, time.Second)
	if _, err := hook.Execute(context.Background(), &core.HookInput{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("notification did not start")
	}
	if _, err := hook.Execute(context.Background(), &core.HookInput{}); err == nil {
		t.Fatal("expected bounded concurrency saturation")
	}
	close(release)
}

func TestWASMHookMapsInputAndDenies(t *testing.T) {
	fake := &fakeWASMAuthorizer{decision: wasmauthz.Decision{Allowed: true}}
	hook := NewWASMHook(fake, core.PhasePreAuthenticate, core.AuthHookConfig{Name: "policy", FailClosed: true})
	input := &core.HookInput{Phase: core.PhasePreAuthenticate, ClientID: "client", TenantID: "tenant", IP: "192.0.2.1"}
	if _, err := hook.Execute(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if fake.request.Action != string(core.PhasePreAuthenticate) || fake.request.Resource != "client" || fake.request.Context["tenant_id"] != "tenant" {
		t.Fatalf("request=%#v", fake.request)
	}
	fake.decision.Allowed = false
	if _, err := hook.Execute(context.Background(), input); err == nil {
		t.Fatal("expected denied WASM decision to reject")
	}
}

type fakeWASMAuthorizer struct {
	decision wasmauthz.Decision
	request  wasmauthz.Request
}

func (f *fakeWASMAuthorizer) Authorize(_ context.Context, request wasmauthz.Request) (wasmauthz.Decision, error) {
	f.request = request
	return f.decision, nil
}
