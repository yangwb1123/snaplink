package sso_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oidc/bcl"
)

type bclFailingNotifier struct{ calls int }

func (n *bclFailingNotifier) Notify(context.Context, string, string) error {
	n.calls++
	return errors.New("rp unavailable")
}

type bclSuccessNotifier struct{ calls int }

func (n *bclSuccessNotifier) Notify(context.Context, string, string) error {
	n.calls++
	return nil
}

func TestBackchannelFailureIsQueuedAfterRetryExhaustion(t *testing.T) {
	t.Parallel()
	notifier := &bclFailingNotifier{}
	manager := bcl.NewManager(rcovLogoutTokenIssuer{}, notifier, bcl.NewMemoryStore(10), bcl.WithRetryInterval(time.Hour))
	t.Cleanup(func() { _ = manager.Close(context.Background()) })
	s := rcovNewServer(t, sso.WithBackchannelLogout(rcovLogoutTokenIssuer{}, manager))
	client, _ := s.clients.Get(context.Background(), rcovClient)
	client.BackchannelLogoutURI = "https://rp.example/bcl"
	s.clients.AddSeed(client)
	access, _ := rcovDirectLogin(t, s)
	status, out := rcovPostJSON(t, s.http.URL+"/logout", access, nil)
	if status != http.StatusOK || out["status"] != "logged_out" {
		t.Fatalf("logout = %d %v", status, out)
	}
	entries, err := manager.ListFailures(context.Background(), "", 10)
	if err != nil || len(entries) != 1 || entries[0].Attempts != sso.DefaultBackchannelLogoutMaxAttempts {
		t.Fatalf("queued failures = %+v, %v", entries, err)
	}
	if notifier.calls != sso.DefaultBackchannelLogoutMaxAttempts {
		t.Fatalf("delivery attempts = %d", notifier.calls)
	}
}

func TestBackchannelFailureAdminListAndReplay(t *testing.T) {
	t.Parallel()
	notifier := &bclSuccessNotifier{}
	manager := bcl.NewManager(rcovLogoutTokenIssuer{}, notifier, bcl.NewMemoryStore(10), bcl.WithRetryInterval(time.Hour))
	t.Cleanup(func() { _ = manager.Close(context.Background()) })
	if err := manager.RecordFailure(context.Background(), bcl.Failure{
		ClientID: rcovClient, Subject: rcovUser, TokenSubject: rcovUser,
		URI: "https://rp.example/bcl", LastError: "initial failure",
	}); err != nil {
		t.Fatal(err)
	}
	env := rcovNewAdminServer(t, sso.WithBackchannelLogout(rcovLogoutTokenIssuer{}, manager))
	status, body := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/backchannel-logout/failures", env.token, nil)
	if status != http.StatusOK || body["total"] != float64(1) {
		t.Fatalf("list = %d %v", status, body)
	}
	entries, _ := manager.ListFailures(context.Background(), "", 10)
	status, body = rcovPostJSON(t, env.url+"/api/v1/admin/backchannel-logout/failures/"+entries[0].ID+"/replay", env.token, nil)
	if status != http.StatusOK || body["delivery_status"] != "delivered" {
		t.Fatalf("replay = %d %v", status, body)
	}
	left, _ := manager.ListFailures(context.Background(), "", 10)
	if len(left) != 0 || notifier.calls != 1 {
		t.Fatalf("post-replay queue=%v notifier.calls=%d", left, notifier.calls)
	}
}
