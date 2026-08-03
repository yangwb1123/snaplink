package sso_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tokenexchange/agentidentity"
	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	lifecyclememory "github.com/yangwb1123/snaplink/domains/userlifecycle/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

func suspendLifecycleUser(t *testing.T, store userlifecycle.Store) {
	t.Helper()
	err := store.Append(context.Background(), rcovUser, userlifecycle.Transition{
		From: userlifecycle.StateActive,
		To:   userlifecycle.StateSuspended,
		At:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("suspend lifecycle user: %v", err)
	}
}

func TestUserLifecycle_BlocksInteractiveLogin(t *testing.T) {
	t.Parallel()
	store := lifecyclememory.New()
	suspendLifecycleUser(t, store)
	s := rcovNewServer(t, sso.WithUserLifecycle(store))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusForbidden || out["error"] != sso.ErrAccountLocked {
		t.Fatalf("suspended login status=%d body=%v, want 403 account_locked", status, out)
	}
	sessions, err := s.sessions.ListByUser(context.Background(), rcovUser)
	if err != nil || len(sessions) != 0 {
		t.Fatalf("sessions after denied login = %d, err=%v; want none", len(sessions), err)
	}
}

func TestUserLifecycle_StateReadFailureFailsClosed(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithUserLifecycle(failingLifecycleStore{}))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusForbidden || out["error"] != sso.ErrAccountLocked {
		t.Fatalf("failed lifecycle lookup status=%d body=%v, want 403 account_locked", status, out)
	}
}

func TestUserLifecycle_BlocksExistingAccessAndRefreshTokens(t *testing.T) {
	t.Parallel()
	store := lifecyclememory.New()
	s := rcovNewServer(t, sso.WithUserLifecycle(store))
	access, refresh := rcovDirectLogin(t, s)
	suspendLifecycleUser(t, store)

	status, out := rcovDo(t, http.MethodGet, s.http.URL+"/userinfo", access, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("userinfo after suspend status=%d body=%v, want 401", status, out)
	}
	status, out = rcovPostJSON(t, s.http.URL+"/token/introspect", "", map[string]any{
		"token": access, "client_id": rcovClient, "client_secret": rcovSecret,
	})
	if status != http.StatusOK || out["active"] != false {
		t.Fatalf("introspection after suspend status=%d body=%v, want 200 active=false", status, out)
	}
	status, out = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type": "refresh_token", "refresh_token": refresh,
		"client_id": rcovClient, "client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("refresh after suspend status=%d body=%v, want 400 invalid_grant", status, out)
	}
}

func TestUserLifecycle_BlocksPreexistingAuthorizationCode(t *testing.T) {
	t.Parallel()
	store := lifecyclememory.New()
	s := rcovNewServer(t, sso.WithUserLifecycle(store))
	code := rcovIssueEmptyAuthCode(t, s)
	suspendLifecycleUser(t, store)

	status, out := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type": "authorization_code", "code": code,
		"client_id": rcovClient, "client_secret": rcovSecret, "redirect_uri": rcovRedirect,
	})
	if status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("code exchange after suspend status=%d body=%v, want 400 invalid_grant", status, out)
	}
}

func TestUserLifecycle_BlocksDelegationMintAndActorChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := lifecyclememory.New()
	agents := agentidentity.NewMemoryAgentProvider()
	sessions := agentidentity.NewMemoryAgentSessionStore()
	if err := agents.Register(ctx, &agentidentity.Agent{
		ID: "agent-1", DisplayName: "Agent", AllowedScopes: []string{"read"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := sessions.Create(ctx, &agentidentity.AgentSession{
		ID: "delegation-1", HumanSubject: rcovUser, AgentID: "agent-1",
		GrantedScopes: []string{"read"}, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	delegatedIssuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	s := rcovNewServer(t,
		sso.WithUserLifecycle(store),
		sso.WithTokenIssuer("delegated-lifecycle-test", delegatedIssuer),
		sso.WithAgentDelegationGrant(agents, sessions, func(context.Context, string) ([]string, error) {
			return []string{"read"}, nil
		}),
	)
	suspendLifecycleUser(t, store)

	status, out := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type": core.GrantTypeAgentDelegation, "agent_session_id": "delegation-1",
		"client_id": rcovClient, "client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest || out["error"] != core.ErrInvalidGrant {
		t.Fatalf("delegation mint after suspend status=%d body=%v, want 400 invalid_grant", status, out)
	}

	token, err := delegatedIssuer.Issue(ctx, &core.Subject{
		ID: "agent-1", ClientID: rcovClient, Actor: &core.ActorClaim{Subject: rcovUser},
	}, []string{"openid"})
	if err != nil {
		t.Fatalf("issue delegated token: %v", err)
	}
	status, out = rcovDo(t, http.MethodGet, s.http.URL+"/userinfo", token.AccessToken, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("delegated token after human suspend status=%d body=%v, want 401", status, out)
	}
}

type failingLifecycleStore struct{}

func (failingLifecycleStore) Get(context.Context, string) (userlifecycle.Record, error) {
	return userlifecycle.Record{}, errors.New("lifecycle store unavailable")
}

func (failingLifecycleStore) Append(context.Context, string, userlifecycle.Transition) error {
	return errors.New("lifecycle store unavailable")
}

func (failingLifecycleStore) ListByState(context.Context, userlifecycle.State) ([]string, error) {
	return nil, errors.New("lifecycle store unavailable")
}
