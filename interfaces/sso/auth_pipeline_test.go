package sso_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestAuthPipelinePreAuthenticateRejectsWithStableError(t *testing.T) {
	t.Parallel()
	hook := core.AuthHookFunc{
		At:     core.PhasePreAuthenticate,
		Config: core.AuthHookConfig{Name: "test.pre", FailClosed: true},
		Run: func(context.Context, *core.HookInput) (*core.HookOutput, error) {
			return nil, core.NewAuthHookError(core.ErrAuthHookRejected, http.StatusForbidden, errors.New("private policy detail"))
		},
	}
	server := rcovNewServer(t, sso.WithAuthHook(hook))
	status, body := authPipelineLogin(t, server, rcovPassword)
	if status != http.StatusForbidden || body["error"] != core.ErrAuthHookRejected {
		t.Fatalf("status=%d body=%v", status, body)
	}
	events, err := server.sink.Query(context.Background(), audit.Query{Type: audit.EventAuthHookFailed})
	if err != nil || len(events) != 1 || events[0].Metadata["auth_hook.name"] != "test.pre" {
		t.Fatalf("audit events=%#v err=%v", events, err)
	}
}

func TestAuthPipelineMutatesAttributesAndTokenClaims(t *testing.T) {
	t.Parallel()
	postToken := make(chan *core.Token, 1)
	server := rcovNewServer(t,
		sso.WithAuthHook(core.AuthHookFunc{
			At: core.PhasePostAuthenticate, Config: core.AuthHookConfig{Name: "test.attributes", FailClosed: true},
			Run: func(_ context.Context, input *core.HookInput) (*core.HookOutput, error) {
				if input.UserID != rcovUser || input.AuthResult == nil {
					t.Fatalf("post-auth input=%#v", input)
				}
				return &core.HookOutput{Attributes: map[string]string{"department": "engineering"}}, nil
			},
		}),
		sso.WithAuthHook(core.AuthHookFunc{
			At: core.PhasePreTokenIssuance, Config: core.AuthHookConfig{Name: "test.claims", FailClosed: true},
			Run: func(context.Context, *core.HookInput) (*core.HookOutput, error) {
				return &core.HookOutput{Claims: map[string]string{"pipeline": "applied"}}, nil
			},
		}),
		sso.WithAuthHook(core.AuthHookFunc{
			At: core.PhasePostTokenIssuance, Config: core.AuthHookConfig{Name: "test.notify"},
			Run: func(_ context.Context, input *core.HookInput) (*core.HookOutput, error) {
				postToken <- input.Token
				return nil, nil
			},
		}),
	)
	status, body := authPipelineLogin(t, server, rcovPassword)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	access, _ := body["access_token"].(string)
	claims, err := server.srv.ValidateToken(context.Background(), access)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Extra["department"] != "engineering" || claims.Extra["pipeline"] != "applied" {
		t.Fatalf("extra claims=%v", claims.Extra)
	}
	select {
	case token := <-postToken:
		if token == nil || token.AccessToken == "" {
			t.Fatalf("post-token input=%#v", token)
		}
	case <-time.After(time.Second):
		t.Fatal("post-token hook not called")
	}
}

func TestAuthPipelineFailureNotificationAndMFASkip(t *testing.T) {
	t.Parallel()
	failures := make(chan *core.HookInput, 1)
	server := rcovNewServer(t,
		sso.WithRiskScorer(rcovRequireMFAScorer{}),
		sso.WithMFAProvider(rcovTOTPProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), time.Minute),
		sso.WithAuthHook(core.AuthHookFunc{
			At: core.PhasePostAuthenticate, Config: core.AuthHookConfig{Name: "test.skip_mfa", FailClosed: true},
			Run: func(context.Context, *core.HookInput) (*core.HookOutput, error) {
				return &core.HookOutput{SkipMFA: true}, nil
			},
		}),
		sso.WithAuthHook(core.AuthHookFunc{
			At: core.PhaseOnLoginFailed, Config: core.AuthHookConfig{Name: "test.failed"},
			Run: func(_ context.Context, input *core.HookInput) (*core.HookOutput, error) {
				failures <- input
				return nil, nil
			},
		}),
	)
	status, body := authPipelineLogin(t, server, rcovPassword)
	if status != http.StatusOK || body["access_token"] == nil || body["error"] == core.ErrMFARequired {
		t.Fatalf("MFA skip status=%d body=%v", status, body)
	}
	status, body = authPipelineLogin(t, server, "wrong")
	if status != http.StatusUnauthorized || body["error"] != core.ErrInvalidCredentials {
		t.Fatalf("failure status=%d body=%v", status, body)
	}
	select {
	case input := <-failures:
		if input.FailureCode != core.ErrInvalidCredentials || input.Provider != "password" {
			t.Fatalf("failure input=%#v", input)
		}
	case <-time.After(time.Second):
		t.Fatal("login-failure hook not called")
	}
}

func authPipelineLogin(t *testing.T, server *rcovServer, password string) (int, map[string]any) {
	t.Helper()
	return rcovPostJSON(t, server.http.URL+"/auth/login", "", map[string]any{
		"provider": "password", "client_id": rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": password},
		"scope":      []string{"openid", "profile", "email"},
	})
}
