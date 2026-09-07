package authenticators

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestMemoryTempTokenStore_IssueClonesSubject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	actor := &sso.ActorClaim{Subject: "actor-1"}
	actor.Actor = actor
	subject := &sso.Subject{
		ID:                   "user-1",
		Claims:               map[string]string{"role": "member"},
		Resources:            []string{"https://api.example.test"},
		AMR:                  []string{"password"},
		AuthorizationDetails: []byte(`[{"type":"account"}]`),
		Roles:                []string{"member"},
		RequestedClaims:      []byte(`{"userinfo":{"email":null}}`),
		Actor:                actor,
	}
	store := NewMemoryTempTokenStore()
	if err := store.Issue(ctx, "token-1", subject, time.Minute); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	subject.ID = "attacker"
	subject.Claims["role"] = "admin"
	subject.Resources[0] = "https://evil.example.test"
	subject.AMR[0] = "webauthn"
	subject.AuthorizationDetails[0] = '{'
	subject.Roles[0] = "admin"
	subject.RequestedClaims[0] = '['
	subject.Actor.Subject = "attacker"

	got, err := store.Consume(ctx, "token-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ID != "user-1" || got.Claims["role"] != "member" {
		t.Fatalf("subject identity or claims changed through input alias: %+v", got)
	}
	if got.Resources[0] != "https://api.example.test" || got.AMR[0] != "password" || got.Roles[0] != "member" {
		t.Fatalf("subject slices changed through input alias: %+v", got)
	}
	if string(got.AuthorizationDetails) != `[{"type":"account"}]` || string(got.RequestedClaims) != `{"userinfo":{"email":null}}` {
		t.Fatalf("subject raw state changed through input alias: %+v", got)
	}
	if got.Actor.Subject != "actor-1" || got.Actor.Actor != got.Actor {
		t.Fatalf("actor chain was not independently cloned: %+v", got.Actor)
	}
}
