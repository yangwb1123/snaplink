package ssotest

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestRefreshGraceReadyBindingFailureRevokesFamily(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite", "redis", "postgres"} {
		for _, cause := range []string{"client", "tenant", "dpop", "mtls"} {
			t.Run(backend+"/"+cause, func(t *testing.T) {
				grace, _ := newGraceBackend(t, backend, time.Minute)
				first, second, store, issuer := newInflightServers(t, grace)
				close(issuer.release)
				baseline := postNamedRefresh(t.Context(), second.URL, rfClientID, "missing")
				issued := postInflightRefresh(first.URL, rfClientID)
				if issued.err != nil || issued.status != http.StatusOK {
					t.Fatalf("initial rotation: status=%d err=%v", issued.status, issued.err)
				}
				client := rfClientID
				if cause == "client" {
					client = "other-client"
				} else {
					// Model a cached response with a valid signature but a different
					// tenant/sender; validation must not accept mere cache existence.
					subject := &core.Subject{ID: rfUser, ClientID: rfClientID}
					switch cause {
					case "tenant":
						subject.TenantID = "other-tenant"
					case "dpop":
						subject.ConfirmationJKT = "other-proof-key"
					case "mtls":
						subject.ConfirmationX5TS256 = "other-certificate"
					}
					token, err := issuer.TokenIssuer.Issue(t.Context(), subject, []string{"read"})
					if err != nil {
						t.Fatal(err)
					}
					cached, hit := grace.Lookup("original", time.Now())
					if !hit {
						t.Fatal("rotation response was not cached")
					}
					cached[core.KeyAccessToken] = token.AccessToken
					grace.Remember("original", cached, time.Now())
				}
				denied := postInflightRefresh(second.URL, client)
				if baseline.err != nil || denied.err != nil || denied.status != http.StatusBadRequest || denied.raw != baseline.raw {
					t.Fatal("failed ready binding differed from the oracle-safe invalid_grant")
				}
				for _, token := range []string{"probe", issued.body[core.KeyRefreshToken].(string)} {
					if _, err := store.Inspect(t.Context(), token); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
						t.Fatal("failed ready binding suppressed family revocation")
					}
				}
			})
		}
	}
}
