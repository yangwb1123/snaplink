package sso_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestIntrospectionProjectsVerifiedTenantClaim(t *testing.T) {
	t.Parallel()
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://issuer.test"))
	minted, err := issuer.Issue(context.Background(), &core.Subject{
		ID: "user", ClientID: rcovClient, TenantID: "tenant-signed",
	}, []string{"read"})
	if err != nil {
		t.Fatal(err)
	}
	srv := rcovNewServer(t, sso.WithTokenIssuer("jwt", issuer))
	form := url.Values{
		"token": {minted.AccessToken}, "tenant_id": {"tenant-forged"},
	}
	req, err := http.NewRequest(http.MethodPost, srv.http.URL+"/token/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(core.HeaderContentType, "application/x-www-form-urlencoded")
	req.SetBasicAuth(rcovClient, rcovSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || body["active"] != true {
		t.Fatalf("introspection status=%d body=%v, want active token", resp.StatusCode, body)
	}
	if body["tenant_id"] != "tenant-signed" {
		t.Fatalf("tenant_id=%v, want signed claim tenant-signed", body["tenant_id"])
	}
}
