package main

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/internal/composition"
)

func TestDiscoveryMatchesConfiguredMinimalClients(t *testing.T) {
	cfg := composition.DefaultsFromEnv(func(string) string { return "" }, edition)
	cfg.Issuer = "https://issuer.example"
	cfg.Second.Scopes = []string{"openid", "groups"}
	app, err := buildHandler(cfg)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)

	document := getJSON(t, server.URL+"/.well-known/openid-configuration", "")
	assertStringList(t, document[composition.KeyScopes], []string{
		"openid",
		"profile",
		"email",
		"groups",
	})
	assertStringList(t, document[composition.KeyTokenAuthMethods], []string{
		"client_secret_basic",
		"client_secret_post",
	})
	for _, key := range composition.HiddenMetadataEndpoints {
		if _, exists := document[key]; exists {
			t.Fatalf("minimal discovery advertises %s", key)
		}
	}
	if document["userinfo_endpoint"] == nil {
		t.Fatalf("minimal discovery hides the OIDC surface: %v", document)
	}
}

func TestOPSessionHonorsMaxAge(t *testing.T) {
	cfg := composition.DefaultsFromEnv(func(string) string { return "" }, edition)
	cfg.Issuer = "http://issuer.example"
	server, client, sessions := prototypeServerWithSessions(t, cfg)
	loginForCodeWithClient(t, client, server.URL, cfg, cfg.Client, true)
	setOPSessionAuthTime(t, sessions, time.Now().Add(-10*time.Minute))

	payload := loginPayloadForClient(cfg, cfg.Second)
	delete(payload, "provider")
	delete(payload, "credential")
	payload["max_age"] = 60
	_, body := postJSONWithClient(t, client, server.URL+"/auth/login", payload)
	if body["code"] != nil {
		t.Fatalf("expired OP session satisfied max_age: %v", body)
	}
}
