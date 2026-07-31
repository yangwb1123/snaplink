package admin

import (
	"reflect"
	"testing"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/connections/provider"
)

func TestConnectionReadDTOOmitsWriteOnlyConfig(t *testing.T) {
	stored := map[string]string{
		"oidc_client_id":     "public-id",
		"oidc_client_secret": "credential",
		"saml_private_key":   "private",
	}
	got := connectionToJSON(&connections.Connection{Config: stored}).Config
	want := map[string]string{"oidc_client_id": "public-id"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("read config = %#v, want %#v", got, want)
	}
	if stored["oidc_client_secret"] != "credential" {
		t.Fatal("read DTO mutated the stored config")
	}
}

func TestProviderReadDTOOmitsWriteOnlyConfig(t *testing.T) {
	got := providerToJSON(&provider.Provider{Config: map[string]string{
		"issuer":        "https://idp.example",
		"client-secret": "credential",
		"api_key":       "credential",
	}}).Config
	want := map[string]string{"issuer": "https://idp.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("read config = %#v, want %#v", got, want)
	}
}

func TestMergeWriteConfigPreservesOmittedCredentials(t *testing.T) {
	stored := map[string]string{"issuer": "old", "client_secret": "keep"}
	got := mergeWriteConfig(stored, map[string]string{"issuer": "new"})
	want := map[string]string{"issuer": "new", "client_secret": "keep"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged config = %#v, want %#v", got, want)
	}

	got = mergeWriteConfig(stored, map[string]string{"client_secret": ""})
	if value, ok := got["client_secret"]; !ok || value != "" {
		t.Fatalf("explicit credential replacement was not honored: %#v", got)
	}
}
