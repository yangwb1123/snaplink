package ssotest

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// newRegionDiscoveryServer wires a discovery server with an optional
// serving-region advertisement and an optional metadata signer (both pins
// exercise the byte-identity + signed-metadata paths).
func newRegionDiscoveryServer(t *testing.T, advertise string, withSigner bool) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "demo", Secret: "s", Active: true,
		AllowedScopes: []string{"read", "write"},
	})
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.test"),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)
	opts := []sso.Option{
		sso.WithIssuer("https://sso.test"),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if advertise != "" {
		opts = append(opts, sso.WithServingRegionAdvertisement(region.ID(advertise)))
	}
	if withSigner {
		opts = append(opts, sso.WithMetadataSigner(issuer))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// TestDiscovery_ServingRegionAdvertisedWhenWired pins decision 2: the
// extension field + claims_supported entry appear ONLY when
// WithServingRegionAdvertisement is wired, and the signed_metadata (RFC
// 8414 §2.1) carries the same field because it signs the final cfg.
func TestDiscovery_ServingRegionAdvertisedWhenWired(t *testing.T) {
	srv := newRegionDiscoveryServer(t, "eu-west-1", true)
	doc := fetchDiscovery(t, srv)
	if got := doc["serving_region"]; got != "eu-west-1" {
		t.Errorf("serving_region = %v, want eu-west-1", got)
	}
	claims, ok := doc["claims_supported"].([]any)
	if !ok {
		t.Fatalf("claims_supported missing/wrong type: %v", doc["claims_supported"])
	}
	if !containsAnyString(claims, "serving_region") {
		t.Errorf("claims_supported = %v, want it to contain serving_region", claims)
	}

	// signed_metadata signs the FINAL cfg — the advertisement rides into the
	// signed claims automatically (an RS can trust the field cryptographically).
	jws, _ := doc["signed_metadata"].(string)
	if jws == "" {
		t.Fatal("signed_metadata missing despite signer wired")
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("signed_metadata malformed: %d parts", len(parts))
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("signed payload decode: %v", err)
	}
	var signed map[string]any
	if err := json.Unmarshal(payloadRaw, &signed); err != nil {
		t.Fatalf("signed payload parse: %v", err)
	}
	if got := signed["serving_region"]; got != "eu-west-1" {
		t.Errorf("signed serving_region = %v, want eu-west-1", got)
	}
}

// TestDiscovery_ServingRegionAbsentByDefault pins the byte-identity
// guarantee: without the option the discovery document has no serving_region
// field and claims_supported has no serving_region entry.
func TestDiscovery_ServingRegionAbsentByDefault(t *testing.T) {
	srv := newRegionDiscoveryServer(t, "", false)
	doc := fetchDiscovery(t, srv)
	if _, present := doc["serving_region"]; present {
		t.Errorf("serving_region present without WithServingRegionAdvertisement: %v", doc)
	}
	if claims, ok := doc["claims_supported"].([]any); ok {
		for _, c := range claims {
			if c == "serving_region" {
				t.Errorf("claims_supported contains serving_region without the option: %v", claims)
			}
		}
	}
}

func containsAnyString(list []any, want string) bool {
	for _, v := range list {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}
