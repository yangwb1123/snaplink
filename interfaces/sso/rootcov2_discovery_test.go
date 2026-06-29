package sso_test

// rootcov2_discovery_test.go targets the discovery-document branch surface and a
// broad set of cheap one-line WithXxx option setters the first rootcov_* pass
// left at 0%:
//   - signed_metadata + JARM + JAR-fetch/decrypt + JWE-response-encrypt +
//     mTLS-bound + pairwise branches of buildOIDCConfiguration / discovery_config.go
//   - the PAR-then-/auth/login resolution path (resolve_login_request.go)
//   - the pairwise subject round-trip (pairwise_client_assertion.go
//     applyPairwiseSubject / resolveLocalSubject)
//   - the WithXxx setters: WithJARFetcher / WithJARDecrypter /
//     WithJWEResponseEncrypter / WithClientCertExtractor / WithDPoPNonceProvider /
//     WithMetadataSigner / WithPairwiseSubjectStore / WithPairwiseSalt /
//     WithFederationAutoRegistration / WithTenantMiddlewareOptions /
//     WithAnomalyRunner / WithInvitationSender / WithStorageHealth.
//
// REUSES rcovNewServer / rcovDirectLogin / rcovPostJSON / rcovDo / rcovGetJSON.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/security"
)

// TestRcov2D_DiscoveryRichBranches wires the broad optional surface and fetches
// the discovery doc, exercising the buildOIDCConfiguration branches +
// signDiscoveryMetadata that only fire when those collaborators are present.
func TestRcov2D_DiscoveryRichBranches(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	dec, err := defaultimpl.NewRSAJWEDecrypter(priv, "enc-1")
	if err != nil {
		t.Fatalf("jwe decrypter: %v", err)
	}
	iss := defaultimpl.NewEd25519JWTIssuer()

	s := rcovNewServer(t,
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithMetadataSigner(iss), // signed_metadata
		sso.WithJARM(iss),           // authorization_signing_alg_values_supported
		sso.WithJARFetcher(security.NewHTTPJARFetcher()),
		sso.WithJARDecrypter(dec), // request_object_encryption_*
		sso.WithJWEResponseEncrypter(defaultimpl.NewRSAJWEResponseEncrypter()),
		sso.WithClientCertExtractor(rcov2CertExtractor{}), // tls_client_certificate_bound
		sso.WithPairwiseSubjectStore(security.NewMemoryPairwiseSubjectStore()),
		sso.WithDPoPNonceProvider(rcov2Nonce(t)),
		sso.WithSupportedACRValues("urn:acr:1"),
		sso.WithOperatorMetadata("https://policy", "https://tos", "https://docs"),
	)

	var doc map[string]any
	resp := rcovGetJSON(t, s.http.URL+"/.well-known/openid-configuration", &doc)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery = %d, want 200", resp.StatusCode)
	}
	// signed_metadata present (WithMetadataSigner).
	if doc["signed_metadata"] == "" || doc["signed_metadata"] == nil {
		t.Errorf("expected signed_metadata in discovery doc")
	}
	// JARM signing algs present (WithJARM).
	if _, ok := doc["authorization_signing_alg_values_supported"]; !ok {
		t.Errorf("expected JARM signing algs in discovery doc")
	}
	// mTLS-bound flag flipped (WithClientCertExtractor).
	if doc["tls_client_certificate_bound_access_tokens"] != true {
		t.Errorf("expected tls_client_certificate_bound = true")
	}
	// pairwise advertised alongside public (WithPairwiseSubjectStore).
	if subs, ok := doc["subject_types_supported"].([]any); ok {
		found := false
		for _, st := range subs {
			if st == "pairwise" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected pairwise in subject_types_supported: %v", subs)
		}
	}
}

// rcov2CertExtractor is a no-op ClientCertExtractor (the discovery doc only
// cares whether one is wired, not what it extracts).
type rcov2CertExtractor struct{}

func (rcov2CertExtractor) ExtractClientCert(*http.Request) (*x509.Certificate, bool) {
	return nil, false
}

// TestRcov2D_PARThenLogin covers resolve_login_request.go's PAR branch: a /par
// push yields a request_uri that /auth/login consumes to recover the pushed
// parameters and mint a code.
func TestRcov2D_PARThenLogin(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithPARStore(defaultimpl.NewMemoryPARStore(), 5*time.Minute))

	// Push the authorization request.
	status, out := rcovPostJSON(t, s.http.URL+"/par", "", map[string]any{
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"response_type": "code",
		"redirect_uri":  rcovRedirect,
		"scope":         "openid profile",
		"state":         "par-state",
		"nonce":         "par-nonce",
	})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("par push = %d body=%v", status, out)
	}
	requestURI, _ := out["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("no request_uri from PAR: %v", out)
	}

	// Login consuming the request_uri (no other params — they come from PAR).
	status, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":    "password",
		"client_id":   rcovClient,
		"request_uri": requestURI,
		"credential":  map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("par login = %d body=%v", status, out)
	}
	if out["code"] == "" || out["code"] == nil {
		t.Errorf("par login minted no code: %v", out)
	}
	// State pushed via PAR is echoed back.
	if out["state"] != "par-state" {
		t.Errorf("par state = %v, want par-state", out["state"])
	}

	// Replaying the (now-consumed) request_uri => invalid_request_uri.
	status, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":    "password",
		"client_id":   rcovClient,
		"request_uri": requestURI,
		"credential":  map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusBadRequest || out["error"] != "invalid_request_uri" {
		t.Errorf("par replay = %d %v, want 400 invalid_request_uri", status, out)
	}
}

// TestRcov2D_PairwiseSubject covers the pairwise subject round-trip: a client
// with subject_type=pairwise gets an opaque sub in its token, and /userinfo
// reverses it via resolveLocalSubject.
func TestRcov2D_PairwiseSubject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser, Email: "alice@example.com"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, RedirectURIs: []string{rcovRedirect},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
		SubjectType: security.SubjectTypePairwise,
	})
	iss := defaultimpl.NewEd25519JWTIssuer()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPairwiseSubjectStore(security.NewMemoryPairwiseSubjectStore()),
		sso.WithPairwiseSalt("rcov2-stable-salt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("pairwise login = %d body=%v", status, out)
	}
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %v", out)
	}

	// /userinfo reverses the pairwise sub to the local subject for lookup.
	status, ui := rcovDo(t, http.MethodGet, httpSrv.URL+"/userinfo", access, nil)
	if status != http.StatusOK {
		t.Fatalf("pairwise userinfo = %d body=%v", status, ui)
	}
	// The sub returned to the RP is the opaque pairwise value, NOT the local id.
	if ui["sub"] == rcovUser {
		t.Errorf("pairwise userinfo sub leaked the local id %q", rcovUser)
	}
	if ui["sub"] == "" || ui["sub"] == nil {
		t.Errorf("pairwise userinfo missing sub: %v", ui)
	}
}

// TestRcov2D_CheapOptionSetters flips a batch of one-line WithXxx setters the
// prior pass left at 0% and confirms the server still constructs + serves. The
// option bodies run during NewServer; building the handler exercises any
// route-mount branches they gate.
func TestRcov2D_CheapOptionSetters(t *testing.T) {
	t.Parallel()
	detectors := []anomaly.Detector{}
	runner := anomaly.NewRunner(detectors, anomaly.SinkFunc(
		func(context.Context, *anomaly.LoginEvent, anomaly.Signal) error { return nil }))

	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),

		// The cheap 0% setters under test.
		sso.WithJARFetcher(security.NewHTTPJARFetcher()),
		sso.WithClientCertExtractor(rcov2CertExtractor{}),
		sso.WithDPoPNonceProvider(rcov2Nonce(t)),
		sso.WithPairwiseSubjectStore(security.NewMemoryPairwiseSubjectStore()),
		sso.WithPairwiseSalt("salt"),
		sso.WithFederationAutoRegistration(),
		sso.WithTenantMiddlewareOptions(sso.TenantMiddlewareOptions{}),
		sso.WithAnomalyRunner(runner),
		sso.WithInvitationSender(rcov2InvitationSender{}),
		sso.WithInvitationStore(defaultimpl.NewMemoryInvitationStore()),
		sso.WithStorageHealth(sso.StorageHealthSource{
			Name: "memory",
			Ping: func(context.Context) error { return nil },
		}),
		sso.WithAuditRecorder(audit.New(audit.NewMemorySink(4))),
	)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	if srv.Handler() == nil {
		t.Fatal("Handler() returned nil with the cheap option set wired")
	}
}

// rcov2Nonce builds a stateless HMAC DPoP nonce provider for option wiring.
func rcov2Nonce(t *testing.T) sso.DPoPNonceProvider {
	t.Helper()
	p, err := sso.NewHMACNonceProvider(time.Minute)
	if err != nil {
		t.Fatalf("NewHMACNonceProvider: %v", err)
	}
	return p
}

// rcov2InvitationSender is a no-op spi.InvitationSender.
type rcov2InvitationSender struct{}

func (rcov2InvitationSender) SendInvitation(context.Context, string, string, string, string) error {
	return nil
}

// rcov2KeepAuthenticators keeps the authenticators import referenced.
var _ = authenticators.NewMemoryTOTPStore
