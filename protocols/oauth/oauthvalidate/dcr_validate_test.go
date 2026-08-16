package oauthvalidate

import (
	"errors"
	"testing"
)

var testSupportedGrants = []string{"authorization_code", "client_credentials", "refresh_token"}

// testSupportedIDTokenAlgs is the wired id_token signing set the validator
// tests accept (the server's DCR path passes its live SigningAlgValues).
var testSupportedIDTokenAlgs = []string{"EdDSA", "ES256", "RS256", "PS256"}

var testDCRPolicy = &DCRPolicy{
	AllowedAuthenticators: []string{"password", "totp"},
}

func TestValidateDCRMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     *DCRMetadata
		policy  *DCRPolicy
		wantErr bool
	}{
		{
			name: "valid auth code client",
			req: &DCRMetadata{
				RedirectURIs: []string{"https://example.com/cb"},
				GrantTypes:   []string{"authorization_code"},
			},
			policy:  &DCRPolicy{},
			wantErr: false,
		},
		{
			name: "wired id_token_signed_response_alg accepted",
			req: &DCRMetadata{
				RedirectURIs:             []string{"https://example.com/cb"},
				IDTokenSignedResponseAlg: "RS256",
			},
			policy:  &DCRPolicy{},
			wantErr: false,
		},
		{
			name: "unwired id_token_signed_response_alg rejected",
			req: &DCRMetadata{
				RedirectURIs:             []string{"https://example.com/cb"},
				IDTokenSignedResponseAlg: "HS256",
			},
			policy:  &DCRPolicy{},
			wantErr: true,
		},
		{
			name: "alg none rejected",
			req: &DCRMetadata{
				RedirectURIs:             []string{"https://example.com/cb"},
				IDTokenSignedResponseAlg: "none",
			},
			policy:  &DCRPolicy{},
			wantErr: true,
		},
		{
			name: "valid client credentials client",
			req: &DCRMetadata{
				GrantTypes: []string{"client_credentials"},
			},
			policy:  &DCRPolicy{},
			wantErr: false,
		},
		{
			name:    "missing redirect_uris",
			req:     &DCRMetadata{GrantTypes: []string{"authorization_code"}},
			policy:  &DCRPolicy{},
			wantErr: true,
		},
		{
			name: "empty redirect_uri in list",
			req: &DCRMetadata{
				RedirectURIs: []string{"https://example.com/cb", ""},
				GrantTypes:   []string{"authorization_code"},
			},
			policy:  &DCRPolicy{},
			wantErr: true,
		},
		{
			name: "private key JWT requires JWKS",
			req: &DCRMetadata{
				TokenEndpointAuthMethod: "private_key_jwt",
			},
			policy:  &DCRPolicy{},
			wantErr: true,
		},
		{
			name: "private key JWT with JWKS",
			req: &DCRMetadata{
				TokenEndpointAuthMethod: "private_key_jwt",
				GrantTypes:              []string{"client_credentials"},
				HasJWKS:                 true,
			},
			policy:  &DCRPolicy{},
			wantErr: false,
		},
		{
			name: "tls client auth requires certificate binding",
			req: &DCRMetadata{
				TokenEndpointAuthMethod: "tls_client_auth",
				GrantTypes:              []string{"client_credentials"},
			},
			policy:  &DCRPolicy{},
			wantErr: true,
		},
		{
			name: "tls client auth with subject DN",
			req: &DCRMetadata{
				TokenEndpointAuthMethod: "tls_client_auth",
				TLSClientAuthSubjectDN:  "CN=workload",
				GrantTypes:              []string{"client_credentials"},
			},
			policy:  &DCRPolicy{},
			wantErr: false,
		},
		{
			name: "reject non-loopback HTTP redirect",
			req: &DCRMetadata{
				RedirectURIs: []string{"http://example.com/cb"},
				GrantTypes:   []string{"authorization_code"},
			},
			policy:  &DCRPolicy{},
			wantErr: true,
		},
		{
			name: "allow loopback HTTP redirect",
			req: &DCRMetadata{
				RedirectURIs: []string{"http://127.0.0.1:8765/cb"},
				GrantTypes:   []string{"authorization_code"},
			},
			policy:  &DCRPolicy{},
			wantErr: false,
		},
		{
			name: "supported auth methods",
			req: &DCRMetadata{
				TokenEndpointAuthMethod: "client_secret_post",
				GrantTypes:              []string{"client_credentials"},
			},
			policy:  &DCRPolicy{},
			wantErr: false,
		},
		{
			name: "unsupported grant type",
			req: &DCRMetadata{
				GrantTypes: []string{"implicit"},
			},
			policy:  &DCRPolicy{},
			wantErr: true,
		},
		{
			name: "unsupported response type",
			req: &DCRMetadata{
				GrantTypes:    []string{"authorization_code"},
				RedirectURIs:  []string{"https://example.com/cb"},
				ResponseTypes: []string{"id_token"},
			},
			policy:  &DCRPolicy{},
			wantErr: true,
		},
		{
			name: "authenticator not in policy allowlist",
			req: &DCRMetadata{
				GrantTypes:            []string{"client_credentials"},
				AllowedAuthenticators: []string{"webauthn"},
			},
			policy:  testDCRPolicy,
			wantErr: true,
		},
		{
			name: "authenticator in policy allowlist",
			req: &DCRMetadata{
				GrantTypes:            []string{"client_credentials"},
				AllowedAuthenticators: []string{"password"},
			},
			policy:  testDCRPolicy,
			wantErr: false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDCRMetadata(tc.req, tc.policy, testSupportedGrants, "authorization_code", testSupportedIDTokenAlgs)
			if tc.wantErr {
				if err == nil {
					t.Error("ValidateDCRMetadata() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("ValidateDCRMetadata() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestErrDCR(t *testing.T) {
	t.Parallel()

	err := ErrDCR("invalid metadata")
	if err == nil {
		t.Fatal("ErrDCR() returned nil")
	}
	if err.Error() != "invalid metadata" {
		t.Errorf("ErrDCR().Error() = %q, want %q", err.Error(), "invalid metadata")
	}
	// Should be unwrappable as a *dcrError
	var target *dcrError
	if !errors.As(err, &target) {
		t.Error("ErrDCR() should be a *dcrError")
	}
}

func TestNormalizeAndValidateEncryption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     *DCRMetadata
		wantErr bool
		wantAlg string
		wantEnc string
	}{
		{
			name: "no encryption configured",
			req:  &DCRMetadata{},
		},
		{
			name: "alg without enc defaults enc",
			req: &DCRMetadata{
				IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
			},
			wantAlg: "RSA-OAEP-256",
			wantEnc: "A256GCM",
		},
		{
			name: "alg with explicit enc",
			req: &DCRMetadata{
				IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
				IDTokenEncryptedResponseEnc: "A256GCM",
			},
			wantAlg: "RSA-OAEP-256",
			wantEnc: "A256GCM",
		},
		{
			name: "unsupported alg",
			req: &DCRMetadata{
				IDTokenEncryptedResponseAlg: "RSA1_5",
			},
			wantErr: true,
		},
		{
			name: "unsupported enc",
			req: &DCRMetadata{
				IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
				IDTokenEncryptedResponseEnc: "A128CBC-HS256",
			},
			wantErr: true,
		},
		{
			name: "enc without alg",
			req: &DCRMetadata{
				IDTokenEncryptedResponseEnc: "A256GCM",
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := normalizeAndValidateEncryption(tc.req)
			if tc.wantErr {
				if err == nil {
					t.Error("normalizeAndValidateEncryption() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("normalizeAndValidateEncryption() unexpected error: %v", err)
			}
			if tc.req.IDTokenEncryptedResponseAlg != "" {
				if tc.req.IDTokenEncryptedResponseAlg != tc.wantAlg {
					t.Errorf("alg = %q, want %q", tc.req.IDTokenEncryptedResponseAlg, tc.wantAlg)
				}
				if tc.req.IDTokenEncryptedResponseEnc != tc.wantEnc {
					t.Errorf("enc = %q, want %q", tc.req.IDTokenEncryptedResponseEnc, tc.wantEnc)
				}
			}
		})
	}
}
