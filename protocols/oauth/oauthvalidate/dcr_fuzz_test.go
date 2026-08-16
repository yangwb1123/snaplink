package oauthvalidate

import (
	"testing"
)

// FuzzValidateDCRMetadata throws arbitrary DCRMetadata configs at the
// real ValidateDCRMetadata and asserts it NEVER panics. Dynamic client
// registration accepts fully attacker-controlled metadata from the
// /register POST body — redirect_uris, grant_types, response_types,
// auth_method, etc. — so a panic on crafted metadata is a remote DoS.
//
// An error return (validation rejection) is the expected outcome for
// most random inputs; only a panic or a wedged reflect/slice is a finding.
func FuzzValidateDCRMetadata(f *testing.F) {
	// Seed corpus: realistic DCR metadata shapes.
	seeds := []*DCRMetadata{
		// Standard auth-code client
		{RedirectURIs: []string{"https://client.example/cb"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "client_secret_basic"},
		// Client-credentials only (no redirect_uris required)
		{GrantTypes: []string{"client_credentials"}, TokenEndpointAuthMethod: "client_secret_post"},
		// Public client (no secret)
		{RedirectURIs: []string{"https://app.example/cb"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none"},
		// With JWE encryption metadata
		{RedirectURIs: []string{"https://client.example/cb"}, IDTokenEncryptedResponseAlg: "RSA-OAEP-256", IDTokenEncryptedResponseEnc: "A256GCM"},
		// With authenticator policy
		{RedirectURIs: []string{"https://client.example/cb"}, AllowedAuthenticators: []string{"password", "webauthn"}},
		// Multiple redirect URIs
		{RedirectURIs: []string{"https://a.example/cb", "https://b.example/cb", "http://localhost:3000/cb"}},
		// Minimal
		{RedirectURIs: []string{"https://example.com/"}},
		// Empty (will fail validation, but must not panic)
		{},
	}
	for _, seed := range seeds {
		f.Add(
			joinStrings(seed.RedirectURIs),
			seed.TokenEndpointAuthMethod,
			joinStrings(seed.GrantTypes),
			joinStrings(seed.ResponseTypes),
			joinStrings(seed.AllowedAuthenticators),
			seed.IDTokenEncryptedResponseAlg,
			seed.IDTokenEncryptedResponseEnc,
			seed.UserinfoEncryptedResponseAlg,
			seed.UserinfoEncryptedResponseEnc,
		)
	}

	policy := &DCRPolicy{
		DefaultActive:         true,
		AllowedAuthenticators: []string{"password", "webauthn", "totp"},
	}
	supportedGrants := []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "urn:openid:params:grant-type:ciba"}

	f.Fuzz(func(t *testing.T,
		redirectURIs, tokenEndpointAuthMethod, grantTypes, responseTypes, allowedAuthenticators,
		idTokenEncAlg, idTokenEncEnc, userinfoEncAlg, userinfoEncEnc string,
	) {
		req := &DCRMetadata{
			RedirectURIs:                 splitStrings(redirectURIs),
			TokenEndpointAuthMethod:      tokenEndpointAuthMethod,
			GrantTypes:                   splitStrings(grantTypes),
			ResponseTypes:                splitStrings(responseTypes),
			AllowedAuthenticators:        splitStrings(allowedAuthenticators),
			IDTokenEncryptedResponseAlg:  idTokenEncAlg,
			IDTokenEncryptedResponseEnc:  idTokenEncEnc,
			UserinfoEncryptedResponseAlg: userinfoEncAlg,
			UserinfoEncryptedResponseEnc: userinfoEncEnc,
		}

		// The contract under test: this MUST NOT panic for any input.
		// An error return is fine and expected for most malformed metadata.
		_ = ValidateDCRMetadata(req, policy, supportedGrants, "authorization_code", []string{"EdDSA", "ES256"})
	})
}

// joinStrings joins a string slice with \x00 so the fuzzer can mutate it
// as a single token and splitStrings recovers the original elements.
func joinStrings(s []string) string {
	if len(s) == 0 {
		return ""
	}
	out := make([]byte, 0, len(s)*32)
	for i, elem := range s {
		if i > 0 {
			out = append(out, '\x00')
		}
		out = append(out, []byte(elem)...)
	}
	return string(out)
}

// splitStrings is the inverse of joinStrings: it splits on \x00
// and discards empty elements (which ValidateDCRMetadata already
// catches as "empty redirect_uri").
func splitStrings(s string) []string {
	if s == "" {
		return nil
	}
	parts := splitOnNull(s)
	// Filter out empty strings that would trigger validation errors
	// trivially — the fuzzer explores more interesting shapes this way.
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitOnNull splits s on \x00 bytes, handling empty string correctly.
func splitOnNull(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\x00' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
