package oauthvalidate

import (
	"net"
	"net/url"
	"slices"
	"strings"
)

// DCRMetadata is the subset of RFC 7591 §2 client metadata the
// validator inspects. Mirrors the request struct used by /register
// so the SSO server can validate without round-tripping types.
type DCRMetadata struct {
	RedirectURIs            []string
	TokenEndpointAuthMethod string
	GrantTypes              []string
	ResponseTypes           []string
	AllowedAuthenticators   []string
	HasJWKS                 bool
	TLSClientAuthSubjectDN  string
	TLSClientAuthSANDNS     string
	TLSClientAuthSANEmail   string
	TLSClientAuthSANURI     string

	// OIDC Core JWE response-encryption metadata. Validated +
	// defaulted in place (see normalizeAndValidateEncryption) — the
	// caller copies the (possibly defaulted) values back onto the
	// stored Client.
	IDTokenEncryptedResponseAlg  string
	IDTokenEncryptedResponseEnc  string
	UserinfoEncryptedResponseAlg string
	UserinfoEncryptedResponseEnc string

	// IDTokenSignedResponseAlg is the OIDC Core §3.1.3.1 / RFC 7591 §2
	// client metadata naming the JWS algorithm the AS uses to sign THIS
	// client's ID Tokens. Validated against the server's wired signing
	// set (validateIDTokenSigningAlg) — an alg the AS cannot actually
	// produce is rejected at registration, never accepted-then-broken.
	IDTokenSignedResponseAlg string
}

// supportedJWEResponseAlgs / supportedJWEResponseEncs enumerate the
// JWE algorithms the default response encrypter (RSAJWEResponseEncrypter)
// can satisfy. DCR rejects anything outside these so a client can't
// register an alg the AS will silently fail to honor at issuance time.
// Operators wiring a richer JWEEncrypter must extend this list (and the
// discovery advertisement follows the encrypter's SupportedAlgs/Encs).
var (
	supportedJWEResponseAlgs = []string{"RSA-OAEP-256"}
	supportedJWEResponseEncs = []string{"A256GCM"}
)

// DefaultJWEResponseEnc is the `enc` applied when a client registers an
// `*_encrypted_response_alg` without a matching `*_enc`. OIDC Core §10.2
// makes A256GCM the conventional default and it matches the request-
// direction JWE pipeline (RSAJWEDecrypter).
const DefaultJWEResponseEnc = "A256GCM"

// ValidateDCRMetadata enforces the subset of RFC 7591 §2 / §5 rules
// this server understands plus the policy's whitelist constraints.
//
// supportedGrants lists the grant types the AS advertises in
// discovery — caller supplies it (typically core.SupportedGrants) so
// the validator stays a leaf with no upstream imports.
//
// authzCodeGrant is the canonical name of the auth-code grant
// (typically core.GrantAuthorizationCode); the redirect_uris-required
// rule §2 only fires when this is present in or defaults from the
// request's grant_types.
func ValidateDCRMetadata(req *DCRMetadata, policy *DCRPolicy, supportedGrants []string, authzCodeGrant string, supportedIDTokenAlgs []string) error {
	if err := validateRedirectURIs(req, authzCodeGrant); err != nil {
		return err
	}

	switch req.TokenEndpointAuthMethod {
	case "", "client_secret_basic", "client_secret_post", "none",
		"private_key_jwt", "tls_client_auth", "self_signed_tls":
		// supported
	default:
		return ErrDCR("unsupported token_endpoint_auth_method: " + req.TokenEndpointAuthMethod)
	}
	if err := validateClientAuthenticationMetadata(req); err != nil {
		return err
	}

	if err := validateGrantTypes(req, supportedGrants); err != nil {
		return err
	}

	if err := validateResponseTypes(req); err != nil {
		return err
	}

	if err := validateAuthenticatorPolicy(req, policy); err != nil {
		return err
	}

	if err := normalizeAndValidateEncryption(req); err != nil {
		return err
	}

	if err := validateIDTokenSigningAlg(req, supportedIDTokenAlgs); err != nil {
		return err
	}

	return nil
}

// validateIDTokenSigningAlg rejects an id_token_signed_response_alg the
// AS cannot produce: the value must be empty (server default issuer) or in
// the server's wired signing set — the SAME set discovery advertises as
// id_token_signing_alg_values_supported — so a client can never register
// an alg that issuance would fail to honor. "none" and any other JWS
// value outside the wired set are rejected here (and "none" can never be
// wired: the SDK option whitelists security.AsymmetricJWSAlgs only).
func validateIDTokenSigningAlg(req *DCRMetadata, supported []string) error {
	if req.IDTokenSignedResponseAlg == "" {
		return nil
	}
	if !slices.Contains(supported, req.IDTokenSignedResponseAlg) {
		return ErrDCR("unsupported id_token_signed_response_alg: " + req.IDTokenSignedResponseAlg)
	}
	return nil
}

// validateRedirectURIs enforces RFC 7591 §2 redirect_uris rules:
// REQUIRED for grant_type=authorization_code (the default), OPTIONAL for
// client_credentials-only clients, every entry non-empty and safe.
func validateRedirectURIs(req *DCRMetadata, authzCodeGrant string) error {
	wantsCodeFlow := len(req.GrantTypes) == 0 ||
		slices.Contains(req.GrantTypes, authzCodeGrant)
	if wantsCodeFlow && len(req.RedirectURIs) == 0 {
		return ErrDCR("redirect_uris required for authorization_code flow")
	}
	if slices.Contains(req.RedirectURIs, "") {
		return ErrDCR("empty redirect_uri")
	}
	for _, redirectURI := range req.RedirectURIs {
		if !safeRedirectURI(redirectURI) {
			return ErrDCR("unsafe redirect_uri: " + redirectURI)
		}
	}
	return nil
}

func safeRedirectURI(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Fragment != "" || parsed.User != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "https" {
		return parsed.Hostname() != ""
	}
	if scheme == "http" {
		host := strings.ToLower(parsed.Hostname())
		ip := net.ParseIP(host)
		return host == "localhost" || (ip != nil && ip.IsLoopback())
	}
	switch scheme {
	case "about", "blob", "data", "file", "javascript", "vbscript":
		return false
	default:
		return scheme != ""
	}
}

func validateClientAuthenticationMetadata(req *DCRMetadata) error {
	switch req.TokenEndpointAuthMethod {
	case "private_key_jwt", "self_signed_tls":
		if !req.HasJWKS {
			return ErrDCR(req.TokenEndpointAuthMethod + " requires jwks")
		}
	case "tls_client_auth":
		if req.TLSClientAuthSubjectDN == "" && req.TLSClientAuthSANDNS == "" &&
			req.TLSClientAuthSANEmail == "" && req.TLSClientAuthSANURI == "" {
			return ErrDCR("tls_client_auth requires certificate binding metadata")
		}
	}
	return nil
}

// validateGrantTypes rejects any requested grant_type the AS does not
// advertise in discovery. Leaf helper of ValidateDCRMetadata — returns
// the same ErrDCR policy-rejection value (classified via errors.As).
func validateGrantTypes(req *DCRMetadata, supportedGrants []string) error {
	for _, g := range req.GrantTypes {
		if !slices.Contains(supportedGrants, g) {
			return ErrDCR("unsupported grant_type: " + g)
		}
	}
	return nil
}

// validateResponseTypes rejects any response_type outside the set this
// server can satisfy. Leaf helper of ValidateDCRMetadata — returns the
// same ErrDCR policy-rejection value (classified via errors.As).
func validateResponseTypes(req *DCRMetadata) error {
	for _, rt := range req.ResponseTypes {
		switch rt {
		case "code", "token", "":
			// supported
		default:
			return ErrDCR("unsupported response_type: " + rt)
		}
	}
	return nil
}

// validateAuthenticatorPolicy enforces the registration policy's
// authenticator allowlist (no-op when the policy lists none). Leaf
// helper of ValidateDCRMetadata — returns the same ErrDCR
// policy-rejection value (classified via errors.As).
func validateAuthenticatorPolicy(req *DCRMetadata, policy *DCRPolicy) error {
	if len(policy.AllowedAuthenticators) == 0 {
		return nil
	}
	for _, a := range req.AllowedAuthenticators {
		if !slices.Contains(policy.AllowedAuthenticators, a) {
			return ErrDCR("authenticator not permitted by registration policy: " + a)
		}
	}
	return nil
}

// normalizeAndValidateEncryption validates the OIDC JWE response-
// encryption metadata and defaults `enc` to DefaultJWEResponseEnc when
// the corresponding `alg` is set but `enc` is empty. Mutates req in
// place so the caller persists the canonical values. An `enc` without
// an `alg` is rejected (no key-management algorithm to apply).
func normalizeAndValidateEncryption(req *DCRMetadata) error {
	normalize := func(name string, alg, enc *string) error {
		if *alg == "" {
			if *enc != "" {
				return ErrDCR(name + "_encrypted_response_enc set without _alg")
			}
			return nil
		}
		if !slices.Contains(supportedJWEResponseAlgs, *alg) {
			return ErrDCR("unsupported " + name + "_encrypted_response_alg: " + *alg)
		}
		if *enc == "" {
			*enc = DefaultJWEResponseEnc
		}
		if !slices.Contains(supportedJWEResponseEncs, *enc) {
			return ErrDCR("unsupported " + name + "_encrypted_response_enc: " + *enc)
		}
		return nil
	}
	if err := normalize("id_token", &req.IDTokenEncryptedResponseAlg, &req.IDTokenEncryptedResponseEnc); err != nil {
		return err
	}
	return normalize("userinfo", &req.UserinfoEncryptedResponseAlg, &req.UserinfoEncryptedResponseEnc)
}

// ErrDCR wraps a DCR validation failure message as a typed error so
// the /register handler can recognize policy rejection vs other
// errors via errors.As.
func ErrDCR(msg string) error {
	return &dcrError{msg: msg}
}

type dcrError struct{ msg string }

func (e *dcrError) Error() string { return e.msg }
