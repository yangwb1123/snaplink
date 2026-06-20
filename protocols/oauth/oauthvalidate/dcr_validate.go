package oauthvalidate

import (
	"slices"
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

	// OIDC Core JWE response-encryption metadata. Validated +
	// defaulted in place (see normalizeAndValidateEncryption) — the
	// caller copies the (possibly defaulted) values back onto the
	// stored Client.
	IDTokenEncryptedResponseAlg  string
	IDTokenEncryptedResponseEnc  string
	UserinfoEncryptedResponseAlg string
	UserinfoEncryptedResponseEnc string
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
func ValidateDCRMetadata(req *DCRMetadata, policy *DCRPolicy, supportedGrants []string, authzCodeGrant string) error {
	// redirect_uris is REQUIRED for grant_type=authorization_code
	// (the default), OPTIONAL for client_credentials-only clients
	// (per §2 — "redirect_uris is OPTIONAL ... If the grant types
	// supported include authorization_code or implicit, then this
	// metadata REQUIRED").
	wantsCodeFlow := len(req.GrantTypes) == 0 ||
		slices.Contains(req.GrantTypes, authzCodeGrant)
	if wantsCodeFlow && len(req.RedirectURIs) == 0 {
		return ErrDCR("redirect_uris required for authorization_code flow")
	}

	if slices.Contains(req.RedirectURIs, "") {
		return ErrDCR("empty redirect_uri")
	}

	switch req.TokenEndpointAuthMethod {
	case "", "client_secret_basic", "client_secret_post", "none":
		// supported
	default:
		return ErrDCR("unsupported token_endpoint_auth_method: " + req.TokenEndpointAuthMethod)
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
