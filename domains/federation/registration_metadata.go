package federation

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/snaplink/sso/shared/core"
)

// MetadataToClient derives a core.Client from the POLICY-APPLIED
// openid_relying_party metadata of a validated trust chain. This is the
// federation analogue of the DCR metadata-to-Client mapping (oauth.Handle
// Register): the same RP parameters (redirect_uris, response_types,
// grant_types, scope, token_endpoint_auth_method, jwks/jwks_uri) map to the
// same Client fields — but SOURCED from the chain, not a self-service POST.
//
// entityID is the leaf RP's Entity Identifier (TrustChain.LeafEntityID); it
// becomes Client.ID so RFC 9068 ClientID + every audience/binding check keys
// off the federation identity. jwks is the chain-vouched key set used for
// private_key_jwt / JAR. tenantID stamps the client's tenant affinity (empty =
// any).
//
// Crux: rp is the POLICY-CONSTRAINED map (the trust anchor's metadata_policy
// already bounded it). This function only PROJECTS it — it adds nothing the
// policy didn't permit, so the federation can never exceed the trust anchor's
// constraints. A redirect_uri / response_type / scope the policy stripped is
// simply absent here and the derived Client doesn't carry it (the normal
// authz check then rejects a request for it).
func MetadataToClient(entityID string, rp map[string]any, jwks []core.JWK, tenantID string) (*core.Client, error) {
	if entityID == "" {
		return nil, fmt.Errorf("%w: empty entity id", ErrFederationMetadataInvalid)
	}

	redirectURIs := metaStringSlice(rp, "redirect_uris")
	// An authorization_code RP without a redirect_uri can never complete the
	// flow (the redirect_uri exact-match would always fail). Reject the
	// mapping so the client stays unknown rather than admitting a half-usable
	// client. (A pure client_credentials RP has no end-user redirect; but the
	// automatic-registration value is the interactive authorization_code flow,
	// and admitting a redirect-less client here would only ever fail downstream
	// — so we require at least one redirect_uri for a federation client.)
	if len(redirectURIs) == 0 {
		return nil, fmt.Errorf("%w: no redirect_uris in resolved metadata", ErrFederationMetadataInvalid)
	}

	client := &core.Client{
		ID:           entityID,
		Name:         metaString(rp, "client_name"),
		RedirectURIs: redirectURIs,
		// Scope authorization is bounded by the policy-constrained scope; an RP
		// can only request what the federation policy permitted into its
		// metadata. Empty = the server's default (unrestricted-by-this-source)
		// — but a federation deployment SHOULD pin scope via metadata_policy.
		AllowedScopes: splitScopeString(metaString(rp, "scope")),
		// Active immediately: validation IS the gate (the chain validated). An
		// inactive-by-default posture would defeat automatic registration (the
		// whole point is no human approval step) — the trust decision already
		// happened cryptographically.
		Active:   true,
		TenantID: tenantID,
		// JWKS = the chain-vouched entity keys → private_key_jwt + signed
		// request objects work with NO shared secret. Secret stays EMPTY: a
		// federation client authenticates asymmetrically only (a secret would
		// be an unauthenticated-registration bypass).
		JWKS:       jwks,
		Federation: true,
	}

	// token_endpoint_auth_method: a federation RP authenticates with its
	// chain-vouched keys (private_key_jwt) or, for public-style RPs, "none"
	// (PKCE-protected). Either way there is no secret. We do not reject other
	// declared methods here (the absence of a Secret means client_secret_*
	// simply cannot succeed at /token), but a public RP is marked RequirePKCE
	// so a code interception is mitigated — mirroring DCR's "public clients
	// always PKCE" rule.
	if metaString(rp, "token_endpoint_auth_method") == "none" {
		client.RequirePKCE = true
	}

	return client, nil
}

// ----- resolved-metadata projection helpers -------------------------------
//
// The policy engine returns the openid_relying_party metadata as a
// map[string]any where list values are []any and scalars are typed (string,
// bool, ...). These helpers project that loosely-typed map onto the Client
// fields without panicking on an unexpected shape (a hostile/odd metadata
// value yields an empty/absent field, never a crash) — defense in depth atop
// the policy constraints.

// metaString reads a string-valued member, or "" when absent/non-string.
func metaString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// metaStringSlice reads a string-list member as []string. Accepts the policy
// engine's []any (each element string-coerced) and a plain []string. Non-list
// or non-string elements are dropped. Returns nil when absent/empty.
func metaStringSlice(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}

// splitScopeString splits an OAuth scope string ("openid profile email") into
// its members. Empty in ⇒ nil out (no scope constraint from this source). A
// local splitter so federation depends on neither oauth nor strings-helpers in
// root.
func splitScopeString(scope string) []string {
	var out []string
	start := -1
	for i := 0; i < len(scope); i++ {
		if scope[i] == ' ' || scope[i] == '\t' || scope[i] == '\n' {
			if start >= 0 {
				out = append(out, scope[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, scope[start:])
	}
	return out
}

// parseRPJWKS extracts the inline `jwks` JWK Set from the policy-applied RP
// metadata as []core.JWK. The member is a map[string]any of the RFC 7517 shape
// {"keys": [ {kty,...}, ... ]}; we re-marshal it and unmarshal into the typed
// EntityJWKS (so core.JWK's field tags govern the decode — no hand parsing of
// each key parameter). Returns (nil,nil) when no jwks member is present (an RP
// may legitimately publish only a jwks_uri, not dereferenced here). An error
// is returned only when a jwks member IS present but cannot decode to a
// non-empty key set.
func parseRPJWKS(rp map[string]any) ([]core.JWK, error) {
	if rp == nil {
		return nil, nil
	}
	raw, ok := rp["jwks"]
	if !ok || raw == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal jwks member: %w", err)
	}
	var set EntityJWKS
	if err := json.Unmarshal(encoded, &set); err != nil {
		return nil, fmt.Errorf("decode jwks member: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("jwks member present but empty")
	}
	return set.Keys, nil
}
