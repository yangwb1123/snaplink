package apiclient

// Claims-matrix verification for `sso-ctl check` (T-8a): JWT decoding, the
// JWKS kid index, and the REQ-3 claims assertions (kid/typ/iss/sub/client_id/
// jti unconditional; scope/aud when requested; tenant_id/roles only when
// declared via --expect-*). Split out of token.go to hold the file within
// the 500-line budget.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// decodeJWT splits a JWT into its base64url-raw header and payload maps.
// No signature verification — the sweep is a truthiness probe, not a
// verifier (that is the resource server's contract).
func decodeJWT(token string) (map[string]any, map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("access token is not a JWT (got %d dot-separated parts)", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		if hb, err = base64.URLEncoding.DecodeString(parts[0]); err != nil {
			return nil, nil, fmt.Errorf("bad base64url header: %v", err)
		}
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if pb, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return nil, nil, fmt.Errorf("bad base64url payload: %v", err)
		}
	}
	header, payload := map[string]any{}, map[string]any{}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, fmt.Errorf("header is not JSON: %v", err)
	}
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, nil, fmt.Errorf("payload is not JSON: %v", err)
	}
	return header, payload, nil
}

// loadJWKS fetches the advertised jwks_uri once and indexes its kids. The
// minted token's kid must be present (a freshly minted token's signing key
// is published). The advertised URL is preflighted (row-2 rule) so a
// malformed value never reaches the HTTP layer, whose url.Error would echo
// it raw.
func (ck *checker) loadJWKS() []string {
	if ck.doc.JWKSURI == "" {
		return []string{"claims: jwks_uri absent from discovery"}
	}
	if err := validateAdvertisedURL(ck.doc.JWKSURI); err != nil {
		return []string{"claims: jwks_uri " + redactURL(ck.doc.JWKSURI) + ": " + err.Error() + "; row failed"}
	}
	client, path := ck.endpointClient(ck.doc.JWKSURI)
	resp, err := client.Get(path)
	if err != nil {
		return []string{"claims: jwks_uri " + redactURL(ck.doc.JWKSURI) + ": " + redactURL(err.Error())}
	}
	raw, rerr := ReadBody(resp)
	if rerr != nil {
		return []string{"claims: jwks_uri " + redactURL(ck.doc.JWKSURI) + ": " + rerr.Error()}
	}
	if resp.StatusCode != http.StatusOK {
		return []string{fmt.Sprintf("claims: jwks_uri %s: status %d, expected 200", redactURL(ck.doc.JWKSURI), resp.StatusCode)}
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []string{"claims: jwks_uri " + redactURL(ck.doc.JWKSURI) + ": invalid JSON"}
	}
	ck.jwks = make(map[string]bool, len(doc.Keys))
	for _, k := range doc.Keys {
		ck.jwks[k.Kid] = true
	}
	return nil
}

// verifyClaims runs the REQ-3 claims matrix. Unconditional claims (kid/typ/
// iss/sub/client_id/jti) are always asserted; scope/aud only when requested;
// tenant_id/roles only when declared via --expect-*. Absence of an
// undeclared claim is never a failure.
func (ck *checker) verifyClaims() []string {
	var diags []string
	h, p := ck.header, ck.payload
	kid, _ := h["kid"].(string)
	if kid == "" {
		diags = append(diags, "claims: kid missing")
	} else if !ck.jwks[kid] {
		diags = append(diags, fmt.Sprintf("claims: kid %q not in JWKS", kid))
	}
	if typ, _ := h["typ"].(string); typ != "at+jwt" {
		diags = append(diags, fmt.Sprintf("claims: typ %q != \"at+jwt\"", typ))
	}
	if iss, _ := p["iss"].(string); iss != ck.doc.Issuer {
		diags = append(diags, fmt.Sprintf("claims: iss %q != discovery issuer %q", redactURL(iss), redactURL(ck.doc.Issuer)))
	}
	if sub, _ := p["sub"].(string); sub != ck.clientID {
		diags = append(diags, fmt.Sprintf("claims: sub %q != %q", sub, ck.clientID))
	}
	if cid, _ := p["client_id"].(string); cid != ck.clientID {
		diags = append(diags, fmt.Sprintf("claims: client_id %q != %q", cid, ck.clientID))
	}
	if jti, _ := p["jti"].(string); jti == "" {
		diags = append(diags, "claims: jti missing")
	}
	if ck.scope != "" {
		got, _ := p["scope"].(string)
		for _, want := range strings.Fields(ck.scope) {
			if !containsToken(got, want) {
				diags = append(diags, fmt.Sprintf("claims: scope %q missing %q", got, want))
			}
		}
	}
	if len(ck.resources) > 0 {
		gotAud := audValues(p["aud"])
		for _, want := range ck.resources {
			if !contains(gotAud, want) {
				diags = append(diags, fmt.Sprintf("claims: aud %s missing %q", redactURL(strings.Join(gotAud, " ")), redactURL(want)))
			}
		}
	}
	if ck.expectTenantID != "" {
		diags = append(diags, ck.verifyTenantID(ck.expectTenantID)...)
	}
	diags = append(diags, ck.verifyRolesClaims()...)
	return diags
}

// verifyTenantID runs the --expect-tenant-id declaration: a matching
// tenant_id passes, an absent one fails with the distinct absent diagnostic,
// and a present-but-different one names both values (observed vs declared).
// Extracted from verifyClaims to hold the function within the 50-line budget.
func (ck *checker) verifyTenantID(want string) []string {
	tid, _ := ck.payload["tenant_id"].(string)
	if tid == want {
		return nil
	}
	if tid == "" {
		return []string{"claims: tenant_id absent"}
	}
	return []string{fmt.Sprintf("claims: tenant_id %q != %q", tid, want)}
}

// verifyRolesClaims runs the conditional roles assertion. roles is a
// wiring-conditional claim: the server emits it only when Subject.Roles is
// non-empty (issue_payload.go non-empty guard + omitempty), and the cc mint
// never resolves Subject.Roles at all. So absence/empty is tolerated under
// --expect-roles (a guaranteed-fail declaration would be a deployment
// landmine), presence requires set equality with the declared set, and
// --expect-no-roles requires absence. A present non-array claim is always a
// failure: a misbehaving server must surface, never be read as absence.
// No roles declaration means no assertion (undeclared claims always pass).
func (ck *checker) verifyRolesClaims() []string {
	if !ck.expectRolesSet && !ck.expectNoRoles {
		return nil
	}
	raw, present := ck.payload["roles"]
	if !present {
		return nil
	}
	roles, ok := raw.([]any)
	if !ok {
		return []string{"claims: roles claim is not an array"}
	}
	if len(roles) == 0 {
		return nil // an empty roles array is absence (omitempty never emits one)
	}
	got := make([]string, 0, len(roles))
	for _, r := range roles {
		s, ok := r.(string)
		if !ok {
			return []string{"claims: roles claim is not an array"}
		}
		got = append(got, s)
	}
	if ck.expectNoRoles {
		return []string{"claims: roles present but --expect-no-roles declared"}
	}
	if !roleSetsEqual(got, ck.expectRoles) {
		return []string{fmt.Sprintf("claims: roles [%s] != declared [%s]", strings.Join(got, " "), strings.Join(ck.expectRoles, " "))}
	}
	return nil
}

// roleSetsEqual reports whether got and want have exactly the same members.
// Roles are a set: order-insensitive, and repetition never equals a
// de-duplicated set of the same names.
func roleSetsEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(want))
	for _, r := range want {
		seen[r]++
	}
	for _, r := range got {
		if seen[r] == 0 {
			return false
		}
		seen[r]--
	}
	return true
}

// audValues normalizes the polymorphic `aud` claim (string or array) to a
// string slice.
func audValues(v any) []string {
	switch t := v.(type) {
	case string:
		if t != "" {
			return []string{t}
		}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// containsToken reports whether a space-separated scope string contains the
// exact scope token.
func containsToken(scope, want string) bool {
	for _, tok := range strings.Fields(scope) {
		if tok == want {
			return true
		}
	}
	return false
}

// contains reports whether a string slice contains the exact value.
func contains(haystack []string, want string) bool {
	for _, v := range haystack {
		if v == want {
			return true
		}
	}
	return false
}
