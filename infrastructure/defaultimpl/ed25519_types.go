package defaultimpl

import (
	"encoding/json"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

type ed25519Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type ed25519Payload struct {
	Iss   string            `json:"iss,omitempty"`
	Sub   string            `json:"sub,omitempty"`
	Aud   audClaim          `json:"aud,omitempty"`
	Exp   int64             `json:"exp,omitempty"`
	Nbf   int64             `json:"nbf,omitempty"`
	Iat   int64             `json:"iat,omitempty"`
	Scope string            `json:"scope,omitempty"`
	Extra map[string]string `json:"ext,omitempty"`

	// RFC 9068 §2.2 access-token claims.
	ClientID string             `json:"client_id,omitempty"`
	JTI      string             `json:"jti,omitempty"`
	AuthTime int64              `json:"auth_time,omitempty"`
	ACR      string             `json:"acr,omitempty"`
	AMR      []string           `json:"amr,omitempty"`
	SID      string             `json:"sid,omitempty"`
	CNF      *confirmationClaim `json:"cnf,omitempty"`

	// RFC 9396 — Rich Authorization Requests. Pass-through of
	// the original `authorization_details` array as raw JSON so
	// extension fields survive without an explicit schema here.
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`

	// RFC 8693 §4.1 `act` claim for delegation chains. Populated
	// by the token-exchange grant when an actor_token is
	// presented; nil for direct (non-delegated) tokens.
	Act *actClaim `json:"act,omitempty"`

	// RequestedClaims carries the OIDC Core §5.5 `claims` parameter
	// so /userinfo can project RP-requested claims from the token.
	RequestedClaims json.RawMessage `json:"_claims_,omitempty"`
}

// confirmationClaim is RFC 7800 §3.1's `cnf` JSON object. RFC 9449
// §6 uses the `jkt` member to carry a DPoP key's JWK thumbprint;
// RFC 8705 §3.1 uses `x5t#S256` to carry the mTLS client cert
// thumbprint. A single token uses one mechanism — both fields
// populated simultaneously would be a caller bug.
type confirmationClaim struct {
	JKT     string `json:"jkt,omitempty"`
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// actClaim is the wire shape of `act`. Per RFC 8693 §4.1 the
// claim is a JSON object with at least `sub` and an optional
// nested `act` for multi-hop delegation chains. Mirrors
// sso.ActorClaim's structure on the public API side.
type actClaim struct {
	Sub string    `json:"sub,omitempty"`
	Act *actClaim `json:"act,omitempty"`
}

// actorChainToWire walks an sso.ActorClaim chain (outermost-first)
// into the wire-shape actClaim chain. nil-safe — returns nil so
// "no delegation" stays distinguishable from "empty chain" in the
// emitted JWT.
func actorChainToWire(a *sso.ActorClaim) *actClaim {
	if a == nil || a.Subject == "" {
		return nil
	}
	return &actClaim{Sub: a.Subject, Act: actorChainToWire(a.Actor)}
}

// wireChainToActor is the inverse: rebuild the sso.ActorClaim
// chain from a validated JWT's act tree. nil-safe.
func wireChainToActor(a *actClaim) *sso.ActorClaim {
	if a == nil || a.Sub == "" {
		return nil
	}
	return &sso.ActorClaim{Subject: a.Sub, Actor: wireChainToActor(a.Act)}
}

// audClaim handles RFC 7519 §4.1.3's polymorphic `aud` claim. Per
// the spec it's "an array of case-sensitive strings"; "in the
// special case when the JWT has one audience, the aud value MAY be
// a single case-sensitive string." OIDC ID tokens favor the
// single-string form; access tokens here favor the array form.
// Tolerating both lets one Validate path handle every shape.
type audClaim []string

func (a *audClaim) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*a = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

func (a audClaim) MarshalJSON() ([]byte, error) {
	// Single-audience tokens stay compact-string per OIDC convention;
	// multi-audience marshals as an array.
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// ed25519IDPayload is the ID-Token-specific claim set, distinct from
// access tokens because OIDC names some fields differently (aud is a
// scalar string when single-valued in many real deployments; auth_time
// is a first-class claim; nonce/amr/acr/azp are OIDC-specific).
type ed25519IDPayload struct {
	Iss      string            `json:"iss,omitempty"`
	Sub      string            `json:"sub,omitempty"`
	Aud      string            `json:"aud,omitempty"`
	Exp      int64             `json:"exp,omitempty"`
	Iat      int64             `json:"iat,omitempty"`
	Nonce    string            `json:"nonce,omitempty"`
	AtHash   string            `json:"at_hash,omitempty"`
	DsHash   string            `json:"ds_hash,omitempty"`
	AuthTime int64             `json:"auth_time,omitempty"`
	AMR      []string          `json:"amr,omitempty"`
	ACR      string            `json:"acr,omitempty"`
	AZP      string            `json:"azp,omitempty"`
	SID      string            `json:"sid,omitempty"`
	Extra    map[string]string `json:"ext,omitempty"`
}
