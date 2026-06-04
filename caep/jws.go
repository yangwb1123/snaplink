package caep

import (
	"encoding/base64"
	"encoding/json"
)

// Compact-JWS helpers for the SET RECEIVER. These do NO cryptography —
// security.VerifyCompactJWS owns signature verification (alg-allowlist,
// kid binding, on-curve checks). These only split the compact form and
// read the unverified header `typ` / payload `iss` needed to SELECT the
// trust bundle and enforce the typ gate. Everything they read is
// re-validated by VerifyCompactJWS (the signature) before any action.

// Asymmetric JWS alg identifiers (RFC 7518 §3.1) the receiver admits by
// default. Defined locally so caep depends only on the shared
// VerifyCompactJWS primitive, not on security's internal alg consts. They
// are PASSED to VerifyCompactJWS, which itself refuses any non-asymmetric
// alg in the allowlist — so `none` and every HS* remain unreachable.
const (
	jwsAlgEdDSA = "EdDSA"
	jwsAlgES256 = "ES256"
	jwsAlgES384 = "ES384"
	jwsAlgES512 = "ES512"
	jwsAlgRS256 = "RS256"
	jwsAlgRS384 = "RS384"
	jwsAlgRS512 = "RS512"
	jwsAlgPS256 = "PS256"
	jwsAlgPS384 = "PS384"
	jwsAlgPS512 = "PS512"
)

// splitCompactJWS splits a 3-segment compact JWS into its decoded header +
// payload JSON bytes. ok=false for anything that is not exactly three
// base64url segments with decodable header + payload. It does NOT decode or
// trust the signature segment (VerifyCompactJWS does, over the raw compact
// string). Returns header/payload so the caller can read the unverified
// `typ` / `iss` for bundle selection only.
func splitCompactJWS(compact string) (header, payload []byte, ok bool) {
	dot1, dot2 := -1, -1
	for i := 0; i < len(compact); i++ {
		if compact[i] != '.' {
			continue
		}
		switch {
		case dot1 < 0:
			dot1 = i
		case dot2 < 0:
			dot2 = i
		default:
			return nil, nil, false // more than two dots
		}
	}
	if dot1 <= 0 || dot2 <= dot1+1 || dot2 == len(compact)-1 {
		return nil, nil, false
	}
	h, err := base64.RawURLEncoding.DecodeString(compact[:dot1])
	if err != nil {
		return nil, nil, false
	}
	p, err := base64.RawURLEncoding.DecodeString(compact[dot1+1 : dot2])
	if err != nil {
		return nil, nil, false
	}
	return h, p, true
}

// headerTypIsSET reports whether the JOSE header declares the SET media
// type (RFC 8417 §2.3, typ "secevent+jwt"). Enforced AFTER signature
// verification so a plain access/id token signed by the same upstream key
// can never be replayed here as a SET — the inverse of the issuers' at+jwt
// typ gate.
func headerTypIsSET(header []byte) bool {
	var h struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		return false
	}
	return h.Typ == SecurityEventTokenTyp
}

// setAudClaim parses the RFC 7519 §4.1.3 `aud` claim — a single string OR
// an array of strings. Local to caep so the receiver doesn't reach into
// security's unexported audClaim type.
type setAudClaim []string

func (a *setAudClaim) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// Contains reports whether want is one of the audiences. The aud-binding
// crux: a SET acts here ONLY if this server's audience is in its aud.
func (a setAudClaim) Contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}
