package federation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Compact-JWS helpers for the trust-chain resolver. These do the UNVERIFIED
// structural decode the walk needs to NAVIGATE (read authority_hints / jwks /
// fetch endpoint) and the JOSE typ gate the validator applies BEFORE the
// signature check. The actual signature verification is always
// security.VerifyCompactJWS — these never verify a signature, so reading a
// payload here grants no trust.

// splitCompactJWS splits a 3-segment compact JWS into its header, payload, and
// signature segments. Mirrors the segment-count discipline of
// security.VerifyCompactJWS (exactly two dots, non-empty trailing segment) so a
// malformed token is rejected the same way at parse time.
func splitCompactJWS(compact string) (headerSeg, payloadSeg, sigSeg string, err error) {
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
			return "", "", "", errors.New("federation: not a 3-segment compact JWS")
		}
	}
	if dot1 < 0 || dot2 < 0 || dot2 == len(compact)-1 {
		return "", "", "", errors.New("federation: not a 3-segment compact JWS")
	}
	return compact[:dot1], compact[dot1+1 : dot2], compact[dot2+1:], nil
}

// unverifiedPayload returns the base64url-decoded payload bytes of a compact
// JWS WITHOUT verifying the signature. Used only to parse claims for the walk;
// the trust decision is the later VerifyCompactJWS.
func unverifiedPayload(compact string) ([]byte, error) {
	_, payloadSeg, _, err := splitCompactJWS(compact)
	if err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadSeg)
	if err != nil {
		return nil, fmt.Errorf("federation: payload decode: %w", err)
	}
	return payload, nil
}

// jwsHeaderTyp returns the JOSE `typ` header of a compact JWS WITHOUT verifying
// the signature. Used to gate a token's type BEFORE the signature check (so a
// token of the wrong shape signed by the right key is rejected early), shared by
// the entity-statement typ gate and the §7 trust-mark typ gate.
func jwsHeaderTyp(compact string) (string, error) {
	headerSeg, _, _, err := splitCompactJWS(compact)
	if err != nil {
		return "", err
	}
	hb, err := base64.RawURLEncoding.DecodeString(headerSeg)
	if err != nil {
		return "", fmt.Errorf("federation: header decode: %w", err)
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return "", fmt.Errorf("federation: header parse: %w", err)
	}
	return h.Typ, nil
}

// requireEntityStatementTyp asserts the JOSE `typ` header is
// entity-statement+jwt (OpenID Federation 1.0 §3.1) BEFORE any signature
// check, so a plain access/id token signed by the same key can never be
// accepted as a federation statement (the typ gate, mirroring the issuers'
// at+jwt discipline and the inverse of the slice-1 emit typ).
func requireEntityStatementTyp(compact string) error {
	typ, err := jwsHeaderTyp(compact)
	if err != nil {
		return err
	}
	if typ != EntityStatementTyp {
		return fmt.Errorf("federation: typ %q != %q", typ, EntityStatementTyp)
	}
	return nil
}
