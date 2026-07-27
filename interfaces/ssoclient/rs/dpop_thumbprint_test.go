package rs

import (
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// TestJWKThumbprintRFC7638_RSAKnownAnswer pins jwkThumbprintRFC7638's RSA
// canonical form (members e/kty/n, lexically ordered, no whitespace) against
// the RFC 7638 §3.1 worked example — the published spec vector, not a
// self-referential recomputation. A wrong member set or order silently
// breaks the DPoP cnf.jkt comparison into either always-fail or (worse)
// always-succeed, so this is a security regression guard, not busywork.
func TestJWKThumbprintRFC7638_RSAKnownAnswer(t *testing.T) {
	t.Parallel()
	const (
		n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
			"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
			"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
			"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
			"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
			"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		e              = "AQAB"
		wantThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	)
	got, err := jwkThumbprintRFC7638(core.JWK{Kty: "RSA", N: n, E: e})
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got != wantThumbprint {
		t.Fatalf("RSA thumbprint = %q, want RFC 7638 §3.1 answer %q", got, wantThumbprint)
	}
}

func TestJWKThumbprintRFC7638_UnsupportedKty(t *testing.T) {
	t.Parallel()
	if _, err := jwkThumbprintRFC7638(core.JWK{Kty: "oct"}); err == nil {
		t.Fatal("expected error for unsupported kty")
	}
}
