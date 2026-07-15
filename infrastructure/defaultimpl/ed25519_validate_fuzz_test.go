package defaultimpl

import (
	"context"
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
)

// FuzzEd25519Validate drives Ed25519JWTIssuer.Validate with an arbitrary
// "token" string — the shape an attacker fully controls via any inbound
// Authorization: Bearer header. The only contract under fuzz is "never
// panic, never hang": parseAndGuardHeader/decodeAndCheckClaims run BEFORE
// signature verification (RFC 9068 §4 alg-confusion defense — see the
// doc on parseAndGuardHeader), so malformed base64, malformed/deeply
// nested JSON, alg=none, and algorithm-confusion variants must all fail
// closed without ever reaching a crash or an unbounded allocation.
func FuzzEd25519Validate(f *testing.F) {
	j := NewEd25519JWTIssuer(WithEd25519Issuer("fuzz-issuer"))
	// Seed with a genuinely valid token plus the classic malformed shapes.
	ctx := context.Background()
	valid, err := j.Issue(ctx, &sso.Subject{ID: "fuzz-user", ClientID: "fuzz-client"}, []string{"read"})
	if err != nil {
		f.Fatalf("seed Issue: %v", err)
	}
	seeds := []string{
		valid.AccessToken,
		"",
		".",
		"..",
		"a.b.c",
		"a.b.c.d",
		`eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.`, // alg=none
		`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln`,                    // alg=HS256 confusion
		`eyJhbGciOiJFZERTQSIsInR5cCI6WyJKV1QiXX0.eyJzdWIiOiJhIn0.c2ln`, // typ as array
		`{"alg":"EdDSA"}`, // not base64 at all, raw JSON with dots missing
		"\x00.\x00.\x00",
		"eyJhbGciOiJFZERTQSJ9." + string(make([]byte, 0)) + ".",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, token string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Validate panicked on token %q: %v", token, r)
			}
		}()
		_, _ = j.Validate(ctx, token)
	})
}
