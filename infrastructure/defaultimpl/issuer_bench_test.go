package defaultimpl

// Hot-path benchmarks for the JWT issuers — the per-request mint
// (Issue) + verify (Validate) and the JWKS document compute. These are
// the operations a >1k-QPS deployment runs on every token request, so
// they double as a regression guard against a future per-request
// allocation or signing-path regression.
//
// New file, dep-free (std testing only). Each target calls
// b.ReportAllocs() and consumes its result through a package-level sink
// so the compiler cannot elide the work under test.

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// Package-level sinks. Writing each benchmark's result here defeats
// dead-code elimination: the compiler cannot prove the produced token /
// claims / JWKS are unused, so the work inside the loop must run.
var (
	benchTokenSink  *sso.Token
	benchClaimsSink *sso.TokenClaims
	benchJWKSSink   []sso.JWK
	benchErrSink    error
)

// benchSubject is a representative RFC 9068 access-token subject: a
// real end-user login with ClientID (REQUIRED §2.2), an auth_time, and
// an AMR. Scopes are passed separately to Issue.
func benchSubject() *sso.Subject {
	return &sso.Subject{
		ID:       "user-1234567890",
		Provider: "password",
		ClientID: "web-app",
		AuthTime: time.Now(),
		AMR:      []string{"password"},
		Claims: map[string]string{
			"email": "user@example.com",
			"name":  "Example User",
		},
	}
}

var benchScopes = []string{"openid", "profile", "email", "offline_access"}

// ----- Ed25519 (EdDSA) — the default/recommended issuer -----

func BenchmarkEd25519Issue(b *testing.B) {
	iss := NewEd25519JWTIssuer(WithEd25519Issuer("https://sso.example.com"))
	ctx := context.Background()
	sub := benchSubject()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tok, err := iss.Issue(ctx, sub, benchScopes)
		benchTokenSink, benchErrSink = tok, err
	}
}

func BenchmarkEd25519Validate(b *testing.B) {
	iss := NewEd25519JWTIssuer(WithEd25519Issuer("https://sso.example.com"))
	ctx := context.Background()
	tok, err := iss.Issue(ctx, benchSubject(), benchScopes)
	if err != nil {
		b.Fatalf("issue: %v", err)
	}
	raw := tok.AccessToken
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		claims, err := iss.Validate(ctx, raw)
		benchClaimsSink, benchErrSink = claims, err
	}
}

// BenchmarkEd25519IssueValidate covers the full per-request round trip
// (mint then verify) as a single combined hot-path figure.
func BenchmarkEd25519IssueValidate(b *testing.B) {
	iss := NewEd25519JWTIssuer(WithEd25519Issuer("https://sso.example.com"))
	ctx := context.Background()
	sub := benchSubject()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tok, err := iss.Issue(ctx, sub, benchScopes)
		if err != nil {
			b.Fatal(err)
		}
		claims, err := iss.Validate(ctx, tok.AccessToken)
		benchClaimsSink, benchErrSink = claims, err
	}
}

func BenchmarkEd25519JWKS(b *testing.B) {
	iss := NewEd25519JWTIssuer(WithEd25519Issuer("https://sso.example.com"))
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jwks, err := iss.JWKS(ctx)
		benchJWKSSink, benchErrSink = jwks, err
	}
}

// ----- ECDSA (ES256) -----

func BenchmarkECDSAIssue(b *testing.B) {
	iss := NewECDSAJWTIssuer(WithECDSAIssuer("https://sso.example.com"))
	ctx := context.Background()
	sub := benchSubject()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tok, err := iss.Issue(ctx, sub, benchScopes)
		benchTokenSink, benchErrSink = tok, err
	}
}

func BenchmarkECDSAValidate(b *testing.B) {
	iss := NewECDSAJWTIssuer(WithECDSAIssuer("https://sso.example.com"))
	ctx := context.Background()
	tok, err := iss.Issue(ctx, benchSubject(), benchScopes)
	if err != nil {
		b.Fatalf("issue: %v", err)
	}
	raw := tok.AccessToken
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		claims, err := iss.Validate(ctx, raw)
		benchClaimsSink, benchErrSink = claims, err
	}
}

func BenchmarkECDSAJWKS(b *testing.B) {
	iss := NewECDSAJWTIssuer(WithECDSAIssuer("https://sso.example.com"))
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jwks, err := iss.JWKS(ctx)
		benchJWKSSink, benchErrSink = jwks, err
	}
}

// ----- RSA (RS256) — the slowest signer; capacity planners care most -----

func BenchmarkRSAIssue(b *testing.B) {
	iss := NewRSAJWTIssuer(WithRSAIssuer("https://sso.example.com"))
	ctx := context.Background()
	sub := benchSubject()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tok, err := iss.Issue(ctx, sub, benchScopes)
		benchTokenSink, benchErrSink = tok, err
	}
}

func BenchmarkRSAValidate(b *testing.B) {
	iss := NewRSAJWTIssuer(WithRSAIssuer("https://sso.example.com"))
	ctx := context.Background()
	tok, err := iss.Issue(ctx, benchSubject(), benchScopes)
	if err != nil {
		b.Fatalf("issue: %v", err)
	}
	raw := tok.AccessToken
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		claims, err := iss.Validate(ctx, raw)
		benchClaimsSink, benchErrSink = claims, err
	}
}

func BenchmarkRSAJWKS(b *testing.B) {
	iss := NewRSAJWTIssuer(WithRSAIssuer("https://sso.example.com"))
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jwks, err := iss.JWKS(ctx)
		benchJWKSSink, benchErrSink = jwks, err
	}
}
