package txntoken_test

import (
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/protocols/oauth/txntoken"
)

// Compile-time guards that the three defaultimpl signing issuers satisfy
// txntoken.Signer via their SignJWT method. These live HERE (txntoken's
// test, package txntoken_test) rather than in defaultimpl on purpose — the
// SAME reasoning as protocols/caep/jwtsigner_guard_test.go: the dependency
// edge must point txntoken -> defaultimpl, never the reverse. defaultimpl
// is the foundational signing primitive and must not import this
// peripheral package just to host an interface guard. Go's structural
// typing means the issuers already satisfy txntoken.Signer with no guard
// in defaultimpl; these assertions keep the compile-time proof while
// reversing the import direction (test-only, so it adds no edge to
// txntoken's own package import graph).
var (
	_ txntoken.Signer = (*defaultimpl.Ed25519JWTIssuer)(nil)
	_ txntoken.Signer = (*defaultimpl.ECDSAJWTIssuer)(nil)
	_ txntoken.Signer = (*defaultimpl.RSAJWTIssuer)(nil)
)

// Both defaultimpl issuers' JWKS() method also already satisfies
// core.JWKSProvider, so either can back a Validator directly for
// same-process self-validation (the nested-mint case) with no adapter.
