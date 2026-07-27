package caep_test

import (
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/protocols/caep"
)

// Compile-time guards that the three defaultimpl signing issuers satisfy
// caep.JWTSigner via their SignJWT method. These live HERE (caep's test,
// package caep_test) rather than in defaultimpl on purpose: the dependency
// edge must point caep -> defaultimpl, never the reverse. defaultimpl is the
// foundational signing primitive; making it import the peripheral caep
// subsystem just to host an interface guard is a backwards coupling and a
// future-cycle risk if caep ever needs defaultimpl in non-test code. Go's
// structural typing means the issuers satisfy caep.JWTSigner with no guard in
// defaultimpl; these assertions keep the compile-time proof while reversing
// the import direction (caep_test -> defaultimpl is fine; this is a test file,
// so it adds no edge to the caep package's own import graph).
var (
	_ caep.JWTSigner = (*defaultimpl.Ed25519JWTIssuer)(nil)
	_ caep.JWTSigner = (*defaultimpl.ECDSAJWTIssuer)(nil)
	_ caep.JWTSigner = (*defaultimpl.RSAJWTIssuer)(nil)
)
