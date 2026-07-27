package federation_test

import (
	"github.com/yangwb1123/snaplink/domains/federation"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

// Compile-time guards that the three defaultimpl signing issuers satisfy
// federation.JWTSigner via their SignJWT method. These live HERE (federation's
// test, package federation_test) rather than in defaultimpl on purpose: the
// dependency edge must point federation -> defaultimpl, never the reverse.
// defaultimpl is the foundational signing primitive; making it import the
// peripheral federation subsystem just to host an interface guard is a
// backwards coupling and a future-cycle risk. Go's structural typing means the
// issuers satisfy federation.JWTSigner with no guard in defaultimpl; these
// assertions keep the compile-time proof while reversing the import direction
// (federation_test -> defaultimpl is fine; this is a test file, so it adds no
// edge to the federation package's own import graph).
var (
	_ federation.JWTSigner = (*defaultimpl.Ed25519JWTIssuer)(nil)
	_ federation.JWTSigner = (*defaultimpl.ECDSAJWTIssuer)(nil)
	_ federation.JWTSigner = (*defaultimpl.RSAJWTIssuer)(nil)
)
