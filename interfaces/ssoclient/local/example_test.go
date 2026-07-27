package local_test

import (
	"context"
	"fmt"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/local"
)

// Example demonstrates the "embed the SDK in-process" consumer mode
// (README "3. Consume from a downstream app" — local backend): a downstream
// app constructs its ssoclient.AuthClient directly from the same
// sso.TokenIssuer the embedded SSO server signs tokens with, so token
// verification happens in-process — no network round-trip, no JWKS cache to
// keep warm, because there is no separate SSO process to call.
func Example() {
	// In a real app this is the same *defaultimpl.Ed25519JWTIssuer instance
	// passed to sso.WithTokenIssuer when constructing the embedded server.
	issuer := defaultimpl.NewEd25519JWTIssuer()

	token, err := issuer.Issue(context.Background(), &sso.Subject{
		ID: "user-alice",
	}, []string{"openid", "profile"})
	if err != nil {
		fmt.Println("issue error:", err)
		return
	}

	client := local.NewAuthClient(issuer)
	subject, err := client.ValidateToken(context.Background(), token.AccessToken)
	if err != nil {
		fmt.Println("validate error:", err)
		return
	}

	fmt.Println(subject.ID, subject.Scopes)
	// Output: user-alice [openid profile]
}
