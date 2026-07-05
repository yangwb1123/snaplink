package defaultimpl_test

import (
	"context"
	"fmt"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// Example demonstrates the default Ed25519 JWT issuer — the TokenIssuer
// most commonly wired via sso.WithTokenIssuer / sso.WithIDTokenIssuer (see
// interfaces/sso/example_test.go's Example_minimumViable): sign an access
// token for a Subject + scope list, then validate it back into
// sso.TokenClaims the way a resource server or ssoclient/local.AuthClient
// would.
func Example() {
	issuer := defaultimpl.NewEd25519JWTIssuer()

	token, err := issuer.Issue(context.Background(), &sso.Subject{
		ID: "user-alice",
	}, []string{"openid", "profile"})
	if err != nil {
		fmt.Println("issue error:", err)
		return
	}

	claims, err := issuer.Validate(context.Background(), token.AccessToken)
	if err != nil {
		fmt.Println("validate error:", err)
		return
	}

	fmt.Println(claims.Subject, claims.Scopes, token.TokenType)
	// Output: user-alice [openid profile] Bearer
}
