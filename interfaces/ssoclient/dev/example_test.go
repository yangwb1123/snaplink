package dev_test

import (
	"context"
	"fmt"

	"github.com/snaplink/sso/interfaces/ssoclient/dev"
)

// Example demonstrates the "dev" backend (README "3. Consume from a
// downstream app" — dev): an allow-all stub for local development or UI
// work, so business code written against the ssoclient interfaces runs
// end-to-end without a real SSO server. ValidateToken always succeeds and
// returns the configured Subject regardless of the token bytes passed in —
// that is the point.
//
// Every real (non-test) constructor in this package prints a one-time
// "AUTH-BYPASS" warning to stderr so accidental production use is loud;
// [dev.WithSilent] suppresses it here since this example's Output only
// checks stdout.
func Example() {
	client := dev.NewAuthClient(dev.WithSilent(), dev.WithUserID("dev-alice"))

	subject, err := client.ValidateToken(context.Background(), "any-bearer-token-is-accepted")
	if err != nil {
		fmt.Println("validate error:", err)
		return
	}

	fmt.Println(subject.ID, subject.Scopes)
	// Output: dev-alice [openid profile email]
}
