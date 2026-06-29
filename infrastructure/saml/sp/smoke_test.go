package sp

import (
	"context"
	"testing"
	"time"
)

// TestSmoke_HappyPath is a minimal end-to-end check that the test minter
// produces an assertion the real validator accepts — the foundation every
// adversarial test builds on. (Kept separate so a minter regression is obvious.)
func TestSmoke_HappyPath(t *testing.T) {
	t.Parallel()
	const (
		idpEntity = "https://idp.example.com"
		spEntity  = "https://sp.example.com/saml/metadata"
		acsURL    = "https://sp.example.com/auth/saml/callback"
	)
	signer := newIDPKeypair(t)
	now := time.Now()
	a := newTestSP(t, signer, idpEntity, spEntity, acsURL, now)

	resp := mintValidResponse(t, defaultAssertionParams(idpEntity, spEntity, acsURL), signer, acsURL)

	res, err := a.ProcessAssertion(context.Background(), resp, "")
	if err != nil {
		t.Fatalf("ProcessAssertion(valid) = %v, want success", err)
	}
	if res.ExternalID != "alice@example.com" {
		t.Errorf("ExternalID = %q, want alice@example.com", res.ExternalID)
	}
}
