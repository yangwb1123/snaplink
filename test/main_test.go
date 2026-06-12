package ssotest

import (
	"os"
	"testing"

	"github.com/snaplink/sso/defaultimpl"
	"golang.org/x/crypto/bcrypt"
)

// TestMain reduces the bcrypt work factor for the entire integration-test
// suite.  The test harness seeds many clients via AddSeed; at DefaultCost (10)
// each hash takes ~100ms and 170+ seeds would push the suite over any
// reasonable timeout.  MinCost (4) is still a valid bcrypt hash and exercises
// exactly the same code paths — cost only governs how long key-stretching
// runs, not correctness.
func TestMain(m *testing.M) {
	defaultimpl.BcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}
