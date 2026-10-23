package importcmd

import (
	"strings"
	"testing"
)

func TestBatchContinuationR011B(t *testing.T) {
	const valid = `[{"user_id":"auth0|r011b","email":"r011b@example.com"}]`

	t.Run("accept-array-with-json-whitespace", func(t *testing.T) {
		users, err := parseInput("auth0", strings.NewReader(" \n\t"+valid+"\r\n\t "))
		if err != nil {
			t.Fatalf("parseInput(auth0) rejected one array plus JSON whitespace: %v", err)
		}
		if len(users) != 1 || users[0].Email != "r011b@example.com" {
			t.Fatalf("parseInput(auth0) users = %+v; want the one array user", users)
		}
	})

	for _, tc := range []struct {
		name  string
		input string
	}{
		{"second-array-document", valid + ` [{"user_id":"auth0|extra"}]`},
		{"second-object-document", valid + ` {"user_id":"auth0|extra"}`},
		{"trailing-junk", valid + ` not-json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users, err := parseInput("auth0", strings.NewReader(tc.input))
			if err == nil {
				t.Fatalf("R011B_AUTH0_TRAILING_DOCUMENT_MUST_FAIL: parseInput accepted %s and returned %d users", tc.name, len(users))
			}
			if users != nil {
				t.Fatalf("R011B_AUTH0_TRAILING_DOCUMENT_RETURNED_PARTIAL_USERS: parseInput returned %d users with error %v", len(users), err)
			}
		})
	}
}
