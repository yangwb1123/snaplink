package importcmd

import (
	"strings"
	"testing"
)

func TestContinuationOktaArrayClosingDelimiterRequired(t *testing.T) {
	const incompleteArray = `[{"id":"00u1","profile":{"login":"array@example.com"}}`
	users, err := parseInput("okta", strings.NewReader(incompleteArray))
	if err == nil {
		t.Fatalf("premature EOF accepted at required array closing delimiter: parsed %d user(s)", len(users))
	}
}

func TestContinuationOktaCompleteFramingUnchanged(t *testing.T) {
	const completeArray = `[{"id":"00u1","profile":{"login":"array@example.com","email":"array@example.com"}}]`
	users, err := parseInput("okta", strings.NewReader(completeArray))
	if err != nil {
		t.Fatalf("complete okta array must parse: %v", err)
	}
	if len(users) != 1 || users[0].ID != "okta:00u1" || users[0].Email != "array@example.com" {
		t.Fatalf("complete okta array changed: %+v", users)
	}

	const ndjson = `{"id":"00u2","profile":{"login":"ndjson1@example.com","email":"ndjson1@example.com"}}
{"id":"00u3","profile":{"login":"ndjson2@example.com","email":"ndjson2@example.com"}}
`
	streamUsers, err := parseInput("okta", strings.NewReader(ndjson))
	if err != nil {
		t.Fatalf("valid okta ndjson must parse: %v", err)
	}
	if len(streamUsers) != 2 || streamUsers[0].ID != "okta:00u2" || streamUsers[1].ID != "okta:00u3" {
		t.Fatalf("valid okta ndjson changed: %+v", streamUsers)
	}
}
