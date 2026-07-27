package memory

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tokenexchange"
)

func TestStore_AllowDefaultAndRules(t *testing.T) {
	s := New(true, tokenexchange.Rule{SubjectID: "a", ActorSubject: "b", Deny: true})
	ok, err := s.Allow(context.Background(), tokenexchange.Hop{SubjectID: "a", ActorSubject: "b"})
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if ok {
		t.Fatal("want deny for a<-b hop")
	}
	ok, err = s.Allow(context.Background(), tokenexchange.Hop{SubjectID: "a", ActorSubject: "z"})
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !ok {
		t.Fatal("want allow (defaultAllow, no matching rule)")
	}
}

func TestStore_Replace(t *testing.T) {
	s := New(true)
	if rules := s.Rules(); len(rules) != 0 {
		t.Fatalf("want empty initial rules, got %d", len(rules))
	}
	s.Replace([]tokenexchange.Rule{{SubjectID: "a", Deny: true}})
	ok, _ := s.Allow(context.Background(), tokenexchange.Hop{SubjectID: "a"})
	if ok {
		t.Fatal("want deny after Replace installed a deny rule")
	}
}

var _ tokenexchange.Policy = (*Store)(nil)
