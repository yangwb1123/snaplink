package tokenexchange

import "testing"

func TestEvaluate_DefaultAllowNoRules(t *testing.T) {
	if !Evaluate(Hop{SubjectID: "alice"}, nil, true) {
		t.Fatal("want allow (no rules, defaultAllow=true)")
	}
	if Evaluate(Hop{SubjectID: "alice"}, nil, false) {
		t.Fatal("want deny (no rules, defaultAllow=false)")
	}
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	rules := []Rule{
		{Name: "block-b-acting-for-a", SubjectID: "a", ActorSubject: "b", Deny: true},
		{Name: "allow-everything-else", Deny: false},
	}
	if Evaluate(Hop{SubjectID: "a", ActorSubject: "b"}, rules, true) {
		t.Fatal("want deny: exact subject+actor match on a Deny rule")
	}
	if !Evaluate(Hop{SubjectID: "a", ActorSubject: "c"}, rules, true) {
		t.Fatal("want allow: actor c does not match the deny rule, falls to the catch-all allow rule")
	}
}

func TestEvaluate_WildcardFieldsMatchAny(t *testing.T) {
	// A rule with only ClientID set should match regardless of subject/actor.
	rules := []Rule{{ClientID: "svc-b", Deny: true}}
	if Evaluate(Hop{SubjectID: "x", ActorSubject: "y", ClientID: "svc-b"}, rules, true) {
		t.Fatal("want deny: ClientID matches, other fields wildcard")
	}
	if !Evaluate(Hop{SubjectID: "x", ActorSubject: "y", ClientID: "svc-c"}, rules, true) {
		t.Fatal("want allow: ClientID does not match the rule")
	}
}

func TestEvaluate_AllowRuleShortCircuits(t *testing.T) {
	rules := []Rule{
		{SubjectID: "a", Deny: false}, // explicit allow
		{SubjectID: "a", Deny: true},  // would deny, but never reached
	}
	if !Evaluate(Hop{SubjectID: "a"}, rules, false) {
		t.Fatal("want allow: first matching rule (allow) wins over the later deny rule")
	}
}
