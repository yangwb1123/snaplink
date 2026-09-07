package memory

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tokenpolicy"
)

// TestStore_SeedAndList proves New seeds the set and Policies returns it.
func TestStore_SeedAndList(t *testing.T) {
	t.Parallel()
	s := New(
		tokenpolicy.Policy{Name: "a", ClientID: "c1", MaxTTL: time.Minute},
		tokenpolicy.Policy{Name: "b", MaxRefreshDepth: 3},
	)
	got, err := s.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Fatalf("Policies = %+v, want [a b]", got)
	}
}

// TestStore_EmptyIsEmpty proves a store with no seed returns an empty set, not
// an error.
func TestStore_EmptyIsEmpty(t *testing.T) {
	t.Parallel()
	got, err := New().Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Policies = %+v, want empty", got)
	}
}

// TestStore_NewFromSlice proves the ParseYAML-shaped constructor.
func TestStore_NewFromSlice(t *testing.T) {
	t.Parallel()
	in := []tokenpolicy.Policy{{Name: "x"}}
	got, _ := NewFromSlice(in).Policies(context.Background())
	if len(got) != 1 || got[0].Name != "x" {
		t.Fatalf("Policies = %+v", got)
	}
}

func policyFixture(name string) tokenpolicy.Policy {
	return tokenpolicy.Policy{
		Name:              name,
		ClientID:          "client-*",
		Subject:           "svc-*",
		SubjectRoles:      []string{"admin"},
		Scopes:            []string{"openid"},
		MaxTTL:            time.Minute,
		MaxRefreshDepth:   2,
		MaxActiveSessions: 3,
		RequireRenewAfter: 0.5,
		BlockScopeCombos:  [][]string{{"admin:*", "openid"}, {"billing", "offline_access"}},
	}
}

func policyInput() tokenpolicy.PolicyInput {
	return tokenpolicy.PolicyInput{
		ClientID:       "client-app",
		Subject:        "svc-payments",
		SubjectRoles:   []string{"admin"},
		Scopes:         []string{"admin:read", "openid"},
		Kind:           tokenpolicy.KindRefresh,
		RefreshDepth:   2,
		ActiveSessions: 3,
		RequestedTTL:   time.Hour,
	}
}

func mutatePolicy(policy *tokenpolicy.Policy) {
	policy.Name = "mutated"
	policy.SubjectRoles[0] = "guest"
	policy.Scopes[0] = "profile"
	policy.BlockScopeCombos[0][0] = "other:*"
	policy.BlockScopeCombos[1][1] = "other"
	policy.BlockScopeCombos[0] = []string{"other"}
}

func assertPolicySnapshot(t *testing.T, got []tokenpolicy.Policy, want tokenpolicy.Policy) {
	t.Helper()
	if !reflect.DeepEqual(got, []tokenpolicy.Policy{want}) {
		t.Fatalf("Policies = %+v, want %+v", got, []tokenpolicy.Policy{want})
	}
	wantDecision := tokenpolicy.Evaluate(policyInput(), []tokenpolicy.Policy{want})
	gotDecision := tokenpolicy.Evaluate(policyInput(), got)
	if gotDecision != wantDecision {
		t.Fatalf("policy decision = %+v, want %+v", gotDecision, wantDecision)
	}
}

func TestStore_ConstructorsCloneInputs(t *testing.T) {
	t.Parallel()
	constructors := []struct {
		name string
		new  func([]tokenpolicy.Policy) *Store
	}{
		{name: "New", new: func(p []tokenpolicy.Policy) *Store { return New(p...) }},
		{name: "NewFromSlice", new: NewFromSlice},
	}
	for _, tc := range constructors {
		t.Run(tc.name, func(t *testing.T) {
			input := []tokenpolicy.Policy{policyFixture("active")}
			store := tc.new(input)
			mutatePolicy(&input[0])
			input[0] = tokenpolicy.Policy{Name: "replaced"}

			got, err := store.Policies(context.Background())
			if err != nil {
				t.Fatalf("Policies: %v", err)
			}
			assertPolicySnapshot(t, got, policyFixture("active"))
		})
	}
}

func TestStore_ReplaceClonesInput(t *testing.T) {
	t.Parallel()
	store := New(policyFixture("old"))
	input := []tokenpolicy.Policy{policyFixture("replacement")}
	store.Replace(input)
	mutatePolicy(&input[0])
	input[0] = tokenpolicy.Policy{Name: "replaced"}

	got, err := store.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	assertPolicySnapshot(t, got, policyFixture("replacement"))
}

func TestStore_PoliciesReturnsDeepCopy(t *testing.T) {
	t.Parallel()
	store := New(policyFixture("active"))
	got, err := store.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	mutatePolicy(&got[0])
	got[0] = tokenpolicy.Policy{Name: "replaced"}

	current, err := store.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies after output mutation: %v", err)
	}
	assertPolicySnapshot(t, current, policyFixture("active"))
}

func TestStore_ClonesPreserveNilAndEmptySlices(t *testing.T) {
	t.Parallel()
	empty := []string{}
	input := []tokenpolicy.Policy{{
		SubjectRoles:     empty,
		Scopes:           empty,
		BlockScopeCombos: [][]string{nil, {}},
	}}
	got, err := NewFromSlice(input).Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	policy := got[0]
	if policy.SubjectRoles == nil || policy.Scopes == nil || policy.BlockScopeCombos == nil {
		t.Fatalf("non-nil empty slices were not preserved: %+v", policy)
	}
	if policy.BlockScopeCombos[0] != nil || policy.BlockScopeCombos[1] == nil {
		t.Fatalf("nested nil/empty slices were not preserved: %v", policy.BlockScopeCombos)
	}
}

// TestStore_ReplaceIsCopyOnWrite proves Replace swaps the set atomically and a
// slice returned BEFORE a Replace is never mutated by it (the read-only
// contract the hot path relies on).
func TestStore_ReplaceIsCopyOnWrite(t *testing.T) {
	t.Parallel()
	s := New(tokenpolicy.Policy{Name: "old"})
	before, _ := s.Policies(context.Background())

	s.Replace([]tokenpolicy.Policy{{Name: "new1"}, {Name: "new2"}})

	if len(before) != 1 || before[0].Name != "old" {
		t.Fatalf("previously returned slice was mutated: %+v", before)
	}
	after, _ := s.Policies(context.Background())
	if len(after) != 2 || after[0].Name != "new1" {
		t.Fatalf("post-Replace Policies = %+v, want [new1 new2]", after)
	}
}

// TestStore_ConcurrentReadWrite proves the store is race-free under concurrent
// Policies reads and Replace writes (run with -race).
func TestStore_ConcurrentReadWrite(t *testing.T) {
	t.Parallel()
	s := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = s.Policies(context.Background()) }()
		go func() { defer wg.Done(); s.Replace([]tokenpolicy.Policy{{Name: "r"}}) }()
	}
	wg.Wait()
}

// staticProbe pins the interface guard: the memory store satisfies the SPI.
var _ tokenpolicy.Store = (*Store)(nil)
