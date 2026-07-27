package config

import (
	"context"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"testing"
)

type mockNetworkStore struct {
	policies []netpolicy.Policy
}

func (m *mockNetworkStore) Apply(_ context.Context, p *netpolicy.Policy) (*netpolicy.Policy, error) {
	m.policies = append(m.policies, *p)
	return p, nil
}
func (m *mockNetworkStore) Get(_ context.Context, name string) (*netpolicy.Policy, error) {
	return nil, nil
}
func (m *mockNetworkStore) List(_ context.Context) ([]*netpolicy.Policy, error)     { return nil, nil }
func (m *mockNetworkStore) Delete(_ context.Context, name string) error             { return nil }
func (m *mockNetworkStore) Close() error                                            { return nil }
func (m *mockNetworkStore) Watch(_ context.Context) (<-chan netpolicy.Event, error) { return nil, nil }

func TestApplyNetworkPolicySeeds(t *testing.T) {
	store := &mockNetworkStore{}
	ctx := context.Background()

	seeds := []NetworkPolicySeed{
		{
			Name:     "allow-datacenter",
			CIDRs:    []string{"10.0.0.0/8", "192.168.0.0/16"},
			Priority: 100,
		},
		{
			Name:      "allow-vpn",
			Hostnames: []string{"vpn.example.com"},
			Priority:  50,
		},
	}

	err := ApplyNetworkPolicySeeds(ctx, store, seeds)
	if err != nil {
		t.Fatalf("ApplyNetworkPolicySeeds: %v", err)
	}

	if len(store.policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(store.policies))
	}
	if store.policies[0].Name != "allow-datacenter" {
		t.Errorf("expected 'allow-datacenter', got %q", store.policies[0].Name)
	}
	if len(store.policies[0].CIDRs) != 2 {
		t.Errorf("expected 2 CIDRs, got %d", len(store.policies[0].CIDRs))
	}
}

func TestApplyNetworkPolicySeeds_Empty(t *testing.T) {
	store := &mockNetworkStore{}
	err := ApplyNetworkPolicySeeds(context.Background(), store, nil)
	if err != nil {
		t.Fatalf("ApplyNetworkPolicySeeds nil: %v", err)
	}
	if len(store.policies) != 0 {
		t.Errorf("expected 0 policies for nil seeds, got %d", len(store.policies))
	}
}
