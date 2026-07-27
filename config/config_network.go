package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/platform/netpolicy/memory"
)

// NetworkConfig configures the network-classification control plane.
//
//   - Enabled=true wires a Store and Classifier into the Server.
//   - APIEnabled=true additionally mounts the REST endpoints
//     (/api/v1/netpolicy/...).
//   - Store selects the backend; "memory" (default) is in-process, "etcd"
//     reads from an etcd cluster (see EtcdEndpoints below). The etcd
//     backend is materialized by cmd/sso-server, NOT by [Config.BuildNetworkStore]
//     — the config package keeps the etcd transitive dep out of the SPI.
//   - Policies is the seed list applied at startup. Operators can also add /
//     update / delete policies live via the API.
type NetworkConfig struct {
	Enabled         bool                `yaml:"enabled"`
	APIEnabled      bool                `yaml:"api_enabled"`
	Store           string              `yaml:"store"` // "memory" | "etcd"
	EtcdEndpoints   []string            `yaml:"etcd_endpoints"`
	EtcdPrefix      string              `yaml:"etcd_prefix"`
	EtcdDialTimeout time.Duration       `yaml:"etcd_dial_timeout"`
	EtcdUsername    string              `yaml:"etcd_username"`
	EtcdPassword    string              `yaml:"etcd_password"`
	Policies        []NetworkPolicySeed `yaml:"policies"`
}

// NetworkPolicySeed is the YAML projection of netpolicy.Policy with only the
// fields operators are allowed to set declaratively.
type NetworkPolicySeed struct {
	Name                string            `yaml:"name"`
	CIDRs               []string          `yaml:"cidrs"`
	Hostnames           []string          `yaml:"hostnames"`
	Priority            int32             `yaml:"priority"`
	AdvertisedBaseURL   string            `yaml:"advertised_base_url"`
	AdvertisedJWKSURL   string            `yaml:"advertised_jwks_url"`
	AdvertisedLogoutURL string            `yaml:"advertised_logout_url"`
	Metadata            map[string]string `yaml:"metadata"`
}

// BuildNetworkStore returns a netpolicy.Store configured per NetworkConfig
// and seeds it with the declared policies. Returns nil when network is
// disabled. Callers own the returned store's lifetime — Close it at
// shutdown.
//
// The etcd backend intentionally errors here so the config package stays
// free of the etcd transitive dep. Operators wiring network.store=etcd
// MUST construct the [netpolicy/etcd.Store] inside cmd/sso-server (or
// any embedder) and feed seeds through [ApplyNetworkPolicySeeds].
func (c *Config) BuildNetworkStore() (netpolicy.Store, error) {
	if !c.Network.Enabled {
		return nil, nil
	}
	var store netpolicy.Store
	switch strings.ToLower(c.Network.Store) {
	case "", "memory":
		store = memory.New()
	case "etcd":
		return nil, errors.New("config: network.store=etcd: construct via cmd/sso-server directly (needs endpoints + dial timeout)")
	default:
		return nil, fmt.Errorf("config: unknown network.store %q", c.Network.Store)
	}
	if err := ApplyNetworkPolicySeeds(context.Background(), store, c.Network.Policies); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

// ApplyNetworkPolicySeeds applies declarative NetworkPolicySeed entries
// to any netpolicy.Store via its [netpolicy.Store.Apply] method. Used
// by [Config.BuildNetworkStore] for the memory path and by cmd
// directly for the etcd path so both stay in lockstep on seed
// semantics + error wrapping.
//
// Returns a wrapped error identifying the offending policy on the
// first failure; the caller is responsible for closing the partially
// populated store.
func ApplyNetworkPolicySeeds(ctx context.Context, store netpolicy.Store, seeds []NetworkPolicySeed) error {
	for _, seed := range seeds {
		if _, err := store.Apply(ctx, &netpolicy.Policy{
			Name:                seed.Name,
			CIDRs:               seed.CIDRs,
			Hostnames:           seed.Hostnames,
			Priority:            seed.Priority,
			AdvertisedBaseURL:   seed.AdvertisedBaseURL,
			AdvertisedJWKSURL:   seed.AdvertisedJWKSURL,
			AdvertisedLogoutURL: seed.AdvertisedLogoutURL,
			Metadata:            seed.Metadata,
		}); err != nil {
			return fmt.Errorf("config: seed policy %q: %w", seed.Name, err)
		}
	}
	return nil
}
