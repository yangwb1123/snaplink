package serverbuildplatform

import (
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

func TestBuildUserLifecycleBackends(t *testing.T) {
	t.Parallel()
	if store, err := BuildUserLifecycle(config.UserLifecycleConfig{}, nil, ""); err != nil || store != nil {
		t.Fatalf("disabled = (%v, %v), want (nil, nil)", store, err)
	}
	for _, backend := range []string{"", "memory"} {
		store, err := BuildUserLifecycle(config.UserLifecycleConfig{Enabled: true, Backend: backend}, nil, "")
		if err != nil || store == nil {
			t.Errorf("backend %q = (%v, %v), want non-nil memory store", backend, store, err)
		}
	}
	if _, err := BuildUserLifecycle(config.UserLifecycleConfig{Enabled: true, Backend: "postgres"}, nil, ""); err == nil {
		t.Error("postgres without shared pool succeeded")
	}
	if _, err := BuildUserLifecycle(config.UserLifecycleConfig{Enabled: true, Backend: "bogus"}, nil, ""); err == nil {
		t.Error("unknown backend succeeded")
	}
}
