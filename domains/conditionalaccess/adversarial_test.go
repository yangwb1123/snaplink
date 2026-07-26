package conditionalaccess

import (
	"context"
	"sync"
	"testing"
)

func TestMemoryStore_Adversarial_ConcurrentPut(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			_ = store.Put(ctx, Policy{
				Name:     "policy-" + itoa(n),
				Priority: n,
			})
		}(i)
	}
	wg.Wait()

	all, _ := store.List(ctx)
	if len(all) != goroutines {
		t.Errorf("expected %d policies, got %d", goroutines, len(all))
	}
}

func TestMemoryStore_Adversarial_ConcurrentUpdateSame(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	_ = store.Put(ctx, Policy{
		Name: "shared", Priority: 1,
	})

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			_ = store.Put(ctx, Policy{
				Name: "shared", Priority: 1,
			})
		}()
	}
	wg.Wait()

	all, _ := store.List(ctx)
	if len(all) != 1 {
		t.Errorf("expected 1 policy after concurrent updates, got %d", len(all))
	}
}

func TestMemoryStore_Adversarial_RacePutDelete(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	for i := range 10 {
		_ = store.Put(ctx, Policy{
			Name: "p-" + itoa(i), Priority: i,
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 20 {
			_, _ = store.List(ctx)
		}
	}()

	go func() {
		defer wg.Done()
		for i := range 10 {
			_ = store.Delete(ctx, "p-"+itoa(i))
		}
	}()

	wg.Wait()
}

func TestMemoryStore_Adversarial_DeleteIdempotent(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	_ = store.Put(ctx, Policy{Name: "temp", Priority: 1})

	// Delete twice
	if err := store.Delete(ctx, "temp"); err != nil {
		t.Fatalf("first Delete: %v", err)
	}
	if err := store.Delete(ctx, "temp"); err != nil {
		t.Fatalf("second Delete: %v", err)
	}

	_, ok, _ := store.Get(ctx, "temp")
	if ok {
		t.Error("expected policy to be deleted")
	}
}

func TestConfigNormalization(t *testing.T) {
	t.Run("default degraded trust", func(t *testing.T) {
		cfg := Config{}
		if dt := cfg.degradedTrust(); dt != DefaultDegradedTrust {
			t.Errorf("expected default degraded trust %f, got %f", DefaultDegradedTrust, dt)
		}
	})

	t.Run("custom degraded trust", func(t *testing.T) {
		cfg := Config{DegradedTrust: 0.7}
		if dt := cfg.degradedTrust(); dt != 0.7 {
			t.Errorf("expected 0.7, got %f", dt)
		}
	})

	t.Run("out of range clamps to default", func(t *testing.T) {
		cfg := Config{DegradedTrust: 1.5}
		if dt := cfg.degradedTrust(); dt != DefaultDegradedTrust {
			t.Errorf("expected clamped to %f, got %f", DefaultDegradedTrust, dt)
		}
	})
}

func TestConditionsSpecificity(t *testing.T) {
	empty := Conditions{}
	one := Conditions{DeviceType: "mobile"}
	two := Conditions{DeviceType: "mobile", DeviceTrustLevel: 0.5}

	if empty.specificity() >= one.specificity() {
		t.Error("expected empty to have lower specificity")
	}
	if one.specificity() >= two.specificity() {
		t.Error("expected one condition to have lower specificity than two")
	}
}

func TestPolicyValidateEdgeCases(t *testing.T) {
	t.Run("empty name fails", func(t *testing.T) {
		p := Policy{Name: "", Priority: 1}
		if err := p.Validate(); err == nil {
			t.Error("expected error for empty name")
		}
	})

	t.Run("valid policy", func(t *testing.T) {
		p := Policy{Name: "test", Priority: 1}
		if err := p.Validate(); err != nil {
			t.Fatalf("expected valid, got: %v", err)
		}
	})

	t.Run("no-op policy is valid", func(t *testing.T) {
		p := Policy{Name: "noop", Priority: 2}
		if err := p.Validate(); err != nil {
			t.Fatalf("no-op policy should be valid: %v", err)
		}
	})
}

func TestCloneStrings(t *testing.T) {
	original := []string{"a", "b", "c"}
	clone := cloneStrings(original)

	if len(clone) != len(original) {
		t.Fatalf("length mismatch: %d vs %d", len(clone), len(original))
	}

	clone[0] = "modified"
	if original[0] != "a" {
		t.Error("original should be unchanged")
	}

	if cloneStrings(nil) != nil {
		t.Error("nil input should return nil")
	}
}

func TestContainsFold(t *testing.T) {
	if !containsFold([]string{"Alice", "Bob"}, "alice") {
		t.Error("expected case-insensitive match")
	}
	if !containsFold([]string{"Alice", "Bob"}, "ALICE") {
		t.Error("expected case-insensitive match for uppercase")
	}
	if containsFold([]string{"Alice", "Bob"}, "Charlie") {
		t.Error("unexpected match")
	}
	if containsFold(nil, "test") {
		t.Error("nil list should not match")
	}
}

func itoa(n int) string {
	if n == 0 { return "0" }
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--; buf[i] = byte('0' + n%10); n /= 10
	}
	return string(buf[i:])
}
