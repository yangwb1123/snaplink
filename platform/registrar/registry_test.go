package registrar

import (
	"fmt"
	"testing"
)

func TestRegistry_RegisterLookupNames(t *testing.T) {
	reg := New[func() error]()
	first := func() error { return nil }
	second := func() error { return fmt.Errorf("x") }

	reg.Register("a", first)
	reg.Register("b", second)

	got, ok := reg.Lookup("a")
	if !ok {
		t.Fatal("Lookup(a) missing")
	}
	if got == nil {
		t.Fatal("Lookup(a) returned nil")
	}
	if _, ok := reg.Lookup("missing"); ok {
		t.Fatal("Lookup(missing) reported ok")
	}

	names := reg.Names()
	if len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Fatalf("Names() = %v, want [a b]", names)
	}
}

func TestRegistry_RegisterPanicsOnMistakes(t *testing.T) {
	reg := New[func()]()
	ok := func() {}
	cases := []struct {
		name  string
		value func()
		label string
	}{
		{"", ok, "empty name"},
		{"nil", nil, "nil value"},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("Register(%q, <nilable>): want panic", tc.name)
				}
			}()
			reg.Register(tc.name, tc.value)
		})
	}
	reg.Register("dup", ok)
	defer func() {
		if recover() == nil {
			t.Fatal("Register duplicate: want panic")
		}
	}()
	reg.Register("dup", ok)
}

func TestRegistry_NonNilableZeroValueAllowed(t *testing.T) {
	// A struct zero value is a legitimate registered value — only
	// nilable kinds are rejected.
	reg := New[struct{ N int }]()
	reg.Register("zero", struct{ N int }{})
	got, ok := reg.Lookup("zero")
	if !ok || got.N != 0 {
		t.Fatalf("zero-value registration = %v, %v", got, ok)
	}
}
