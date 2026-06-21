package main

import "testing"

// assertPanic asserts that f panics; shared test helper for the cmd wiring tests.
func assertPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected panic, got none", what)
		}
	}()
	f()
}
