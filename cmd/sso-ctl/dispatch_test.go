package main

import "testing"

// TestSubcommands_GenerateIsWired is the regression test for a bug where
// cmd/sso-ctl/generate (a fully implemented, tested scaffolding subcommand)
// was never registered in the subcommands dispatch table — sso-ctl generate
// could never actually be invoked despite the package existing and working.
func TestSubcommands_GenerateIsWired(t *testing.T) {
	if _, ok := subcommands["generate"]; !ok {
		t.Fatal(`subcommands["generate"] is not registered — "sso-ctl generate ..." is unreachable`)
	}
}

// TestSubcommands_EveryEntryHasARunFunc is a broad sanity guard: every
// registered subcommand must have a non-nil Run function, so a future
// refactor can't silently register a nil entry.
func TestSubcommands_EveryEntryHasARunFunc(t *testing.T) {
	for name, run := range subcommands {
		if run == nil {
			t.Errorf("subcommands[%q] is nil", name)
		}
	}
}
