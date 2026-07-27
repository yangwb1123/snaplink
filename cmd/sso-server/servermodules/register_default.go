//go:build !snaplink_configured

// Package servermodules is the explicit composition hook replaced by the
// profile builder when cold modules are selected.
package servermodules

// Register is a no-op in the historical stock build. Configured builds replace
// this file through a constrained Go overlay and call their registrars here.
func Register() {}
