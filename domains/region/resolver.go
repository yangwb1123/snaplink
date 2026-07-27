package region

import (
	"net/http"

	"github.com/yangwb1123/snaplink/shared/security/peertrust"
)

// DefaultServingRegionHeader is the request header HeaderResolver reads
// when none is configured. Only trust this header behind a known edge that
// strips any client-supplied copy and re-sets it from trusted state — the
// same X-Forwarded-* / X-Auth-* threat model AGENTS.md §2 governs. An
// allowlist on the resolver is the in-process backstop against an injected
// value.
const DefaultServingRegionHeader = "X-Serving-Region"

// ConfigPinnedResolver always resolves to a single operator-configured
// region. This is the single-region deployment's resolver: every request
// served by this binary is in Region. A zero-value ("") Region resolves to
// "" (unconstrained), so a pinned resolver is nil-safe to wire even before
// the operator has chosen a region.
type ConfigPinnedResolver struct {
	Region ID
}

// Resolve returns the pinned region unconditionally.
func (c ConfigPinnedResolver) Resolve(*http.Request) (ID, error) {
	return c.Region, nil
}

// HeaderResolver reads the serving region from a request header (an edge /
// mesh that pins traffic to a regional deployment sets it). It is hardened
// against header injection: when Allowed is non-empty, a header value not
// in the set is rejected (returns Default, not the injected value); when
// Allowed is empty, any non-empty value passes through. A missing header
// falls back to Default.
type HeaderResolver struct {
	// Header is the request header to read. Empty uses
	// DefaultServingRegionHeader.
	Header string

	// Allowed, when non-empty, restricts accepted header values to this
	// set — a value outside it is treated as absent (anti-injection). When
	// empty, any non-empty value is accepted (the edge is trusted to set a
	// valid region).
	Allowed []ID

	// Default is returned when the header is missing or its value is
	// rejected by Allowed. Empty Default means "" (unconstrained).
	Default ID

	// PeerTrust, when non-nil, gates the header on the DIRECT peer: the
	// serving-region header is edge/mesh-supplied, so a request whose
	// r.RemoteAddr is outside the trusted-proxy CIDRs forged it itself —
	// treat it as absent (Default), same as an allowlist rejection. Nil
	// (the default) keeps the legacy trust-the-header behavior
	// byte-identical.
	PeerTrust *peertrust.Checker
}

// Resolve reads + validates the header value, falling back to Default.
func (h HeaderResolver) Resolve(r *http.Request) (ID, error) {
	if r == nil {
		return h.Default, nil
	}
	if h.PeerTrust != nil && !h.PeerTrust.TrustsRemoteAddr(r.RemoteAddr) {
		return h.Default, nil
	}
	name := h.Header
	if name == "" {
		name = DefaultServingRegionHeader
	}
	raw := ID(r.Header.Get(name))
	if raw == "" {
		return h.Default, nil
	}
	if len(h.Allowed) > 0 && !containsRegion(h.Allowed, raw) {
		// Value present but not allow-listed: a possible injection. Do not
		// echo it — fall back to the trusted Default.
		return h.Default, nil
	}
	return raw, nil
}

// ChainResolver tries each resolver in order; the first non-empty,
// error-free result wins. A resolver returning an error short-circuits the
// chain (the error propagates — the middleware logs it via OnError and
// proceeds with an empty region). The empty chain resolves to "".
type ChainResolver struct {
	Resolvers []Resolver
}

// Resolve walks the chain.
func (c ChainResolver) Resolve(r *http.Request) (ID, error) {
	for _, res := range c.Resolvers {
		if res == nil {
			continue
		}
		id, err := res.Resolve(r)
		if err != nil {
			return "", err
		}
		if id != "" {
			return id, nil
		}
	}
	return "", nil
}

func containsRegion(set []ID, want ID) bool {
	for _, id := range set {
		if id == want {
			return true
		}
	}
	return false
}

// Compile-time interface checks.
var (
	_ Resolver = ConfigPinnedResolver{}
	_ Resolver = HeaderResolver{}
	_ Resolver = ChainResolver{}
)
