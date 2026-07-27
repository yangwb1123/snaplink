package region

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/shared/security/peertrust"
)

func peerTrustChecker(t *testing.T, cidrs ...string) *peertrust.Checker {
	t.Helper()
	c, err := peertrust.NewChecker(cidrs)
	if err != nil {
		t.Fatalf("NewChecker(%v): %v", cidrs, err)
	}
	return c
}

func regionReq(remoteAddr, header string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if header != "" {
		r.Header.Set(DefaultServingRegionHeader, header)
	}
	return r
}

func TestHeaderResolver_PeerTrust_TrustedPeerHonorsHeader(t *testing.T) {
	t.Parallel()
	h := HeaderResolver{
		Default:   ID("eu-west-1"),
		PeerTrust: peerTrustChecker(t, "10.0.0.0/8"),
	}
	got, err := h.Resolve(regionReq("10.0.0.7:9443", "us-east-1"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != ID("us-east-1") {
		t.Errorf("trusted peer resolved %q, want us-east-1 (header honored)", got)
	}
}

func TestHeaderResolver_PeerTrust_UntrustedPeerFallsBackToDefault(t *testing.T) {
	t.Parallel()
	h := HeaderResolver{
		Default:   ID("eu-west-1"),
		PeerTrust: peerTrustChecker(t, "10.0.0.0/8"),
	}
	got, err := h.Resolve(regionReq("203.0.113.9:9443", "us-east-1"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The header is proxy-supplied: an untrusted direct peer set it itself,
	// so it resolves as if absent — the trusted Default, never the injected
	// value.
	if got != ID("eu-west-1") {
		t.Errorf("untrusted peer resolved %q, want eu-west-1 (default)", got)
	}
}

func TestHeaderResolver_NilPeerTrust_LegacyHeaderTrust(t *testing.T) {
	t.Parallel()
	// Unset knob (nil checker) must stay byte-identical to the legacy
	// trust-the-header behavior.
	h := HeaderResolver{Default: ID("eu-west-1")}
	got, err := h.Resolve(regionReq("203.0.113.9:9443", "us-east-1"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != ID("us-east-1") {
		t.Errorf("nil PeerTrust resolved %q, want us-east-1 (legacy)", got)
	}
}
