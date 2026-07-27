package sso_test

import (
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/caep"
)

// TestCAEPOptInWiring proves WithCAEPTransmitter is opt-in and
// byte-identical when absent: WITHOUT the option the audit recorder's
// sink is untouched (the original MemorySink); WITH it the sink is tapped
// (wrapped in a MultiSink) and the transmitter is reachable for drain.
func TestCAEPOptInWiring(t *testing.T) {
	t.Parallel()

	// Baseline: recorder wired, NO transmitter. The sink must be exactly
	// the MemorySink the operator passed — no extra fan-out, no overhead.
	primary := audit.NewMemorySink(8)
	recBaseline := audit.New(primary)
	sBaseline := sso.NewServer(sso.WithAuditRecorder(recBaseline))
	if sBaseline.HasCAEPTransmitterForTest() {
		t.Fatal("baseline server reports a transmitter without the option")
	}
	if _, isMulti := sBaseline.AuditorSinkForTest().(*audit.MultiSink); isMulti {
		t.Fatal("baseline audit sink was wrapped without WithCAEPTransmitter — not byte-identical")
	}
	if sBaseline.AuditorSinkForTest() != primary {
		t.Fatal("baseline audit sink is not the original MemorySink")
	}

	// With the option: the sink is tapped (MultiSink) so events fan to the
	// transmitter, and CAEPTransmitter() returns it for shutdown drain.
	iss := defaultimpl.NewEd25519JWTIssuer()
	store := defaultimpl.NewMemoryClientStore()
	tx := caep.NewTransmitter(iss, store)
	primary2 := audit.NewMemorySink(8)
	recWired := audit.New(primary2)
	sWired := sso.NewServer(
		sso.WithAuditRecorder(recWired),
		sso.WithCAEPTransmitter(tx),
	)
	if !sWired.HasCAEPTransmitterForTest() {
		t.Fatal("transmitter not wired despite WithCAEPTransmitter")
	}
	if sWired.CAEPTransmitter() != tx {
		t.Fatal("CAEPTransmitter() did not return the wired transmitter")
	}
	if _, isMulti := sWired.AuditorSinkForTest().(*audit.MultiSink); !isMulti {
		t.Fatal("audit sink was NOT tapped after WithCAEPTransmitter")
	}
}
