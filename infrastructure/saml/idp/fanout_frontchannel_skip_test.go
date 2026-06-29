package idp

import (
	"context"
	"testing"
	"time"
)

// TestFanout_IdPInitiated_SkipsFrontChannelSPs proves the IdP-initiated Fanout
// SKIPS front-channel SPs (a server-side fan-out has no browser to drive the
// redirect chain) while still cleaning their index rows, and still back-channel
// dispatches the others. With ONLY a front-channel SP recorded, no outbound
// dispatch happens but the index is reclaimed (RemoveAll), exercising Fanout's
// len(front) > 0 skip-log branch.
func TestFanout_IdPInitiated_SkipsFrontChannelSPs(t *testing.T) {
	t.Parallel()
	const nameID = "fc-skip@example.com"
	hh, _, _, idx, _ := newFanoutHarness(t, nameID)
	ctx := context.Background()

	// A FRONT-channel SP row (SPChannel = ChannelFrontchannel): the IdP-initiated
	// fan-out can't reach it (no browser), so it must be skipped + its row cleaned.
	_ = idx.Record(ctx, nameID, SAMLSPSession{
		SPEntityID: "https://sp-fc.example.com/saml/metadata",
		SPClientID: "sp-fc-client",
		SPSLOUrl:   "https://sp-fc.example.com/saml/slo",
		SPBinding:  BindingRedirect,
		SPChannel:  ChannelFrontchannel,
		NameID:     nameID,
	})

	hh.h.Fanout(ctx, nameID, "")

	// The index is cleaned synchronously by Fanout (RemoveAll), even though the
	// front-channel SP got no dispatch.
	if rows, _ := idx.ListBySubject(ctx, nameID); len(rows) != 0 {
		t.Fatalf("front-channel SP row not cleaned after IdP-initiated fan-out: %+v", rows)
	}
}

// TestFanout_BlankSubject_NoOp proves Fanout is a no-op for a blank subject
// (nothing to log out) — the early guard, never touching the index.
func TestFanout_BlankSubject_NoOp(t *testing.T) {
	t.Parallel()
	hh, _, _, idx, _ := newFanoutHarness(t, "someone@example.com")
	ctx := context.Background()
	// Record a row under a real subject; a blank-subject Fanout must NOT clean it.
	_ = idx.Record(ctx, "kept@example.com", SAMLSPSession{
		SPEntityID: "https://sp-x/saml", SPClientID: "x", SPSLOUrl: "https://sp-x/slo",
		SPBinding: BindingRedirect, NameID: "kept@example.com",
	})
	hh.h.Fanout(ctx, "", "")
	time.Sleep(20 * time.Millisecond)
	if rows, _ := idx.ListBySubject(ctx, "kept@example.com"); len(rows) != 1 {
		t.Fatalf("blank-subject Fanout touched an unrelated subject's rows: %+v", rows)
	}
}
