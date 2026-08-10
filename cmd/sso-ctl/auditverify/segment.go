package auditverify

import (
	"fmt"
	"os"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// verifyAnchoredSegment is the --anchor-hash branch of Run: R2 order
// normalization, then exactly ONE audit.VerifyChainSegment(events, anchor)
// call (R3). Never retry verification after a failure ("verify both
// orders" is a tamper-masking hazard): after normalization the order is
// structurally fixed, and continuity binds it cryptographically (every
// PrevHash must equal the previous Hash). The anchor is cryptographically
// bound because eventHash covers PrevHash — forging the anchor breaks the
// first event's own hash. Returns the exit code (0 verified, 1
// break/truncated/empty; misuse exit 2 is checkMisuse's job).
func verifyAnchoredSegment(events []*audit.Event, anchor string, limit int, truncated bool) int {
	// R6: an empty buffer carries no event asserting the boundary; the
	// legacy "no events to verify" (exit 0) must NOT apply here.
	if len(events) == 0 {
		fmt.Fprintf(os.Stderr, "cannot verify an empty segment against anchor %q\n", anchor)
		return 1
	}
	normalizeSegmentOrder(events, anchor)
	if err := audit.VerifyChainSegment(events, anchor); err != nil {
		fmt.Fprintf(os.Stderr, "chain BROKEN: %v\n", err)
		return 1
	}
	if truncated {
		// R7 honest reporting: the START-boundary claim is fully verified,
		// but the head is a prefix head — never assert it is the chain tip.
		fmt.Printf("prefix verified: %d event(s) — truncated by --limit %d; head=%s is not the full chain\n",
			len(events), limit, events[len(events)-1].Hash)
		return 1
	}
	fmt.Printf("segment verified: %d event(s), anchored=%s, head=%s\n",
		len(events), anchor, events[len(events)-1].Hash)
	return 0
}

// normalizeSegmentOrder applies the R2 structural order normalization:
// the anchor position decides BEFORE verification, and verification runs
// exactly once. Case (a) anchor on the first event keeps chain order;
// case (b) anchor on the LAST event means the buffer is newest-first
// (API/relay delivery shape) and is reversed; case (c) neither — the
// order is left untouched and VerifyChainSegment fails closed at index 0
// with the chainer's honest expected/prev_hash values. Reversal cannot
// mask tampering: after reversal, continuity still requires every
// PrevHash to equal the previous Hash.
func normalizeSegmentOrder(events []*audit.Event, anchor string) {
	if len(events) == 0 {
		return
	}
	if events[0].PrevHash == anchor {
		return
	}
	if len(events) > 1 && events[len(events)-1].PrevHash == anchor {
		reverseEvents(events)
	}
}
