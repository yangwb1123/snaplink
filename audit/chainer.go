package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
)

// chainer maintains a running hash chain over the events a Recorder
// processes. Each event's Hash covers its own canonical-JSON
// encoding + the previous event's Hash, so any tampering with a past
// event breaks the recomputation of every subsequent Hash.
//
// Scope: in-process running state, seeded from durable storage on
// construction. A fresh process resumes the chain from the last
// persisted event's Hash (see [ChainTip] + [WithHashChain]) so the
// first post-restart event's PrevHash equals the last pre-restart
// Hash — no spurious genesis at the restart seam, which would
// otherwise read as a chain break (or mask tampering) to
// [VerifyChain]. An empty store seeds genesis (prevHash == "").
//
// Limitation: tampering with the LAST event isn't detectable from
// the chain alone (no future hash to break). Detection requires
// either a periodic external attestation (publish the head hash to
// a separate channel) or a cryptographic signature on the head
// hash — both out of scope for v1.
type chainer struct {
	mu       sync.Mutex
	prevHash string
}

// ChainTip is the optional [Sink] extension that lets a Recorder
// resume a [WithHashChain] chain across process restarts. A durable
// sink returns its most recently persisted event's Hash (chain head)
// here; an empty store returns "" so the chain seeds at genesis. The
// composing sinks (MultiSink, AsyncSink) forward this to their read-
// capable leaf, mirroring how FacetQuerier is forwarded, so the seam
// works through the standard Async -> Multi -> leaf pipeline.
//
// Memory-only sinks deliberately do NOT implement this — they lose
// every event on restart, so there is no durable tip to resume from
// and a fresh genesis is the correct (and only) behavior.
type ChainTip interface {
	// LastHash returns the Hash of the most recently recorded event,
	// or "" when the store holds none. A non-nil error means the tip
	// couldn't be read; the caller seeds genesis and continues (a
	// failed resume must never block recording).
	LastHash(ctx context.Context) (string, error)
}

// seed sets the chain head before any event is stamped. Called once
// at Recorder construction, before the Recorder is shared with
// request handlers, so it needs no extra synchronization beyond the
// mutex the rest of the chainer already holds.
func (c *chainer) seed(prev string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prevHash = prev
}

// stamp populates e.PrevHash + e.Hash from the chainer state and
// advances the chain. Idempotent only if called on the same event
// pointer before the chainer has advanced past it.
func (c *chainer) stamp(e *Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.PrevHash = c.prevHash
	e.Hash = eventHash(e)
	c.prevHash = e.Hash
}

// eventHash returns sha256(canonical JSON encoding of e) with two
// fields cleared so they don't end up as their own input:
//
//   - Hash: the field we're computing — including it would be
//     recursive.
//   - ID: assigned by the Sink AFTER the chainer stamps the event,
//     so we'd hash an empty ID then the sink would fill it in and
//     VerifyChain would see a different ID at read time and
//     recompute a different hash. Excluding ID means the chain
//     protects content, not storage assignment — adequate for the
//     tamper-evidence promise (an attacker rewriting an event's
//     reason / outcome / actor breaks the chain; rewriting the
//     storage id alone does not, but also doesn't change what the
//     event MEANS).
//
// Canonical-encoding strategy: marshal the *Event struct directly.
// Go's encoding/json emits struct fields in declaration order and
// map keys in sorted lexical order. Both are deterministic across
// Go versions per the spec — adequate for the chain's "same input
// produces same hash" requirement.
//
// Stability caveat: reordering fields in the Event struct WILL
// change every event's Hash. Treat the struct's field order as part
// of the wire contract once a deployment is recording chains.
func eventHash(e *Event) string {
	cp := *e
	cp.ID = ""
	cp.Hash = ""
	raw, _ := json.Marshal(&cp)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// VerifyChain walks a sequence of events in CHAIN ORDER (oldest →
// newest) and confirms:
//
//   - events[0].PrevHash == "" (genesis)
//   - every events[i].PrevHash == events[i-1].Hash
//   - every events[i].Hash == eventHash(events[i])
//
// Returns nil when the chain verifies; a descriptive error pointing
// at the first break otherwise.
//
// MemorySink returns query results NEWEST-FIRST by default — callers
// must reverse the slice (or query with the right limit/offset) to
// get chain order. Easy mistake to make; the error message mentions
// "chain order" to nudge debuggers in the right direction.
func VerifyChain(events []*Event) error {
	var prev string
	for i, e := range events {
		if e == nil {
			return fmt.Errorf("audit: VerifyChain: nil event at index %d (events must be in chain order, oldest first)", i)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("audit: chain break at index %d (id=%s): prev_hash=%q, expected %q (events must be in chain order, oldest first)",
				i, e.ID, e.PrevHash, prev)
		}
		recomputed := eventHash(e)
		if e.Hash != recomputed {
			return fmt.Errorf("audit: hash mismatch at index %d (id=%s): stored=%q, recomputed=%q (event was tampered with after recording)",
				i, e.ID, e.Hash, recomputed)
		}
		prev = e.Hash
	}
	return nil
}
