package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/spi"
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
	lastTS   time.Time // last stamped Timestamp; keeps stamped ts strictly monotonic
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
	// Persist a strictly-MONOTONIC timestamp in chain (stamp) order. Record
	// assigns e.Timestamp OUTSIDE this lock, so two concurrent records whose
	// wall-clock order inverts relative to the mutex-acquisition order would be
	// read back out of chain order by the durable path's ORDER BY ts_unix_ns,
	// and VerifyChain would report a false break. Bumping a non-increasing
	// timestamp to lastTS+1ns makes ts order == chain order without a separate
	// sequence column. (Wall clock must slew, never step, per the ops contract,
	// so this stays within nanoseconds of real time.)
	if !e.Timestamp.After(c.lastTS) {
		e.Timestamp = c.lastTS.Add(time.Nanosecond)
	}
	c.lastTS = e.Timestamp
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
	// Normalize the timestamp to UTC before hashing. The durable sinks persist
	// only the instant (UnixNano) and reconstruct e.Timestamp as .UTC() on read,
	// while Record stamps it from the server's LOCAL-zone clock (time.Now). Without
	// this, a non-UTC deployment hashes "...-04:00" at write but recomputes "...Z"
	// at verify -> VerifyChain falsely reports every event as tampered. UTC is the
	// canonical, location-independent form for both write and read.
	cp.Timestamp = cp.Timestamp.UTC()
	raw, _ := json.Marshal(&cp)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// GenesisHash is the well-known PrevHash of a chain's first (genesis)
// event. Chain-segment tooling — a bulk compliance export that may not
// begin at true genesis (see the auditexport package) or the Prune
// re-chain posture documented on the SQLite sink — needs a named symbol
// for "this run starts at the chain's beginning" rather than a bare ""
// literal at every call site.
const GenesisHash = ""

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
	return verifyChainFrom(events, GenesisHash)
}

// VerifyChainSegment verifies the internal continuity of a SLICE of a
// larger chain, seeded from expectedPrevHash — the "boundary anchor":
// the PrevHash the oldest exported event carried at export time. Passing
// [GenesisHash] reproduces [VerifyChain] exactly; passing the Hash of
// the last EXCLUDED event lets a mid-chain export (e.g. a Since/Until
// compliance window) stay independently tamper-evident WITHOUT rewriting
// any persisted Hash. The anchor is trusted input, but it is still bound
// cryptographically: eventHash covers PrevHash, so rewriting events[0]'s
// PrevHash to match a forged anchor breaks events[0]'s own Hash check.
//
// Fail-closed: any break or per-event tamper is a returned error.
func VerifyChainSegment(events []*Event, expectedPrevHash string) error {
	return verifyChainFrom(events, expectedPrevHash)
}

// VerifyEventIntegrity checks only that each event's Hash matches its
// content (eventHash), NOT that the events link into a continuous chain.
// It is the right check for an attribute-filtered export (by type, actor,
// tenant, …): such a subset SKIPS intervening events, so PrevHash
// linkage genuinely does not hold, but each retained event's content is
// still tamper-evident on its own. Order-independent; a nil event is a
// returned error.
func VerifyEventIntegrity(events []*Event) error {
	for i, e := range events {
		if e == nil {
			return fmt.Errorf("audit: VerifyEventIntegrity: nil event at index %d", i)
		}
		if recomputed := eventHash(e); e.Hash != recomputed {
			return fmt.Errorf("audit: hash mismatch at index %d (id=%s): stored=%q, recomputed=%q (event was tampered with after recording)",
				i, e.ID, e.Hash, recomputed)
		}
	}
	return nil
}

// verifyChainFrom is the shared walk behind VerifyChain and
// VerifyChainSegment: it seeds the running PrevHash with prev instead of
// a hardcoded "" so the same recomputation logic serves both a
// genesis-anchored full chain and a boundary-anchored segment.
func verifyChainFrom(events []*Event, prev string) error {
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

// ---------------------------------------------------------------------------
// Chain-head notarization (see the chainer limitation note above).
// ---------------------------------------------------------------------------

// Checkpoint is a signed attestation of the chain head at one moment.
// Sequence is monotonic; PrevHash (the previous checkpoint's HeadHash)
// chains checkpoints so a deleted/reordered one is tamper-evident.
type Checkpoint struct {
	Sequence  int64     `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	HeadHash  string    `json:"head_hash"`
	PrevHash  string    `json:"prev_hash,omitempty"`
}

// SignedCheckpoint is a Checkpoint plus its signature and the signer's
// public key (verification needs no key registry).
type SignedCheckpoint struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	Signature  []byte     `json:"signature"`
	SignerKey  []byte     `json:"signer_key"`
}

// CheckpointSigner signs checkpoint bytes (independent of the signing-key
// registry used for tokens/discovery metadata).
type CheckpointSigner interface {
	Sign(data []byte) (signature []byte, err error)
	// PublicKey returns the raw public key for verification.
	PublicKey() []byte
}

// Ed25519CheckpointSigner is the concrete signer.
type Ed25519CheckpointSigner struct {
	priv ed25519.PrivateKey
}

// NewEd25519CheckpointSigner generates a fresh key pair.
func NewEd25519CheckpointSigner() (*Ed25519CheckpointSigner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("audit notary: generate key: %w", err)
	}
	return &Ed25519CheckpointSigner{priv: priv}, nil
}

// Sign implements CheckpointSigner.
func (s *Ed25519CheckpointSigner) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, data), nil
}

// PublicKey implements CheckpointSigner.
func (s *Ed25519CheckpointSigner) PublicKey() []byte {
	return s.priv.Public().(ed25519.PublicKey)
}

// CheckpointStore persists signed checkpoints (interface + Memory*
// reference impl per AGENTS.md §4; a durable backend slots in without
// touching the Notary).
type CheckpointStore interface {
	Append(ctx context.Context, c *SignedCheckpoint) error
	// Latest returns the most recent checkpoint, or (nil, nil) when empty.
	Latest(ctx context.Context) (*SignedCheckpoint, error)
	List(ctx context.Context, since time.Time, limit int) ([]*SignedCheckpoint, error)
}

// MemoryCheckpointStore is the in-process reference implementation.
type MemoryCheckpointStore struct {
	mu          sync.Mutex
	checkpoints []*SignedCheckpoint
}

// NewMemoryCheckpointStore returns an empty store.
func NewMemoryCheckpointStore() *MemoryCheckpointStore {
	return &MemoryCheckpointStore{}
}

// Append implements CheckpointStore.
func (m *MemoryCheckpointStore) Append(_ context.Context, c *SignedCheckpoint) error {
	if c == nil {
		return errors.New("audit notary: nil checkpoint")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkpoints = append(m.checkpoints, c)
	return nil
}

// Latest implements CheckpointStore.
func (m *MemoryCheckpointStore) Latest(_ context.Context) (*SignedCheckpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.checkpoints) == 0 {
		return nil, nil
	}
	return m.checkpoints[len(m.checkpoints)-1], nil
}

// List implements CheckpointStore.
func (m *MemoryCheckpointStore) List(_ context.Context, since time.Time, limit int) ([]*SignedCheckpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*SignedCheckpoint
	for _, c := range m.checkpoints {
		if c.Checkpoint.Timestamp.Before(since) {
			continue
		}
		out = append(out, c)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// Notary is the periodic chain-head notarization loop: each tick it reads
// the durable sink's ChainTip and signs + stores a checkpoint when the head
// changed. Fail-open: a tip/store error is logged + audited, never fatal,
// never blocking the audit pipeline (the notary consumes the head; it does
// not participate in recording).
type Notary struct {
	tip      ChainTip
	store    CheckpointStore
	signer   CheckpointSigner
	interval time.Duration
	recorder *Recorder
	logger   spi.Logger

	mu         sync.Mutex // guards lastSigned/lastSeq
	lastSigned string
	lastSeq    int64
}

// NewNotary builds the notary (tip + store required; recorder/logger optional).
func NewNotary(tip ChainTip, store CheckpointStore, signer CheckpointSigner, interval time.Duration, recorder *Recorder, logger spi.Logger) *Notary {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &Notary{tip: tip, store: store, signer: signer, interval: interval, recorder: recorder, logger: logger}
}

// Run executes the loop until ctx is cancelled; the first checkpoint is
// attempted immediately (a restart surfaces the current head right away).
func (n *Notary) Run(ctx context.Context) {
	_, _ = n.CheckpointNow(ctx)
	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = n.CheckpointNow(ctx)
		}
	}
}

// StartNotary launches the loop; the done channel closes on ctx cancel.
func StartNotary(ctx context.Context, tip ChainTip, store CheckpointStore, signer CheckpointSigner, interval time.Duration, recorder *Recorder, logger spi.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewNotary(tip, store, signer, interval, recorder, logger).Run(ctx)
	}()
	return done
}

// CheckpointNow signs + stores one checkpoint of the current chain head
// (the testable unit and an admin-triggerable attestation), or (nil, nil)
// when the head is unchanged since the last checkpoint.
func (n *Notary) CheckpointNow(ctx context.Context) (*SignedCheckpoint, error) {
	head, err := n.tip.LastHash(ctx)
	if err != nil {
		n.recordFailure(ctx, fmt.Sprintf("tip read failed: %v", err))
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if head == "" {
		head = GenesisHash // empty store: attest genesis
	}
	if head == n.lastSigned {
		return nil, nil // unchanged head: nothing new to attest
	}
	cp := Checkpoint{
		Sequence:  n.lastSeq + 1,
		Timestamp: time.Now().UTC(),
		HeadHash:  head,
		PrevHash:  n.lastSigned,
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		return nil, fmt.Errorf("audit notary: encode checkpoint: %w", err)
	}
	sig, err := n.signer.Sign(raw)
	if err != nil {
		n.recordFailure(ctx, fmt.Sprintf("checkpoint signing failed: %v", err))
		return nil, err
	}
	signed := &SignedCheckpoint{Checkpoint: cp, Signature: sig, SignerKey: n.signer.PublicKey()}
	if err := n.store.Append(ctx, signed); err != nil {
		n.recordFailure(ctx, fmt.Sprintf("checkpoint store write failed: %v", err))
		return nil, err
	}
	n.lastSigned = head
	n.lastSeq = cp.Sequence
	// Deliberately NO success audit event: the notary's own event would
	// change the chain head it just attested, turning every tick into a new
	// head (and the checkpoint itself IS the record). Failures are recorded
	// (below) because a missed attestation is an operational signal.
	return signed, nil
}

func (n *Notary) recordFailure(ctx context.Context, detail string) {
	if n.logger != nil {
		n.logger.Error("audit chain checkpoint failed", "error", detail)
	}
	if n.recorder == nil {
		return
	}
	n.recorder.Record(ctx, &Event{
		Type:    EventAuditChainCheckpoint,
		Outcome: OutcomeFailure,
		Reason:  "checkpoint_failed",
	})
}

// VerifyCheckpointSignature checks the signature against the embedded
// signer key (Ed25519).
func VerifyCheckpointSignature(c *SignedCheckpoint) error {
	if c == nil {
		return errors.New("audit notary: nil checkpoint")
	}
	if len(c.SignerKey) != ed25519.PublicKeySize {
		return errors.New("audit notary: invalid signer key size")
	}
	raw, err := json.Marshal(c.Checkpoint)
	if err != nil {
		return fmt.Errorf("audit notary: encode checkpoint: %w", err)
	}
	if !ed25519.Verify(c.SignerKey, raw, c.Signature) {
		return errors.New("audit notary: checkpoint signature invalid")
	}
	return nil
}

// VerifyChainAgainstCheckpoint replays the chain and asserts its computed
// head matches the checkpoint's attested head — closing the last-event
// blind spot: an attacker who modified the final event (or replaced the
// whole chain) cannot make the replayed head equal the attestation without
// forging the signature. events carry their persisted Hash fields in chain
// order (oldest first).
func VerifyChainAgainstCheckpoint(events []*Event, c *SignedCheckpoint) error {
	if c == nil {
		return errors.New("audit notary: nil checkpoint")
	}
	if err := VerifyCheckpointSignature(c); err != nil {
		return err
	}
	if err := VerifyChain(events); err != nil {
		return err
	}
	if len(events) == 0 {
		if c.Checkpoint.HeadHash != GenesisHash {
			return fmt.Errorf("audit notary: empty chain head %q, checkpoint attests %q", GenesisHash, c.Checkpoint.HeadHash)
		}
		return nil
	}
	head := events[len(events)-1].Hash
	if head != c.Checkpoint.HeadHash {
		return fmt.Errorf("audit notary: replayed head %q does not match checkpoint attestation %q", head, c.Checkpoint.HeadHash)
	}
	return nil
}

// CheckpointEqual reports byte equality of two checkpoints.
func CheckpointEqual(a, b *SignedCheckpoint) bool {
	if a == nil || b == nil {
		return a == b
	}
	ar, _ := json.Marshal(a)
	br, _ := json.Marshal(b)
	return bytes.Equal(ar, br)
}
