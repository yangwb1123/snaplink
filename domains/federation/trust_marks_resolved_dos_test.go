package federation_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/federation"
	"github.com/snaplink/sso/shared/core"
)

// ===========================================================================
// SLICE 4c HARDENING — bound the NESTED trust-mark issuer-resolution fan-out
// (adversarial-review MEDIUM, DoS amplification). With the federation-resolved
// issuer path ON, an already-chain-validated but malicious RP can carry many
// distinct-iss trust marks, each firing its OWN full nested ResolveTrustChain
// BEFORE the mark signature check. These tests prove the three bounds:
//
//   (a) a PER-REQUEST distinct-issuer resolution BUDGET (deduped + capped),
//   (b) a GLOBAL nested-resolution concurrency SEMAPHORE (excess shed), and
//   (c) a short-TTL NEGATIVE cache (a failed iss is not re-resolved within TTL,
//       re-resolves after TTL, and a legit iss is not pinned out).
//   (d) a leaf trust_marks COUNT cap (an absurd-cardinality leaf rejected).
//
// All fail-closed + oracle-safe (the RP stays unknown — ErrNoSuchClient). The
// SOUND authorization matrix (trust_marks_resolved_test.go) is untouched and
// stays green; this file only proves the fan-out is bounded.
//
// Reuses the slice-2/3/4b fake federation (fedEntity / fakeFetcher / fedClock /
// signTrustMark / leafConfigWithTrustMarks) plus a per-entity counting+blocking
// fetcher decorator (countingFetcher) so a test can OBSERVE how many nested
// issuer resolutions actually fired (via the issuer's Entity-Configuration fetch
// count) and BLOCK them (for the concurrency proof).
// ===========================================================================

// countingFetcher wraps an EntityStatementFetcher and (1) counts
// FetchEntityConfiguration calls PER entityID — a precise proxy for "a nested
// ResolveTrustChain(iss) was attempted", since the resolver fetches the target's
// Entity Configuration first — and (2) optionally BLOCKS the config fetch of any
// entityID in blockIDs until release is closed, signaling entry on entered (so a
// test can hold the nested-resolution semaphore full and prove the excess sheds).
type countingFetcher struct {
	inner federation.EntityStatementFetcher

	mu       sync.Mutex
	cfgCalls map[string]int // entityID -> FetchEntityConfiguration count

	// innerMu serializes the wrapped fetcher's calls. The shared fakeFetcher is
	// NOT thread-safe (its `calls` counter + map reads), and the concurrency
	// proof drives genuinely-concurrent fetches; serializing the inner call (held
	// ONLY around the delegation, never during the block) keeps the harness
	// race-free without changing the bound under test.
	innerMu sync.Mutex

	// concurrency instrumentation (blocking mode).
	blockIDs map[string]struct{} // entityIDs whose config fetch blocks on release
	release  chan struct{}       // closed to unblock all blocked fetches
	entered  chan string         // a blocked fetch sends its entityID on entry
	concNow  atomic.Int64        // currently-blocked config fetches
	concMax  atomic.Int64        // high-water mark of concurrent blocked fetches
}

func newCountingFetcher(inner federation.EntityStatementFetcher) *countingFetcher {
	return &countingFetcher{inner: inner, cfgCalls: map[string]int{}}
}

// blockConfigsFor makes the config fetch of each id block until release is
// closed; each blocked fetch signals its id on entered (buffered to >= len(ids)).
func (c *countingFetcher) blockConfigsFor(release chan struct{}, entered chan string, ids ...string) {
	c.blockIDs = make(map[string]struct{}, len(ids))
	for _, id := range ids {
		c.blockIDs[id] = struct{}{}
	}
	c.release = release
	c.entered = entered
}

func (c *countingFetcher) configCalls(entityID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfgCalls[entityID]
}

func (c *countingFetcher) FetchEntityConfiguration(ctx context.Context, entityID string) ([]byte, error) {
	c.mu.Lock()
	c.cfgCalls[entityID]++
	c.mu.Unlock()

	if _, blocked := c.blockIDs[entityID]; blocked {
		n := c.concNow.Add(1)
		for { // lock-free running max
			m := c.concMax.Load()
			if n <= m || c.concMax.CompareAndSwap(m, n) {
				break
			}
		}
		if c.entered != nil {
			c.entered <- entityID
		}
		<-c.release
		c.concNow.Add(-1)
	}
	c.innerMu.Lock()
	defer c.innerMu.Unlock()
	return c.inner.FetchEntityConfiguration(ctx, entityID)
}

func (c *countingFetcher) FetchSubordinateStatement(ctx context.Context, endpoint, iss, sub string) ([]byte, error) {
	c.innerMu.Lock()
	defer c.innerMu.Unlock()
	return c.inner.FetchSubordinateStatement(ctx, endpoint, iss, sub)
}

// ---------------------------------------------------------------------------
// Shared multi-pair federation builder: one anchor + intermediate, plus an
// arbitrary number of (leaf RP, resolved issuer) pairs all rooted at that
// anchor. Each leaf carries the given marks; the anchor's trust_mark_issuers is
// the authorization root. Returns the underlying fakeFetcher + the anchor so a
// test can wrap the fetcher with countingFetcher and build a store.
// ---------------------------------------------------------------------------

// dosPair is one (leaf, issuer) the leaf's mark is signed by.
type dosPair struct {
	leaf   *fedEntity
	issuer *fedEntity
	marks  []federation.TrustMarkEntry
}

func buildMultiPairFederation(t *testing.T, anchor, inter *fedEntity, anchorTMI map[string][]string, pairs []dosPair) *fakeFetcher {
	t.Helper()
	f := newFakeFetcher()
	f.configs[anchor.id] = anchorConfigWithTMI(t, anchor, tcFetchURL, anchorTMI)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = anchor.subordinateStatement(t, inter, nil)
	for _, p := range pairs {
		f.configs[p.leaf.id] = leafConfigWithTrustMarks(t, p.leaf, []string{inter.id},
			rpWithKeys(t, p.leaf, p.leaf.id+"/cb"), p.marks)
		f.subs[subKey(tcInterFch, inter.id, p.leaf.id)] = inter.subordinateStatement(t, p.leaf, nil)
		// The issuer as a federation entity — a direct child of the anchor.
		f.configs[p.issuer.id] = p.issuer.entityConfig(t, []string{anchor.id}, "", nil)
		f.subs[subKey(tcFetchURL, anchor.id, p.issuer.id)] = anchor.subordinateStatement(t, p.issuer, nil)
	}
	return f
}

// dosStore builds a RegistrationClientStore over the counting fetcher + the
// resolver (fixed resolver clock) + the slice-4c gate from cfg, with the
// registration clock driven by nowFn (a test seam — defaults to fedClock).
func dosStore(t *testing.T, cf *countingFetcher, anchor *fedEntity, cfg *federation.Config, nowFn func() time.Time) *federation.RegistrationClientStore {
	t.Helper()
	if nowFn == nil {
		nowFn = func() time.Time { return fedClock }
	}
	return federation.NewRegistrationClientStore(
		newCountingClientStore(),
		resolverFor(t, cf, anchor),
		federation.WithRegistrationClock(nowFn),
		federation.WithRegistrationTrustMarks(cfg),
	)
}

// dosConfig is fedResolvedConfig with explicit DoS bounds for the test.
func dosConfig(requiredTypes []string, budget, concurrency int, negTTL time.Duration) *federation.Config {
	c := &federation.Config{
		RequiredTrustMarkTypes:                  requiredTypes,
		AllowFederationResolvedTrustMarkIssuers: true,
		MaxResolvedIssuersPerRequest:            budget,
		MaxConcurrentIssuerResolutions:          concurrency,
		ResolvedIssuerNegativeCacheTTL:          negTTL,
	}
	return c
}

// ===========================================================================
// (a) PER-REQUEST distinct-issuer resolution BUDGET.
// ===========================================================================

// A leaf carrying marks from MANY distinct, anchor-authorized issuers — but each
// mark has the WRONG SUBJECT (so it resolves the issuer, then fails the binding,
// forcing the scan to continue) — must attempt only `budget` DISTINCT issuer
// resolutions, not one per mark. The over-budget required type goes unsatisfied
// -> the RP is rejected (fail-closed). Proven via the per-issuer config-fetch
// count (== budget).
func TestTrustMarkResolvedDoS_DistinctIssuerBudget_Capped(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)

	const budget = 3
	const distinct = 8 // > budget: the excess must NOT resolve

	issuers := make([]*fedEntity, distinct)
	marks := make([]federation.TrustMarkEntry, distinct)
	anchorTMI := map[string][]string{tmType: {}} // empty array = anyone authorized
	for i := 0; i < distinct; i++ {
		iss := newFedEntity(t, dosIssuerID(i))
		issuers[i] = iss
		// WRONG subject: the mark resolves the issuer (counting a fetch) but fails
		// the sub==leaf binding, so satisfiedBy keeps scanning to the next issuer.
		m := signTrustMark(t, iss, "https://not-the-leaf.federation.test", tmType, fedClock.Unix(), 0)
		marks[i] = federation.TrustMarkEntry{TrustMarkType: tmType, TrustMark: m}
	}
	pairs := make([]dosPair, distinct)
	for i := range issuers {
		pairs[i] = dosPair{leaf: leaf, issuer: issuers[i]} // marks attached to the single leaf below
	}
	// Attach ALL marks to the one leaf (override the per-pair leaf config).
	f := buildMultiPairFederation(t, anchor, inter, anchorTMI, pairs)
	f.configs[leaf.id] = leafConfigWithTrustMarks(t, leaf, []string{inter.id},
		rpWithKeys(t, leaf, leaf.id+"/cb"), marks)

	cf := newCountingFetcher(f)
	store := dosStore(t, cf, anchor, dosConfig([]string{tmType}, budget, 8, 30*time.Second), nil)

	// Wrong-subject marks never satisfy -> the RP is rejected (oracle-safe).
	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Fatalf("Get(over-budget distinct issuers, all wrong-subject) = %v, want ErrNoSuchClient", err)
	}

	// EXACTLY `budget` DISTINCT issuers were resolved (config-fetched); the rest
	// were budget-shed before any outbound work.
	resolved := 0
	for i := 0; i < distinct; i++ {
		if cf.configCalls(dosIssuerID(i)) > 0 {
			resolved++
		}
	}
	if resolved != budget {
		t.Errorf("distinct issuers resolved = %d, want exactly budget=%d (per-request fan-out not bounded)", resolved, budget)
	}
}

// DEDUP: N marks naming the SAME issuer cost ONE resolution (the budget bounds
// DISTINCT issuers, not marks). All marks wrong-subject (so the scan visits each)
// from a single issuer -> the issuer is resolved exactly once.
func TestTrustMarkResolvedDoS_SameIssuerDedup_OneResolution(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	const n = 6
	marks := make([]federation.TrustMarkEntry, n)
	for i := 0; i < n; i++ {
		// Same issuer, wrong subject -> each mark fails binding, scan continues,
		// but the issuer resolves once (cache hit on marks 2..n).
		m := signTrustMark(t, issuer, "https://not-the-leaf.federation.test", tmType, fedClock.Unix(), int64(i)+1)
		marks[i] = federation.TrustMarkEntry{TrustMarkType: tmType, TrustMark: m}
	}
	anchorTMI := map[string][]string{tmType: {issuer.id}}
	f := buildMultiPairFederation(t, anchor, inter, anchorTMI, []dosPair{{leaf: leaf, issuer: issuer}})
	f.configs[leaf.id] = leafConfigWithTrustMarks(t, leaf, []string{inter.id},
		rpWithKeys(t, leaf, leaf.id+"/cb"), marks)

	cf := newCountingFetcher(f)
	// Budget 1: a single distinct issuer must be enough for N same-iss marks.
	store := dosStore(t, cf, anchor, dosConfig([]string{tmType}, 1, 8, 30*time.Second), nil)

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Fatalf("Get(N same-iss wrong-subject marks) = %v, want ErrNoSuchClient", err)
	}
	if got := cf.configCalls(issuer.id); got != 1 {
		t.Errorf("issuer resolutions for %d same-iss marks = %d, want 1 (dedup)", n, got)
	}
}

// ===========================================================================
// (b) GLOBAL nested-resolution concurrency SEMAPHORE.
// ===========================================================================

// With the nested-resolution semaphore capped low and the issuer config fetch
// BLOCKING, exactly `cap` concurrent registrations hold the semaphore; further
// concurrent registrations (distinct leaves + distinct issuers) find it
// saturated and SHED (fail-closed -> ErrNoSuchClient), rather than spawning an
// unbounded number of concurrent nested resolutions. The deterministic ordering
// (start the cap first, wait until they hold the semaphore, THEN start the
// excess) removes flakiness; the high-water concurrency is asserted == cap.
func TestTrustMarkResolvedDoS_ConcurrencySemaphore_ExcessShed(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)

	const cap = 2
	const extra = 3
	total := cap + extra

	// Each registration is a DISTINCT (leaf, issuer) pair, the issuer anchor-
	// authorized, the mark correct (would admit if resolved) — so each tries its
	// own distinct nested resolution (no dedup/cache coalescing across pairs).
	anchorTMI := map[string][]string{tmType: {}} // empty = anyone
	pairs := make([]dosPair, total)
	leaves := make([]*fedEntity, total)
	blockIDs := make([]string, total)
	for i := 0; i < total; i++ {
		leaf := newFedEntity(t, dosLeafID(i))
		iss := newFedEntity(t, dosIssuerID(i))
		leaves[i] = leaf
		blockIDs[i] = iss.id
		m := signTrustMark(t, iss, leaf.id, tmType, fedClock.Unix(), 0)
		pairs[i] = dosPair{leaf: leaf, issuer: iss, marks: []federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: m}}}
	}
	f := buildMultiPairFederation(t, anchor, inter, anchorTMI, pairs)

	cf := newCountingFetcher(f)
	release := make(chan struct{})
	entered := make(chan string, total)
	cf.blockConfigsFor(release, entered, blockIDs...) // block every issuer's config fetch

	// Budget high enough to not interfere; the semaphore (cap) is the bound.
	store := dosStore(t, cf, anchor, dosConfig([]string{tmType}, 100, cap, 30*time.Second), nil)

	get := func(leafID string) error {
		_, err := store.Get(context.Background(), leafID)
		return err
	}

	// Phase 1: launch `cap` registrations. Each blocks inside its issuer's config
	// fetch holding a semaphore slot. Wait until all `cap` are in. capDone tracks
	// their completion so the test can drain them after release (no leaked
	// goroutines bleeding into later tests).
	capDone := make(chan struct{}, cap)
	for i := 0; i < cap; i++ {
		leafID := leaves[i].id
		go func() { _ = get(leafID); capDone <- struct{}{} }()
	}
	for i := 0; i < cap; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatalf("only %d of %d cap registrations entered the nested resolution", i, cap)
		}
	}

	// Phase 2: with the semaphore now FULL, launch the excess. Each reaches the
	// gate, finds the semaphore saturated, and sheds WITHOUT entering the blocked
	// fetch -> ErrNoSuchClient promptly.
	shedErr := make(chan error, extra)
	for i := cap; i < total; i++ {
		leafID := leaves[i].id
		go func() { shedErr <- get(leafID) }()
	}
	for i := 0; i < extra; i++ {
		select {
		case err := <-shedErr:
			if !errors.Is(err, core.ErrNoSuchClient) {
				t.Errorf("excess registration = %v, want ErrNoSuchClient (shed, fail-closed)", err)
			}
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatalf("an excess registration did not shed promptly (semaphore not bounding concurrency)")
		}
	}

	// The excess must NOT have entered any blocked fetch: high-water concurrency
	// == cap, and none of the excess issuers were config-fetched.
	if got := cf.concMax.Load(); got != int64(cap) {
		t.Errorf("peak concurrent nested resolutions = %d, want cap=%d", got, cap)
	}
	for i := cap; i < total; i++ {
		if got := cf.configCalls(dosIssuerID(i)); got != 0 {
			t.Errorf("excess issuer %d was resolved (config fetches=%d), want 0 (should have shed)", i, got)
		}
	}

	// Release the held cap; drain them so no goroutine leaks past the test.
	close(release)
	for i := 0; i < cap; i++ {
		select {
		case <-capDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("a held cap registration did not finish after release")
		}
	}
}

// ===========================================================================
// (c) short-TTL NEGATIVE cache.
// ===========================================================================

// A FAILING issuer resolution (the issuer chains to the anchor but the anchor
// does NOT authorize it) is negative-cached: a SECOND request within the TTL
// does NOT re-resolve (config-fetch count stays 1); after the TTL elapses it
// re-resolves (count 2). Drives a MUTABLE registration clock past the 30s TTL
// while the resolver clock stays fixed (the 24h statements stay valid).
func TestTrustMarkResolvedDoS_NegativeCache_NoRefetchWithinTTL(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	// The issuer chains + the mark is correctly signed about the leaf, but the
	// anchor authorizes a DIFFERENT entity -> resolution succeeds, authorization
	// FAILS -> negative-cached.
	anchorTMI := map[string][]string{tmType: {tmrIssuerOtherID}}
	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)
	f := buildMultiPairFederation(t, anchor, inter, anchorTMI,
		[]dosPair{{leaf: leaf, issuer: issuer, marks: []federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}}}})

	cf := newCountingFetcher(f)

	const negTTL = 30 * time.Second
	var nowNs atomic.Int64
	nowNs.Store(fedClock.UnixNano())
	regNow := func() time.Time { return time.Unix(0, nowNs.Load()).UTC() }
	store := dosStore(t, cf, anchor, dosConfig([]string{tmType}, 4, 8, negTTL), regNow)

	// 1st request: resolves the issuer (config fetch == 1), fails authorization,
	// negative-caches.
	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Fatalf("1st Get(unauthorized resolved issuer) = %v, want ErrNoSuchClient", err)
	}
	if got := cf.configCalls(issuer.id); got != 1 {
		t.Fatalf("issuer config fetches after 1st request = %d, want 1", got)
	}

	// 2nd request WITHIN the TTL: the negative cache short-circuits -> NO new
	// issuer resolution (count stays 1).
	nowNs.Add(int64(negTTL / 2))
	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Fatalf("2nd Get(within neg-TTL) = %v, want ErrNoSuchClient", err)
	}
	if got := cf.configCalls(issuer.id); got != 1 {
		t.Errorf("issuer config fetches within neg-TTL = %d, want 1 (negative cache should suppress re-resolution)", got)
	}

	// 3rd request AFTER the TTL: the negative entry expired -> it re-resolves
	// (count == 2). The short TTL means a legit issuer that just recovered is not
	// pinned out.
	nowNs.Add(int64(negTTL + time.Second))
	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Fatalf("3rd Get(after neg-TTL) = %v, want ErrNoSuchClient", err)
	}
	if got := cf.configCalls(issuer.id); got != 2 {
		t.Errorf("issuer config fetches after neg-TTL elapsed = %d, want 2 (should re-resolve)", got)
	}
}

// A LEGIT (anchor-authorized) issuer is NOT pinned out by the negative cache: it
// resolves and ADMITS on the first request, and a repeat within the TTL serves
// the POSITIVE cache (still admitted). Proves the negative cache never shadows a
// good issuer.
func TestTrustMarkResolvedDoS_NegativeCache_LegitIssuerNotPinned(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	anchorTMI := map[string][]string{tmType: {issuer.id}} // authorized
	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)
	f := buildMultiPairFederation(t, anchor, inter, anchorTMI,
		[]dosPair{{leaf: leaf, issuer: issuer, marks: []federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}}}})

	cf := newCountingFetcher(f)
	store := dosStore(t, cf, anchor, dosConfig([]string{tmType}, 4, 8, 30*time.Second), nil)

	for i := 0; i < 2; i++ {
		client, err := store.Get(context.Background(), leaf.id)
		if err != nil {
			t.Fatalf("Get #%d(legit anchor-authorized issuer) = %v, want admitted", i+1, err)
		}
		if client == nil || client.ID != leaf.id || !client.Federation {
			t.Fatalf("Get #%d derived client = %+v, want the federation client", i+1, client)
		}
	}
	// The positive cache served the 2nd request: the issuer resolved once.
	if got := cf.configCalls(issuer.id); got != 1 {
		t.Errorf("legit issuer config fetches over 2 admits = %d, want 1 (positive cache)", got)
	}
}

// ===========================================================================
// (d) leaf trust_marks COUNT cap.
// ===========================================================================

// A leaf carrying MORE than MaxLeafTrustMarks entries is rejected CLOSED before
// any per-type scan / nested resolution — defense-in-depth against an absurd-
// cardinality leaf. NO issuer is resolved (the scan is bounded out).
func TestTrustMarkResolvedDoS_LeafTrustMarkCountCap_Rejected(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	const cap = 4
	const count = cap + 2 // over the cap

	marks := make([]federation.TrustMarkEntry, count)
	for i := 0; i < count; i++ {
		m := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), int64(i)+1)
		marks[i] = federation.TrustMarkEntry{TrustMarkType: tmType, TrustMark: m}
	}
	anchorTMI := map[string][]string{tmType: {issuer.id}}
	f := buildMultiPairFederation(t, anchor, inter, anchorTMI, []dosPair{{leaf: leaf, issuer: issuer}})
	f.configs[leaf.id] = leafConfigWithTrustMarks(t, leaf, []string{inter.id},
		rpWithKeys(t, leaf, leaf.id+"/cb"), marks)

	cf := newCountingFetcher(f)
	cfg := dosConfig([]string{tmType}, 4, 8, 30*time.Second)
	cfg.MaxLeafTrustMarks = cap
	store := dosStore(t, cf, anchor, cfg, nil)

	if _, err := store.Get(context.Background(), leaf.id); !errors.Is(err, core.ErrNoSuchClient) {
		t.Fatalf("Get(leaf over trust_marks cap) = %v, want ErrNoSuchClient (count cap, fail-closed)", err)
	}
	if got := cf.configCalls(issuer.id); got != 0 {
		t.Errorf("issuer resolved despite leaf over the trust_marks cap (config fetches=%d), want 0 (scan bounded out)", got)
	}
}

// Under the cap, the gate behaves normally (a leaf with a few valid marks is
// admitted) — the count cap does not over-reject legitimate leaves.
func TestTrustMarkResolvedDoS_LeafTrustMarkCountUnderCap_Admitted(t *testing.T) {
	t.Parallel()
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, tcLeafID)
	issuer := newFedEntity(t, tmrIssuerID)

	anchorTMI := map[string][]string{tmType: {issuer.id}}
	mark := signTrustMark(t, issuer, leaf.id, tmType, fedClock.Unix(), 0)
	f := buildMultiPairFederation(t, anchor, inter, anchorTMI,
		[]dosPair{{leaf: leaf, issuer: issuer, marks: []federation.TrustMarkEntry{{TrustMarkType: tmType, TrustMark: mark}}}})

	cf := newCountingFetcher(f)
	cfg := dosConfig([]string{tmType}, 4, 8, 30*time.Second)
	cfg.MaxLeafTrustMarks = 8 // one mark is well under
	store := dosStore(t, cf, anchor, cfg, nil)

	if _, err := store.Get(context.Background(), leaf.id); err != nil {
		t.Fatalf("Get(one valid mark, under cap) = %v, want admitted", err)
	}
}

// ---------------------------------------------------------------------------
// distinct id helpers (stable per index, all HTTPS federation entity ids).
// ---------------------------------------------------------------------------

func dosIssuerID(i int) string { return "https://dos-issuer-" + itoa(i) + ".federation.test" }
func dosLeafID(i int) string   { return "https://dos-leaf-" + itoa(i) + ".federation.test" }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
