package tokenanomaly

import (
	"context"
	"sync"
	"time"

	"github.com/snaplink/sso/domains/tokenusage"
)

// Default tuning. All are relative/adaptive rather than absolute-rate
// thresholds so operators rarely need to touch them.
const (
	// defaultMaxThumbprints bounds the per-thumbprint observation table so
	// the detector's memory is a rolling window, not an archive (mirrors the
	// tokenusage memory store's bucket cap). At the cap the oldest-first-seen
	// thumbprint is evicted.
	defaultMaxThumbprints = 4096
	// defaultWindow is the look-back for BOTH the geo/velocity observation
	// freshness gate and the rate-spike baseline query.
	defaultWindow = 15 * time.Minute
	// defaultVelocityGap: two DISTINCT-geo sightings of one thumbprint closer
	// together than this imply impossible travel (critical). Generous enough
	// to not flag a genuine cross-border trip, tight enough to catch a token
	// used from two continents "simultaneously".
	defaultVelocityGap = 5 * time.Minute
	// defaultSpikeFactor: a client's latest-minute issuance count must exceed
	// its own trailing baseline by this multiple to be a spike. Per-client
	// adaptive — a high-volume client's normal traffic never trips it.
	defaultSpikeFactor = 3.0
	// defaultSpikeMinCount is the absolute floor below which a "spike" is
	// noise (1->3 is not an incident). Suppresses low-volume false positives.
	defaultSpikeMinCount = 20
)

// observation is the detector's per-thumbprint working state, updated off the
// hot path in Record and read (under lock) by Analyze. Bounded by the
// enclosing map's cap.
type observation struct {
	clientID  string
	subjectID string
	// geos counts sightings per coarse geo; its length is the distinct-geo
	// cardinality the multi_geo signal keys on.
	geos      map[string]int
	first     time.Time
	last      time.Time
	count     int64
	lastGeo   string
	lastGeoAt time.Time
	// minSwitch is the smallest interval observed between two consecutive
	// DISTINCT-geo sightings — the impossible-travel measure. Zero = never
	// switched geo.
	minSwitch time.Duration
}

// Detector decorates a [tokenusage.Store]: it forwards Record/Query verbatim
// (so the wave-1 usage read API is byte-identical) while ALSO capturing a
// bounded per-thumbprint observation on each Record — the raw geo/subject the
// aggregating store discards. A periodic [Detector.Analyze] sweep turns those
// observations plus the client-rate buckets into [Finding]s.
//
// It is wired as the Recorder's store, so every capture happens on the
// recorder's drain goroutine — OFF the request path, exactly like the
// aggregation it wraps.
type Detector struct {
	next     tokenusage.Store
	findings FindingStore

	mu    sync.Mutex
	obs   map[string]*observation
	order []string // thumbprint insertion order; eviction pops the front.

	maxThumbs     int
	window        time.Duration
	velocityGap   time.Duration
	spikeFactor   float64
	spikeMinCount int64

	// onFinding is the metric hook (findingType, severity). Nil-safe; set by
	// the composition root when a metrics registry is wired.
	onFinding func(findingType, severity string)
	// clock is overridable for deterministic tests. Defaults to time.Now.
	clock func() time.Time
}

// The Detector decorates a tokenusage.Store (forwarding Record/Query) and, when
// the wrapped store reports cardinality, its TrackedBucketReporter — so it drops
// in as the wave-1 Recorder's store without changing the usage read API.
var (
	_ tokenusage.Store                 = (*Detector)(nil)
	_ tokenusage.TrackedBucketReporter = (*Detector)(nil)
)

// Option tunes a Detector at construction.
type Option func(*Detector)

// WithMaxThumbprints overrides the observation-table cap (non-positive
// ignored).
func WithMaxThumbprints(n int) Option {
	return func(d *Detector) {
		if n > 0 {
			d.maxThumbs = n
		}
	}
}

// WithWindow overrides the analysis look-back (non-positive ignored).
func WithWindow(w time.Duration) Option {
	return func(d *Detector) {
		if w > 0 {
			d.window = w
		}
	}
}

// WithVelocityGap overrides the impossible-travel interval (non-positive
// ignored).
func WithVelocityGap(g time.Duration) Option {
	return func(d *Detector) {
		if g > 0 {
			d.velocityGap = g
		}
	}
}

// WithSpikeFactor overrides the per-client rate-spike multiple (values <= 1
// ignored — a factor of 1 or less would flag every minute).
func WithSpikeFactor(f float64) Option {
	return func(d *Detector) {
		if f > 1 {
			d.spikeFactor = f
		}
	}
}

// WithSpikeMinCount overrides the absolute spike floor (non-positive ignored).
func WithSpikeMinCount(n int64) Option {
	return func(d *Detector) {
		if n > 0 {
			d.spikeMinCount = n
		}
	}
}

// WithFindingHook installs the metric emitter fired for each emitted finding.
func WithFindingHook(h func(findingType, severity string)) Option {
	return func(d *Detector) { d.onFinding = h }
}

// WithClock overrides the time source (tests inject a fixed clock).
func WithClock(c func() time.Time) Option {
	return func(d *Detector) {
		if c != nil {
			d.clock = c
		}
	}
}

// NewDetector builds a Detector wrapping next and emitting to findings.
// Returns nil when next is nil — every method on a nil *Detector is a safe
// no-op, so callers can wire it unconditionally (mirrors
// tokenusage.NewRecorder). findings may be nil: Analyze still computes and
// returns findings but skips persistence.
func NewDetector(next tokenusage.Store, findings FindingStore, opts ...Option) *Detector {
	if next == nil {
		return nil
	}
	d := &Detector{
		next:          next,
		findings:      findings,
		obs:           make(map[string]*observation),
		maxThumbs:     defaultMaxThumbprints,
		window:        defaultWindow,
		velocityGap:   defaultVelocityGap,
		spikeFactor:   defaultSpikeFactor,
		spikeMinCount: defaultSpikeMinCount,
		clock:         time.Now,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Findings exposes the backing finding store for the admin read API. Nil-safe.
func (d *Detector) Findings() FindingStore {
	if d == nil {
		return nil
	}
	return d.findings
}

// SetFindingHook installs the metric emitter fired for each finding an Analyze
// sweep emits. Safe to call after construction; the composition root wires it
// once at NewServer time (before the sweeper starts). Guarded by d.mu so it
// can't race the sweeper's read. Nil-safe.
func (d *Detector) SetFindingHook(h func(findingType, severity string)) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.onFinding = h
	d.mu.Unlock()
}

// findingHook reads the metric emitter under lock so the read can't race
// SetFindingHook.
func (d *Detector) findingHook() func(findingType, severity string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.onFinding
}

// Record forwards the event to the wrapped store (the wave-1 aggregation) and
// captures a per-thumbprint observation for geo/velocity analysis. Called on
// the recorder's drain goroutine — never the request path. A capture never
// fails; the store's error is returned verbatim so the recorder's fail-open
// logging is unchanged.
func (d *Detector) Record(ctx context.Context, ev tokenusage.Event) error {
	if d == nil {
		return nil
	}
	err := d.next.Record(ctx, ev)
	if ev.Thumbprint != "" {
		d.recordObservation(ev)
	}
	return err
}

// Query forwards to the wrapped store unchanged — the usage read API sees the
// same buckets it would without the detector.
func (d *Detector) Query(ctx context.Context, q tokenusage.Query) ([]tokenusage.Bucket, error) {
	if d == nil {
		return nil, nil
	}
	return d.next.Query(ctx, q)
}

// TrackedBuckets forwards the wrapped store's cardinality when it reports one,
// so the wave-1 tracked-bucket gauge keeps working through the decorator.
func (d *Detector) TrackedBuckets() int {
	if d == nil {
		return 0
	}
	if rep, ok := d.next.(tokenusage.TrackedBucketReporter); ok {
		return rep.TrackedBuckets()
	}
	return 0
}

// recordObservation folds one thumbprint-bearing event into its observation,
// evicting the oldest thumbprint at cap. Caller must NOT hold d.mu.
func (d *Detector) recordObservation(ev tokenusage.Event) {
	at := ev.At
	if at.IsZero() {
		at = d.clock()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	o, ok := d.obs[ev.Thumbprint]
	if !ok {
		if len(d.obs) >= d.maxThumbs {
			d.evictOldestLocked()
		}
		o = &observation{geos: make(map[string]int), first: at}
		d.obs[ev.Thumbprint] = o
		d.order = append(d.order, ev.Thumbprint)
	}
	o.clientID = ev.ClientID
	if ev.SubjectID != "" {
		o.subjectID = ev.SubjectID
	}
	o.count++
	o.last = at
	d.updateGeoLocked(o, ev.GeoCountry, at)
}

// updateGeoLocked records a geo sighting and refreshes the impossible-travel
// measure. Caller holds d.mu.
func (d *Detector) updateGeoLocked(o *observation, geo string, at time.Time) {
	if geo == "" {
		return
	}
	o.geos[geo]++
	if o.lastGeo != "" && o.lastGeo != geo {
		gap := at.Sub(o.lastGeoAt)
		if gap < 0 {
			gap = -gap
		}
		if o.minSwitch == 0 || gap < o.minSwitch {
			o.minSwitch = gap
		}
	}
	o.lastGeo = geo
	o.lastGeoAt = at
}

// evictOldestLocked drops the earliest-inserted thumbprint. Caller holds d.mu.
func (d *Detector) evictOldestLocked() {
	if len(d.order) == 0 {
		return
	}
	delete(d.obs, d.order[0])
	d.order = d.order[1:]
}

// Analyze runs one detection sweep OFF the request path: it inspects the
// captured per-thumbprint observations (geo/velocity) plus the wrapped store's
// per-client rate buckets (rate_spike), emits every finding to the finding
// store, fires the metric hook, and returns the findings (for tests/callers).
// A finding-store write error is collected but never aborts the sweep — the
// remaining findings still emit. NEVER feeds an auth decision.
func (d *Detector) Analyze(ctx context.Context) ([]Finding, error) {
	if d == nil {
		return nil, nil
	}
	now := d.clock()
	findings := d.detectGeoVelocity(now)
	findings = append(findings, d.detectRateSpike(ctx, now)...)

	hook := d.findingHook()
	var firstErr error
	for _, f := range findings {
		if d.findings != nil {
			if err := d.findings.Add(ctx, f); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if hook != nil {
			hook(f.Type, string(f.Severity))
		}
	}
	return findings, firstErr
}
