package degradation

import (
	"context"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/shared/spi"
)

// Health is one store-probe verdict. The tri-state exists so the auto driver
// can fail OPEN on probe uncertainty: only a definitive unhealthy verdict from
// the store itself may drive a read_only transition.
type Health int

const (
	// HealthHealthy reports the store reachable.
	HealthHealthy Health = iota
	// HealthUnhealthy reports the store definitively unreachable — the ONLY
	// verdict that counts toward a read_only transition.
	HealthUnhealthy
	// HealthUnknown reports the probe itself failed or timed out before
	// reaching a verdict. Fail-open: never counts toward a transition, and a
	// sweep containing only Unknown verdicts is treated as clean.
	HealthUnknown
)

// StoreHealthFunc probes one backing store and returns a verdict.
type StoreHealthFunc func(ctx context.Context) Health

// Probe names one watched store. The composition root adapts the existing
// storage-health Ping closures (the same functions behind the admin
// /storage-health report) into this port; the degradation package itself never
// imports interfaces/sso or internal/handler (layering points down).
type Probe struct {
	Name  string
	Check StoreHealthFunc
}

// DefaultAutoInterval is the poll cadence when
// degradation.auto_read_only.interval is <= 0.
const DefaultAutoInterval = 30 * time.Second

// DefaultAutoGrace is the continuous-unhealthy window a store must sustain
// before the driver flips read_only when degradation.auto_read_only.grace is
// <= 0. Twice the default interval, so the default tolerates one flapping
// sweep.
const DefaultAutoGrace = 60 * time.Second

// Per-probe timeout bounds: interval/2 keeps a sweep from overrunning the next
// tick; the floor prevents a degenerate tiny interval from starving the probe;
// the 3s ceiling mirrors the sibling storage-health probe convention
// (interfaces/sso storageHealthProbeTimeout).
const (
	minProbeTimeout = 100 * time.Millisecond
	maxProbeTimeout = 3 * time.Second
)

// Driver is the automatic degraded-mode driver behind
// degradation.auto_read_only_on_store_loss. It polls [Probe]s on a ticker and
// drives its [Manager] between baseline (the configured initial_mode) and
// ModeReadOnly:
//
//   - a store must be continuously unhealthy for at least the grace window
//     before SetMode(read_only) — transient probe jitter never flaps the mode;
//   - a clean sweep (every verdict Healthy or Unknown — probe uncertainty is
//     fail-open) clears the loss window, and when the current read_only was set
//     by this driver, restores baseline;
//   - the driver acts ONLY when the current mode equals baseline (degrade) or
//     is a driver-owned read_only (recover); any operator-set mode is left
//     untouched, and a read_only the driver did not set is never auto-restored.
//
// All transitions go through [Manager.SetMode], so the OnChange hook registered
// by WithDegradationManager logs + moves the mode gauge + records the audit
// event — the identical path the admin /api/v1/admin/dr/mode toggle uses.
type Driver struct {
	mgr      *Manager
	baseline Mode
	probes   []Probe
	interval time.Duration
	grace    time.Duration
	logger   spi.Logger

	// Sweep state, touched only by the Run loop's goroutine (no lock needed).
	lostSince   time.Time // zero = no continuous loss observed
	ownReadOnly bool      // the current read_only was set by this driver
}

// NewDriver builds the auto driver. baseline is the mode the driver restores
// to on recovery (the manager's boot posture, validated by the composition
// root). interval/grace <= 0 take the package defaults. Returns nil when mgr
// is nil (programming-error guard; the composition root pre-checks). With an
// invalid baseline the driver falls back to ModeNormal, mirroring
// NewManager's misconfiguration fallback.
func NewDriver(mgr *Manager, baseline Mode, probes []Probe, interval, grace time.Duration, logger spi.Logger) *Driver {
	if mgr == nil {
		return nil
	}
	if !baseline.Valid() {
		baseline = ModeNormal
	}
	if interval <= 0 {
		interval = DefaultAutoInterval
	}
	if grace <= 0 {
		grace = DefaultAutoGrace
	}
	if logger == nil {
		logger = spi.NopLogger{}
	}
	return &Driver{
		mgr: mgr, baseline: baseline, probes: probes,
		interval: interval, grace: grace, logger: logger,
	}
}

// Run starts the poll loop: one immediate sweep, then one sweep per interval.
// It returns a done channel closed when ctx is canceled (graceful shutdown —
// the caller owns ctx and pairs it with the standard cancel+done lifecycle).
func (d *Driver) Run(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.sweep(ctx)
		t := time.NewTicker(d.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				d.sweep(ctx)
			}
		}
	}()
	return done
}

// Interval returns the effective poll cadence (defaults applied).
func (d *Driver) Interval() time.Duration { return d.interval }

// Grace returns the effective continuous-unhealthy window (defaults applied).
func (d *Driver) Grace() time.Duration { return d.grace }

// StoreCount returns the number of watched stores (for boot logs).
func (d *Driver) StoreCount() int { return len(d.probes) }

// sweep runs one poll pass. State transitions:
//   - any probe Unhealthy: start/keep the loss window; when it has run >= grace
//     and the current mode is the baseline, flip read_only. Re-asserting at the
//     baseline is invariant enforcement: an operator who returns the mode to
//     the configured baseline while a store is still lost re-arms the driver.
//   - no probe Unhealthy (healthy or indeterminate): clear the loss window; if
//     the current read_only is driver-owned, restore baseline.
//   - any other current mode is left untouched (operator override wins).
func (d *Driver) sweep(ctx context.Context) {
	mode := d.mgr.Mode()
	if mode != ModeReadOnly {
		d.ownReadOnly = false
	}
	lost := d.probeOnce(ctx)
	now := time.Now()
	if len(lost) == 0 {
		d.lostSince = time.Time{}
	} else if d.lostSince.IsZero() {
		d.lostSince = now
	}
	switch {
	case len(lost) > 0 && mode == d.baseline && mode != ModeReadOnly && now.Sub(d.lostSince) >= d.grace:
		d.transition(ctx, ModeReadOnly, "auto_read_only: store loss ("+strings.Join(lost, ", ")+")")
		d.ownReadOnly = true
	case len(lost) == 0 && mode == ModeReadOnly && d.ownReadOnly:
		d.transition(ctx, d.baseline, "auto_read_only: store health recovered")
		d.ownReadOnly = false
	}
}

// probeOnce pings every watched store and returns the names of the stores with
// a definitive unhealthy verdict. Each probe is deadline-bounded; a probe that
// times out (HealthUnknown) is fail-open — it neither counts as loss nor blocks
// a clean sweep.
func (d *Driver) probeOnce(ctx context.Context) []string {
	var lost []string
	for _, p := range d.probes {
		probeCtx, cancel := context.WithTimeout(ctx, d.probeTimeout())
		switch p.Check(probeCtx) {
		case HealthUnhealthy:
			lost = append(lost, p.Name)
			d.logger.Error("degradation: auto driver store unhealthy", "store", p.Name)
		case HealthUnknown:
			d.logger.Debug("degradation: auto driver probe indeterminate — fail-open", "store", p.Name)
		}
		cancel()
	}
	return lost
}

// probeTimeout bounds ONE store probe. interval/2 keeps a sweep from
// overrunning the next tick; the floor/ceiling clamps are documented on the
// min/max constants.
func (d *Driver) probeTimeout() time.Duration {
	t := d.interval / 2
	if t < minProbeTimeout {
		t = minProbeTimeout
	}
	if t > maxProbeTimeout {
		t = maxProbeTimeout
	}
	return t
}

// transition drives a mode change through the Manager. Errors are logged and
// swallowed (the modes passed are compile-time constants, so ErrInvalidMode is
// unreachable; a no-op transition fires no OnChange hook, so an already-degraded
// sweep does not spam audit). The OnChange hook (audit + metric gauge) is the
// shared path with the admin dr/mode toggle, so no driver-specific side effects
// are needed here.
func (d *Driver) transition(ctx context.Context, to Mode, reason string) {
	if _, err := d.mgr.SetMode(ctx, to, reason); err != nil {
		d.logger.Error("degradation: auto driver mode transition failed", "to", string(to), "error", err)
	}
}
