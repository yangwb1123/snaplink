package tokenanomaly

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/snaplink/sso/domains/tokenusage"
)

// detectGeoVelocity scans the per-thumbprint observations for tokens seen from
// multiple distinct coarse geos. A single bearer token roaming countries is
// the pattern; two distinct-geo sightings closer than velocityGap is
// impossible travel (critical). Only observations whose LAST sighting is
// within the analysis window are considered, so a stale token that has since
// gone quiet stops being re-reported.
func (d *Detector) detectGeoVelocity(now time.Time) []Finding {
	cutoff := now.Add(-d.window)
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Finding, 0)
	for tp, o := range d.obs {
		if len(o.geos) < 2 || o.last.Before(cutoff) {
			continue
		}
		out = append(out, d.geoFinding(tp, o))
	}
	// Stable order (by thumbprint) so the sweep output is deterministic for
	// tests and the finding store's upsert order is repeatable.
	sort.Slice(out, func(i, j int) bool { return out[i].Thumbprint < out[j].Thumbprint })
	return out
}

// geoFinding builds the multi_geo or velocity finding for one observation.
// Caller holds d.mu.
func (d *Detector) geoFinding(thumbprint string, o *observation) Finding {
	geos := make([]string, 0, len(o.geos))
	for g := range o.geos {
		geos = append(geos, g)
	}
	sort.Strings(geos)

	f := Finding{
		Thumbprint: thumbprint,
		ClientID:   o.clientID,
		SubjectID:  o.subjectID,
		Geos:       geos,
		Count:      o.count,
		FirstSeen:  o.first,
		LastSeen:   o.last,
	}
	switch {
	case o.minSwitch > 0 && o.minSwitch <= d.velocityGap:
		f.Type = FindingVelocity
		f.Severity = SeverityCritical
		f.Detail = fmt.Sprintf("token used from %d coarse geos with a %s gap between distinct geos (<= %s implies impossible travel)",
			len(geos), o.minSwitch.Round(time.Second), d.velocityGap)
	default:
		f.Type = FindingMultiGeo
		f.Severity = SeverityWarn
		if len(geos) >= 3 {
			f.Severity = SeverityCritical
		}
		f.Detail = fmt.Sprintf("token used from %d distinct coarse geos within the analysis window", len(geos))
	}
	return f
}

// clientMinuteRates is a per-client map of UTC-minute (unix seconds) -> count,
// summed across kind + endpoint. It is the shape rate-spike analysis needs
// from the aggregated buckets.
type clientMinuteRates map[string]map[int64]int64

// detectRateSpike queries the wrapped store for the window's buckets and
// flags any client whose most-recent-minute issuance count broke well above
// its own trailing baseline. Adaptive (per-client baseline * spikeFactor) with
// an absolute floor, so a busy client's normal traffic never trips it and a
// tiny 1->3 blip is ignored. A store error yields no findings (fail-open —
// detection never escalates a telemetry-store outage).
func (d *Detector) detectRateSpike(ctx context.Context, now time.Time) []Finding {
	since := now.Add(-d.window)
	buckets, err := d.next.Query(ctx, tokenusage.Query{Since: since})
	if err != nil {
		return nil
	}
	rates := foldClientMinuteRates(buckets)
	clients := make([]string, 0, len(rates))
	for c := range rates {
		clients = append(clients, c)
	}
	sort.Strings(clients) // deterministic sweep order.

	out := make([]Finding, 0)
	for _, c := range clients {
		if f, ok := d.spikeForClient(c, rates[c]); ok {
			out = append(out, f)
		}
	}
	return out
}

// foldClientMinuteRates collapses (client, kind, endpoint, minute) buckets
// into per-client per-minute totals.
func foldClientMinuteRates(buckets []tokenusage.Bucket) clientMinuteRates {
	rates := make(clientMinuteRates)
	for _, b := range buckets {
		byMin := rates[b.ClientID]
		if byMin == nil {
			byMin = make(map[int64]int64)
			rates[b.ClientID] = byMin
		}
		byMin[b.Minute.Unix()] += b.Count
	}
	return rates
}

// spikeForClient decides whether one client's minute series contains a
// latest-minute spike: the newest minute's count must clear the absolute floor
// AND exceed the mean of the EARLIER minutes by spikeFactor. Needs at least
// two earlier minutes of baseline, so a brand-new client can't self-trip.
func (d *Detector) spikeForClient(clientID string, byMin map[int64]int64) (Finding, bool) {
	if len(byMin) < 3 {
		return Finding{}, false
	}
	minutes := make([]int64, 0, len(byMin))
	for m := range byMin {
		minutes = append(minutes, m)
	}
	sort.Slice(minutes, func(i, j int) bool { return minutes[i] < minutes[j] })

	latest := minutes[len(minutes)-1]
	latestCount := byMin[latest]
	if latestCount < d.spikeMinCount {
		return Finding{}, false
	}
	var sum int64
	for _, m := range minutes[:len(minutes)-1] {
		sum += byMin[m]
	}
	baseline := float64(sum) / float64(len(minutes)-1)
	if baseline <= 0 || float64(latestCount) <= baseline*d.spikeFactor {
		return Finding{}, false
	}
	return Finding{
		Type:      FindingRateSpike,
		Severity:  SeverityWarn,
		ClientID:  clientID,
		Count:     latestCount,
		FirstSeen: time.Unix(minutes[0], 0).UTC(),
		LastSeen:  time.Unix(latest, 0).UTC(),
		Detail: fmt.Sprintf("latest-minute count %d is %.1fx the %.1f/min trailing baseline",
			latestCount, float64(latestCount)/baseline, baseline),
	}, true
}
