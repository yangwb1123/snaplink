package auditreport

import (
	"sort"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// areaAccumulator collects per-bucket counts while BuildSOC2Report walks
// a bundle's events once. Kept separate from ControlArea itself so
// ByOutcome/actors stay nil until first use — apply only allocates them
// when at least one event landed in the bucket, matching
// ControlArea.ByOutcome's `omitempty` JSON tag (a zero-event area
// renders without a spurious empty object).
type areaAccumulator struct {
	total     int
	byOutcome map[string]int
	actors    map[string]struct{}
}

func newAreaAccumulator() *areaAccumulator { return &areaAccumulator{} }

func newAreaAccumulators(n int) []*areaAccumulator {
	out := make([]*areaAccumulator, n)
	for i := range out {
		out[i] = newAreaAccumulator()
	}
	return out
}

// add folds one event into the accumulator. An empty ActorID never
// contributes to DistinctActors — some event types (e.g. system/
// bootstrap events) carry no actor.
func (a *areaAccumulator) add(e *audit.Event) {
	a.total++
	if a.byOutcome == nil {
		a.byOutcome = make(map[string]int, 2)
	}
	a.byOutcome[string(e.Outcome)]++
	if e.ActorID == "" {
		return
	}
	if a.actors == nil {
		a.actors = make(map[string]struct{})
	}
	a.actors[e.ActorID] = struct{}{}
}

// apply writes the accumulated counts onto area.
func (a *areaAccumulator) apply(area *ControlArea) {
	area.TotalEvents = a.total
	area.ByOutcome = a.byOutcome
	area.DistinctActors = len(a.actors)
}

// sortEventTypes sorts s in place lexically so ControlArea.EventTypes
// (built from Go map iteration in the Uncategorized case) is
// deterministic across runs — required for stable JSON output and
// reproducible tests.
func sortEventTypes(s []audit.EventType) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}
