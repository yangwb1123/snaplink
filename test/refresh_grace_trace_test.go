package ssotest

import (
	"sync/atomic"
	"time"
)

type inflightPhase uint32

const (
	inflightUnknown inflightPhase = iota + 1
	inflightAuth
	inflightFirstHTTP
	inflightSecondHTTP
	inflightConsume
	inflightReuseSent
	inflightIssue
	inflightIssuerEntered
	inflightIssuerReleased
	inflightIssuerCanceled
	inflightSigning
	inflightGraceLookup
	inflightGraceRemember
	inflightGracePrepare
	inflightWinnerRequest
	inflightLoserRequest
	inflightBaselineRequest
	inflightRetryRequest
	inflightWinnerLaunch
	inflightLoserLaunch
	inflightIssuerObserved
	inflightReuseObserved
	inflightFixtureRelease
)

var inflightPhaseNames = [...]string{
	inflightUnknown:         "unknown",
	inflightAuth:            "client-auth",
	inflightFirstHTTP:       "server-first",
	inflightSecondHTTP:      "server-second",
	inflightConsume:         "consume",
	inflightReuseSent:       "reuse-notified",
	inflightIssue:           "issuer",
	inflightIssuerEntered:   "issuer-entered",
	inflightIssuerReleased:  "issuer-released",
	inflightIssuerCanceled:  "issuer-canceled",
	inflightSigning:         "signing",
	inflightGraceLookup:     "grace-lookup",
	inflightGraceRemember:   "grace-remember",
	inflightGracePrepare:    "grace-prepare",
	inflightWinnerRequest:   "winner-request",
	inflightLoserRequest:    "loser-request",
	inflightBaselineRequest: "baseline-request",
	inflightRetryRequest:    "retry-request",
	inflightWinnerLaunch:    "winner-launch",
	inflightLoserLaunch:     "loser-launch",
	inflightIssuerObserved:  "issuer-observed",
	inflightReuseObserved:   "reuse-observed",
	inflightFixtureRelease:  "fixture-release",
}

type inflightTraceEvent struct {
	phase   atomic.Uint32
	started atomic.Int64
	ended   atomic.Int64
}

// Fixed, append-only slots avoid adding lock coordination or logging to requests.
// Phase publishes initialization; ended stores monotonic offset+1 (zero is active).
// A failure snapshot may observe reserved but not yet published slots.
type inflightTrace struct {
	origin   time.Time
	reserved atomic.Uint64
	events   [256]inflightTraceEvent
}

func newInflightTrace() *inflightTrace {
	return &inflightTrace{origin: time.Now()}
}

func (trace *inflightTrace) begin(phase inflightPhase) int {
	if trace == nil || trace.origin.IsZero() {
		return -1
	}
	index := trace.reserved.Add(1) - 1
	if index >= uint64(len(trace.events)) {
		return -1
	}
	if phase == 0 || uint64(phase) >= uint64(len(inflightPhaseNames)) {
		phase = inflightUnknown
	}
	event := &trace.events[index]
	event.started.Store(time.Since(trace.origin).Nanoseconds())
	event.phase.Store(uint32(phase))
	return int(index)
}

func (trace *inflightTrace) finish(index int) {
	if trace == nil || index < 0 || index >= len(trace.events) {
		return
	}
	trace.events[index].ended.Store(time.Since(trace.origin).Nanoseconds() + 1)
}

func (trace *inflightTrace) mark(phase inflightPhase) {
	trace.finish(trace.begin(phase))
}

func (trace *inflightTrace) report(failed bool, logf func(string, ...any)) {
	if !failed || trace == nil || logf == nil {
		return
	}
	reserved := trace.reserved.Load()
	count := min(reserved, uint64(len(trace.events)))
	logf("%s reserved=%d retained=%d dropped=%d", inflightTracePrefix, reserved, count, reserved-count)
	unpublished := 0
	for index := uint64(0); index < count; index++ {
		event := &trace.events[index]
		phase := event.phase.Load()
		if phase == 0 {
			unpublished++
			continue
		}
		start, end := event.started.Load(), event.ended.Load()
		complete := end != 0
		if complete {
			end--
		}
		logf("%s phase=%s start_ns=%d end_ns=%d complete=%t", inflightTracePrefix, inflightPhaseNames[phase], start, end, complete)
	}
	if unpublished != 0 {
		logf("%s unpublished=%d", inflightTracePrefix, unpublished)
	}
}
