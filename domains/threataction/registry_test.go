package threataction

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

// testPolicyStore is a simple in-memory policy store for testing.
type testPolicyStore struct {
	mu       sync.Mutex
	policies map[string]ThreatPolicy
}

func newTestPolicyStore() *testPolicyStore {
	return &testPolicyStore{policies: make(map[string]ThreatPolicy)}
}

func (s *testPolicyStore) List(_ context.Context) ([]ThreatPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ThreatPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, p)
	}
	return out, nil
}

func (s *testPolicyStore) Get(_ context.Context, name string) (*ThreatPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[name]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	return &p, nil
}

func (s *testPolicyStore) Put(_ context.Context, policy ThreatPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[policy.Name] = policy
	return nil
}

func (s *testPolicyStore) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, name)
	return nil
}

func TestThreatExecutors_NoMatchingPolicy(t *testing.T) {
	store := newTestPolicyStore()
	exec := NewThreatExecutors(store, nil, nil)
	result, err := exec.Execute(context.Background(), Threat{
		Type:      "impossible_travel",
		Severity:  SeverityCritical,
		SubjectID: "user1",
	}, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Action != ActionNoop {
		t.Errorf("expected noop, got %s", result.Action)
	}
}

func TestThreatExecutors_NilPolicyStore(t *testing.T) {
	exec := NewThreatExecutors(nil, nil, nil)
	result, err := exec.Execute(context.Background(), Threat{
		Type:      "impossible_travel",
		Severity:  SeverityCritical,
		SubjectID: "user1",
	}, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Action != ActionNoop {
		t.Errorf("expected noop, got %s", result.Action)
	}
}

func TestThreatExecutors_PolicyMatchRoutesToHandler(t *testing.T) {
	store := newTestPolicyStore()
	_ = store.Put(context.Background(), ThreatPolicy{
		Name:    "critical-suspend",
		Enabled: true,
		Type:    "impossible_travel",
		Action:  ActionSuspend,
	})

	var executed bool
	var mu sync.Mutex
	handler := ExecuteFunc(func(_ context.Context, _ Threat, _ ThreatPolicy) (ActionResult, error) {
		mu.Lock()
		executed = true
		mu.Unlock()
		return ActionResult{Action: ActionSuspend, OK: true, Detail: "suspended"}, nil
	})

	exec := NewThreatExecutors(store, map[Action]ThreatExecutor{
		ActionSuspend: handler,
	}, nil)

	result, err := exec.Execute(context.Background(), Threat{
		Type:      "impossible_travel",
		Severity:  SeverityCritical,
		SubjectID: "user1",
	}, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Action != ActionSuspend {
		t.Errorf("expected suspend, got %s", result.Action)
	}
	if !result.OK {
		t.Error("expected OK")
	}
	if !executed {
		t.Error("handler was not executed")
	}
}

func TestThreatExecutors_NoHandlerForAction(t *testing.T) {
	store := newTestPolicyStore()
	_ = store.Put(context.Background(), ThreatPolicy{
		Name:    "critical-suspend",
		Enabled: true,
		Type:    "impossible_travel",
		Action:  ActionSuspend,
	})

	// No handler registered for ActionSuspend.
	exec := NewThreatExecutors(store, map[Action]ThreatExecutor{}, nil, WithLogger(testLogger{t}))

	result, err := exec.Execute(context.Background(), Threat{
		Type:      "impossible_travel",
		Severity:  SeverityCritical,
		SubjectID: "user1",
	}, ThreatPolicy{})
	if err == nil {
		t.Fatal("expected error for missing handler")
	}
	if result.OK {
		t.Error("expected not OK")
	}
}

func TestThreatExecutors_RateLimit(t *testing.T) {
	store := newTestPolicyStore()
	_ = store.Put(context.Background(), ThreatPolicy{
		Name:    "critical-suspend",
		Enabled: true,
		Type:    "impossible_travel",
		Action:  ActionSuspend,
		RateLimit: &RateLimitPolicy{
			PerWindow: Duration{Duration: time.Minute},
			Max:       2,
		},
	})

	var callCount int
	var mu sync.Mutex
	handler := ExecuteFunc(func(_ context.Context, _ Threat, _ ThreatPolicy) (ActionResult, error) {
		mu.Lock()
		callCount++
		mu.Unlock()
		return ActionResult{Action: ActionSuspend, OK: true, Detail: "suspended"}, nil
	})

	exec := NewThreatExecutors(store, map[Action]ThreatExecutor{
		ActionSuspend: handler,
	}, nil, WithLogger(testLogger{t}))

	ctx := context.Background()
	threat := Threat{Type: "impossible_travel", Severity: SeverityCritical, SubjectID: "user1"}

	// First two should succeed.
	for i := 0; i < 2; i++ {
		result, err := exec.Execute(ctx, threat, ThreatPolicy{})
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if !result.OK {
			t.Errorf("call %d: expected OK, got %v", i, result)
		}
	}

	// Third should be rate-limited.
	result, err := exec.Execute(ctx, threat, ThreatPolicy{})
	if err != nil {
		t.Fatalf("third call: unexpected error: %v", err)
	}
	if result.OK {
		t.Error("expected rate-limited (not OK)")
	}
	if callCount != 2 {
		t.Errorf("expected 2 handler calls, got %d", callCount)
	}
}

func TestThreatExecutors_RateLimitSweepEvictsExpiredEntries(t *testing.T) {
	origThreshold := rateLimitSweepThreshold
	rateLimitSweepThreshold = 5
	defer func() { rateLimitSweepThreshold = origThreshold }()

	exec := NewThreatExecutors(nil, nil, nil, WithLogger(testLogger{t}))
	rl := &RateLimitPolicy{PerWindow: Duration{Duration: 25 * time.Millisecond}, Max: 100}

	// Populate more distinct (subject, type, action) keys than the
	// (shrunk) sweep threshold. None of these subjects ever recurs after
	// this loop — exactly the "stops being looked up" scenario that a
	// lazy-only cleanup can't reach.
	for i := 0; i < 6; i++ {
		threat := Threat{SubjectID: fmt.Sprintf("user-%d", i), Type: "impossible_travel"}
		if !exec.allow(threat, ActionSuspend, rl) {
			t.Fatalf("call %d: expected allow (fresh key)", i)
		}
	}

	exec.mu.Lock()
	sizeBeforeExpiry := len(exec.rateLimit)
	exec.mu.Unlock()
	if sizeBeforeExpiry != 6 {
		t.Fatalf("expected 6 entries before expiry, got %d", sizeBeforeExpiry)
	}

	// Let every entry's window pass — a generous multiple of PerWindow so
	// this isn't a tight timing assertion.
	time.Sleep(150 * time.Millisecond)

	// One more distinct key pushes len(rateLimit) past rateLimitSweepThreshold;
	// allow() must sweep the now-expired entries before inserting the new one.
	newThreat := Threat{SubjectID: "user-new", Type: "impossible_travel"}
	if !exec.allow(newThreat, ActionSuspend, rl) {
		t.Fatal("expected allow for new key")
	}

	exec.mu.Lock()
	size := len(exec.rateLimit)
	_, newKeyPresent := exec.rateLimit[RateLimitKey("user-new", "impossible_travel", ActionSuspend)]
	exec.mu.Unlock()

	if !newKeyPresent {
		t.Fatal("expected the newly-inserted key to survive its own insertion")
	}
	if size != 1 {
		t.Errorf("expected map to shrink back to 1 entry after sweeping 6 expired entries, got %d", size)
	}
}

func TestThreatExecutors_RateLimitMapBoundedOverManyDistinctKeys(t *testing.T) {
	origThreshold := rateLimitSweepThreshold
	rateLimitSweepThreshold = 10
	defer func() { rateLimitSweepThreshold = origThreshold }()

	exec := NewThreatExecutors(nil, nil, nil, WithLogger(testLogger{t}))
	rl := &RateLimitPolicy{PerWindow: Duration{Duration: 15 * time.Millisecond}, Max: 100}

	const rounds = 5
	const keysPerRound = 8
	for round := 0; round < rounds; round++ {
		for i := 0; i < keysPerRound; i++ {
			threat := Threat{SubjectID: fmt.Sprintf("round%d-user%d", round, i), Type: "velocity_burst"}
			exec.allow(threat, ActionSuspend, rl)
		}
		// Let this round's entries expire before the next round starts —
		// simulates distinct subjects that never recur once their burst
		// of activity ends.
		time.Sleep(60 * time.Millisecond)
	}

	exec.mu.Lock()
	size := len(exec.rateLimit)
	exec.mu.Unlock()

	// rounds*keysPerRound = 40 total distinct keys were looked up across
	// the run. Without the opportunistic sweep, none would ever be
	// looked up again so all 40 would still be resident. The sweep
	// should have reclaimed each prior round's expired entries well
	// before the map reached that size.
	const totalKeysSeen = rounds * keysPerRound
	if size >= totalKeysSeen {
		t.Errorf("rateLimit map appears unbounded: %d entries resident after %d total keys seen", size, totalKeysSeen)
	}
}

func TestThreatExecutors_RecordEvidenceBoundsKeyCount(t *testing.T) {
	te := NewThreatExecutors(nil, nil, nil, WithLogger(testLogger{t}))

	evidence := make(map[string]string, maxEvidenceKeys+10)
	for i := 0; i < maxEvidenceKeys+10; i++ {
		evidence[fmt.Sprintf("k%d", i)] = fmt.Sprintf("v%d", i)
	}

	e := &audit.Event{}
	te.recordEvidence(e, Threat{Type: "t", SubjectID: "user1", Evidence: evidence})

	count := 0
	for k := range e.Metadata {
		if strings.HasPrefix(k, "threat.evidence.") {
			count++
		}
	}
	if count > maxEvidenceKeys {
		t.Errorf("expected at most %d evidence keys in audit metadata, got %d", maxEvidenceKeys, count)
	}
	if count == 0 {
		t.Error("expected some evidence keys to survive truncation, got none")
	}
}

func TestThreatExecutors_RecordEvidenceTruncatesLongKeyAndValue(t *testing.T) {
	te := NewThreatExecutors(nil, nil, nil, WithLogger(testLogger{t}))

	longKey := strings.Repeat("k", maxEvidenceKeyLen+50)
	longVal := strings.Repeat("v", maxEvidenceValueLen+50)

	e := &audit.Event{}
	te.recordEvidence(e, Threat{
		Type: "t", SubjectID: "user1",
		Evidence: map[string]string{longKey: longVal},
	})

	if len(e.Metadata) != 1 {
		t.Fatalf("expected exactly 1 metadata entry, got %d: %v", len(e.Metadata), e.Metadata)
	}
	for k, v := range e.Metadata {
		gotKeySuffix := strings.TrimPrefix(k, "threat.evidence.")
		if len(gotKeySuffix) != maxEvidenceKeyLen {
			t.Errorf("expected truncated key len %d, got %d", maxEvidenceKeyLen, len(gotKeySuffix))
		}
		if len(v) != maxEvidenceValueLen {
			t.Errorf("expected truncated value len %d, got %d", maxEvidenceValueLen, len(v))
		}
	}
}

func TestThreatExecutors_RecordEvidenceWithinBoundsUnchanged(t *testing.T) {
	te := NewThreatExecutors(nil, nil, nil, WithLogger(testLogger{t}))

	evidence := map[string]string{
		"distance_km": "5000",
		"country":     "US",
	}
	e := &audit.Event{}
	te.recordEvidence(e, Threat{Type: "t", SubjectID: "user1", Evidence: evidence})

	want := map[string]string{
		"threat.evidence.distance_km": "5000",
		"threat.evidence.country":     "US",
	}
	if len(e.Metadata) != len(want) {
		t.Fatalf("expected %d metadata entries (byte-identical to a plain range+SetMeta loop), got %d: %v",
			len(want), len(e.Metadata), e.Metadata)
	}
	for k, v := range want {
		if e.Metadata[k] != v {
			t.Errorf("metadata[%q] = %q, want %q", k, e.Metadata[k], v)
		}
	}
}

func TestThreatExecutors_NilExecutorIsSafe(t *testing.T) {
	var exec *ThreatExecutors
	result, err := exec.Execute(context.Background(), Threat{
		Type:      "test",
		Severity:  SeverityInfo,
		SubjectID: "user1",
	}, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Action != ActionNoop {
		t.Errorf("expected noop, got %s", result.Action)
	}
}

func TestThreatExecutors_AuditEventRecordedOnNonNoop(t *testing.T) {
	store := newTestPolicyStore()
	_ = store.Put(context.Background(), ThreatPolicy{
		Name:    "critical-suspend",
		Enabled: true,
		Type:    "impossible_travel",
		Action:  ActionSuspend,
	})

	handler := ExecuteFunc(func(_ context.Context, _ Threat, _ ThreatPolicy) (ActionResult, error) {
		return ActionResult{Action: ActionSuspend, OK: true, Detail: "suspended"}, nil
	})

	recorder := audit.New(audit.NewMemorySink(100))
	exec := NewThreatExecutors(store, map[Action]ThreatExecutor{
		ActionSuspend: handler,
	}, recorder, WithLogger(testLogger{t}))

	_, _ = exec.Execute(context.Background(), Threat{
		Type:      "impossible_travel",
		Severity:  SeverityCritical,
		SubjectID: "user1",
		ClientID:  "client1",
	}, ThreatPolicy{})

	sink := recorder.Sink().(*audit.MemorySink)
	if sink.Len() != 1 {
		t.Fatalf("expected 1 audit event, got %d", sink.Len())
	}
}

// testLogger adapts testing.T to spi.Logger.
type testLogger struct {
	t testing.TB
}

func logKV(prefix, msg string, keysAndValues ...any) string {
	s := prefix + msg
	for i := 0; i < len(keysAndValues); i += 2 {
		key := ""
		val := ""
		if i < len(keysAndValues) {
			key = fmt.Sprint(keysAndValues[i])
		}
		if i+1 < len(keysAndValues) {
			val = fmt.Sprint(keysAndValues[i+1])
		}
		s += " " + key + "=" + val
	}
	return s
}

func (l testLogger) Info(msg string, keysAndValues ...any) {
	l.t.Log(logKV("INFO: ", msg, keysAndValues...))
}
func (l testLogger) Error(msg string, keysAndValues ...any) {
	l.t.Log(logKV("ERROR: ", msg, keysAndValues...))
}
func (l testLogger) Debug(msg string, keysAndValues ...any) {
	l.t.Log(logKV("DEBUG: ", msg, keysAndValues...))
}
