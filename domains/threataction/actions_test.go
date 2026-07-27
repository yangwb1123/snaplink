package threataction

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/cluster"
	clustermemory "github.com/yangwb1123/snaplink/platform/cluster/memory"
	"github.com/yangwb1123/snaplink/shared/core"
)

// fakeSessionManager is a minimal in-package core.SessionManager test double.
// No Memory* implementation of this SPI lives at this layer — the real one
// (infrastructure/defaultimpl/memorystoreidentity) sits above domains/ in the
// dependency direction (§0.2), so reaching for it even from a _test.go file
// would run against the grain of the codebase's own layering precedent (see
// platform/lifecycle/sessionhub's recordingSessionTerminator for the same
// tiny-in-package-fake pattern applied to a narrower SessionManager slice).
type fakeSessionManager struct {
	sessions   map[string]*core.Session
	destroyed  []string
	destroyErr error
}

func newFakeSessionManager(sessions ...*core.Session) *fakeSessionManager {
	m := &fakeSessionManager{sessions: make(map[string]*core.Session)}
	for _, s := range sessions {
		m.sessions[s.ID] = s
	}
	return m
}

func (m *fakeSessionManager) Create(_ context.Context, userID string) (*core.Session, error) {
	s := &core.Session{ID: userID + "-new-session", UserID: userID}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *fakeSessionManager) Get(_ context.Context, sessionID string) (*core.Session, error) {
	if s, ok := m.sessions[sessionID]; ok {
		return s, nil
	}
	return nil, core.ErrSessionNotFound
}

func (m *fakeSessionManager) Destroy(_ context.Context, sessionID string) error {
	if m.destroyErr != nil {
		return m.destroyErr
	}
	m.destroyed = append(m.destroyed, sessionID)
	if s, ok := m.sessions[sessionID]; ok {
		s.Revoked = true
	}
	return nil
}

func (m *fakeSessionManager) Refresh(ctx context.Context, sessionID string) (*core.Session, error) {
	return m.Get(ctx, sessionID)
}

func (m *fakeSessionManager) ListByUser(_ context.Context, userID string) ([]*core.Session, error) {
	var out []*core.Session
	for _, s := range m.sessions {
		if s.UserID == userID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *fakeSessionManager) ListAll(_ context.Context) ([]*core.Session, error) {
	out := make([]*core.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out, nil
}

// TestSuspendSessionExecutor_PublishesClusterEvent proves a successful
// suspend fans the action out to peer replicas as a KindSessionSuspended
// Event — the session counterpart of RevokeFamilyExecutor's KindTokenRevoked
// broadcast — using the real in-process cluster/memory.Bus (no fake Bus:
// per AGENTS.md §0.5, a Memory* implementation of an SPI is used over a mock
// wherever one exists, matching how interfaces/sso's bus tests already
// exercise Publish/Subscribe).
func TestSuspendSessionExecutor_PublishesClusterEvent(t *testing.T) {
	sessions := newFakeSessionManager(&core.Session{ID: "s1", UserID: "user1"})
	bus := clustermemory.New()
	defer bus.Close()
	sub, err := bus.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	exec := NewSuspendSessionExecutor(sessions, bus)
	threat := Threat{Type: "impossible_travel", Severity: SeverityCritical, SubjectID: "user1"}

	result, err := exec.Execute(context.Background(), threat, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected OK result, got %+v", result)
	}

	select {
	case evt := <-sub:
		if evt.Kind != cluster.KindSessionSuspended {
			t.Fatalf("published kind = %q, want %q", evt.Kind, cluster.KindSessionSuspended)
		}
		if evt.Key != "user1" {
			t.Fatalf("published key = %q, want %q", evt.Key, "user1")
		}
		if got := evt.Payload["threat_action"]; got != string(ActionSuspend) {
			t.Errorf("payload threat_action = %q, want %q", got, ActionSuspend)
		}
		if got := evt.Payload["threat_type"]; got != "impossible_travel" {
			t.Errorf("payload threat_type = %q, want %q", got, "impossible_travel")
		}
		if got := evt.Payload["subject_id"]; got != "user1" {
			t.Errorf("payload subject_id = %q, want %q", got, "user1")
		}
	case <-time.After(time.Second):
		t.Fatal("no cluster event published for suspend_session")
	}
}

// TestSuspendSessionExecutor_NilBusSafe proves a nil bus (a build without
// cluster coordination wired) never panics — Publish is simply skipped,
// matching RevokeFamilyExecutor's nil-safe bus contract.
func TestSuspendSessionExecutor_NilBusSafe(t *testing.T) {
	sessions := newFakeSessionManager(&core.Session{ID: "s1", UserID: "user1"})
	exec := NewSuspendSessionExecutor(sessions, nil)
	threat := Threat{Type: "impossible_travel", Severity: SeverityCritical, SubjectID: "user1"}

	result, err := exec.Execute(context.Background(), threat, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected OK result, got %+v", result)
	}
	if len(sessions.destroyed) != 1 || sessions.destroyed[0] != "s1" {
		t.Fatalf("expected session s1 destroyed, got %v", sessions.destroyed)
	}
}

// fakeSessionTrustManager is a minimal in-package core.SessionTrustManager
// test double, mirroring fakeSessionManager's rationale (§0.5: no Memory*
// implementation of this SPI lives at this layer).
type fakeSessionTrustManager struct {
	marked  []string
	markErr error
}

func (m *fakeSessionTrustManager) MarkStepUp(_ context.Context, sessionID string) error {
	if m.markErr != nil {
		return m.markErr
	}
	m.marked = append(m.marked, sessionID)
	return nil
}

func (m *fakeSessionTrustManager) SetTrust(_ context.Context, _ string, _ float64, _ time.Time) error {
	return nil
}

// TestChallengeExecutor_MarksSessionsForStepUp proves ChallengeExecutor.Execute
// marks every active (non-revoked) session for the threat's SubjectID via
// MarkStepUp — the same mechanism StepUpMFAExecutor uses (see ChallengeExecutor's
// doc comment: the two action names share this one SessionTrustManager
// primitive today) — and returns ActionChallenge as its Action.
func TestChallengeExecutor_MarksSessionsForStepUp(t *testing.T) {
	sessions := newFakeSessionManager(
		&core.Session{ID: "s1", UserID: "user1"},
		&core.Session{ID: "s2", UserID: "user1"},
		&core.Session{ID: "s3", UserID: "user1", Revoked: true},
		&core.Session{ID: "s4", UserID: "other"},
	)
	trust := &fakeSessionTrustManager{}
	exec := NewChallengeExecutor(trust, sessions)
	threat := Threat{Type: "new_device", Severity: SeverityWarn, SubjectID: "user1"}

	result, err := exec.Execute(context.Background(), threat, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected OK result, got %+v", result)
	}
	if result.Action != ActionChallenge {
		t.Fatalf("Action = %q, want %q", result.Action, ActionChallenge)
	}
	if len(trust.marked) != 2 {
		t.Fatalf("marked = %v, want exactly s1 and s2 marked", trust.marked)
	}
	for _, id := range trust.marked {
		if id != "s1" && id != "s2" {
			t.Errorf("unexpected session marked: %q", id)
		}
	}
}

// TestChallengeExecutor_NilSafe proves Execute is a safe no-op — never a
// panic — when either dependency is nil or the subject is empty, mirroring
// StepUpMFAExecutor's equivalent guard clause.
func TestChallengeExecutor_NilSafe(t *testing.T) {
	sessions := newFakeSessionManager(&core.Session{ID: "s1", UserID: "user1"})
	trust := &fakeSessionTrustManager{}

	cases := []struct {
		name   string
		exec   *ChallengeExecutor
		threat Threat
	}{
		{"nil trust manager", NewChallengeExecutor(nil, sessions), Threat{SubjectID: "user1"}},
		{"nil session manager", NewChallengeExecutor(trust, nil), Threat{SubjectID: "user1"}},
		{"empty subject", NewChallengeExecutor(trust, sessions), Threat{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.exec.Execute(context.Background(), tc.threat, ThreatPolicy{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.OK {
				t.Fatalf("expected not-OK result, got %+v", result)
			}
			if result.Action != ActionChallenge {
				t.Fatalf("Action = %q, want %q", result.Action, ActionChallenge)
			}
		})
	}
	if len(trust.marked) != 0 {
		t.Fatalf("expected no sessions marked, got %v", trust.marked)
	}
}

// TestSuspendSessionExecutor_NoSessionManagerSkipsPublish proves the
// guard-clause no-op path (nil SessionManager or empty SubjectID) never
// reaches the bus, mirroring RevokeFamilyExecutor's equivalent guard.
func TestSuspendSessionExecutor_NoSessionManagerSkipsPublish(t *testing.T) {
	bus := clustermemory.New()
	defer bus.Close()
	sub, err := bus.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	exec := NewSuspendSessionExecutor(nil, bus)
	result, err := exec.Execute(context.Background(), Threat{SubjectID: "user1"}, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OK {
		t.Fatalf("expected not-OK result, got %+v", result)
	}

	select {
	case evt := <-sub:
		t.Fatalf("unexpected event published: %+v", evt)
	case <-time.After(50 * time.Millisecond):
		// Expected: no event.
	}
}

// fakeFamilyRevoker is a minimal in-package FamilyRevoker test double. No
// Memory* implementation of this SPI lives at this layer (it's an
// oauthspi.RefreshTokenFamilyTracker extension one layer up), mirroring
// fakeSessionManager's rationale above.
type fakeFamilyRevoker struct {
	calls []string // familyIDs passed to DeleteFamily, in call order
	count int
	err   error
}

func (f *fakeFamilyRevoker) DeleteFamily(_ context.Context, familyID string) (int, error) {
	f.calls = append(f.calls, familyID)
	if f.err != nil {
		return 0, f.err
	}
	return f.count, nil
}

// fakeSubjectRevoker is a minimal in-package SubjectRevoker test double,
// mirroring fakeFamilyRevoker's rationale (the real
// oauthspi.RefreshTokenSubjectIndex implementation lives one layer up, in
// infrastructure/defaultimpl).
type fakeSubjectRevoker struct {
	subjectIDs []string
	clientIDs  []string
	count      int
	err        error
}

func (f *fakeSubjectRevoker) DeleteAllForSubject(_ context.Context, subjectID, clientID string) (int, error) {
	f.subjectIDs = append(f.subjectIDs, subjectID)
	f.clientIDs = append(f.clientIDs, clientID)
	if f.err != nil {
		return 0, f.err
	}
	return f.count, nil
}

// TestRevokeFamilyExecutor_FamilyIDPresent_UsesFamilyPath proves a threat
// carrying a FamilyID takes the original family-scoped path unchanged — even
// when a SubjectRevoker is ALSO wired, the family path wins whenever both a
// family tracker and a FamilyID are present, so the fallback never
// shadows the existing behavior.
func TestRevokeFamilyExecutor_FamilyIDPresent_UsesFamilyPath(t *testing.T) {
	families := &fakeFamilyRevoker{count: 3}
	subjects := &fakeSubjectRevoker{count: 99}
	bus := clustermemory.New()
	defer bus.Close()
	sub, err := bus.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	exec := NewRevokeFamilyExecutor(families, subjects, bus)
	threat := Threat{Type: "impossible_travel", SubjectID: "user1", ClientID: "client1", FamilyID: "fam1"}

	result, err := exec.Execute(context.Background(), threat, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected OK result, got %+v", result)
	}
	if len(families.calls) != 1 || families.calls[0] != "fam1" {
		t.Fatalf("expected DeleteFamily(fam1) exactly once, got %v", families.calls)
	}
	if len(subjects.subjectIDs) != 0 {
		t.Fatalf("subject fallback must not fire when FamilyID present + family tracker wired, got %v", subjects.subjectIDs)
	}

	select {
	case evt := <-sub:
		if evt.Kind != cluster.KindTokenRevoked {
			t.Errorf("published kind = %q, want %q", evt.Kind, cluster.KindTokenRevoked)
		}
		if evt.Key != "fam1" {
			t.Errorf("published key = %q, want %q", evt.Key, "fam1")
		}
	case <-time.After(time.Second):
		t.Fatal("no cluster event published for revoke_family (family path)")
	}
}

// TestRevokeFamilyExecutor_SubjectFallback_WhenFamilyIDEmpty proves the fix
// for the P0 bug this executor shipped with: neither production caller
// (anomaly.Runner, tokenanomaly.Detector) ever populates Threat.FamilyID, so
// without this fallback revoke_family was a byte-identical permanent no-op.
// A threat with an empty FamilyID now falls back to DeleteAllForSubject,
// keyed on the threat's SubjectID + ClientID.
func TestRevokeFamilyExecutor_SubjectFallback_WhenFamilyIDEmpty(t *testing.T) {
	subjects := &fakeSubjectRevoker{count: 2}
	bus := clustermemory.New()
	defer bus.Close()
	sub, err := bus.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	exec := NewRevokeFamilyExecutor(nil, subjects, bus)
	threat := Threat{Type: "velocity_burst", SubjectID: "user2", ClientID: "client2"}

	result, err := exec.Execute(context.Background(), threat, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected OK result, got %+v", result)
	}
	if len(subjects.subjectIDs) != 1 || subjects.subjectIDs[0] != "user2" {
		t.Fatalf("expected DeleteAllForSubject called with subject user2, got %v", subjects.subjectIDs)
	}
	if len(subjects.clientIDs) != 1 || subjects.clientIDs[0] != "client2" {
		t.Fatalf("expected DeleteAllForSubject called with client client2, got %v", subjects.clientIDs)
	}

	select {
	case evt := <-sub:
		if evt.Kind != cluster.KindTokenRevoked {
			t.Errorf("published kind = %q, want %q", evt.Kind, cluster.KindTokenRevoked)
		}
		if evt.Key != "user2" {
			t.Errorf("published key = %q, want %q", evt.Key, "user2")
		}
	case <-time.After(time.Second):
		t.Fatal("no cluster event published for revoke_family (subject fallback)")
	}
}

// TestRevokeFamilyExecutor_NoCapabilityWired_NoOp proves today's exact no-op
// result + detail message still holds — byte-identical to before the
// SubjectRevoker fallback existed — when neither a family tracker nor a
// subject revoker is wired. No bus event either.
func TestRevokeFamilyExecutor_NoCapabilityWired_NoOp(t *testing.T) {
	bus := clustermemory.New()
	defer bus.Close()
	sub, err := bus.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	exec := NewRevokeFamilyExecutor(nil, nil, bus)
	result, err := exec.Execute(context.Background(), Threat{SubjectID: "user3", FamilyID: "fam3"}, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OK {
		t.Fatalf("expected not-OK result, got %+v", result)
	}
	if result.Detail != "no family tracker or empty family ID" {
		t.Errorf("Detail = %q, want unchanged no-op message", result.Detail)
	}

	select {
	case evt := <-sub:
		t.Fatalf("unexpected event published: %+v", evt)
	case <-time.After(50 * time.Millisecond):
		// Expected: no event.
	}
}

// TestNotifyExecutor_Execute proves NotifyExecutor.Execute always succeeds
// and reports the threat's type + subject in Detail. This executor had ZERO
// test coverage in this file before this change.
func TestNotifyExecutor_Execute(t *testing.T) {
	exec := NewNotifyExecutor()
	if got := exec.Name(); got != "notify" {
		t.Fatalf("Name() = %q, want %q", got, "notify")
	}
	threat := Threat{Type: "new_device", SubjectID: "user4"}
	result, err := exec.Execute(context.Background(), threat, ThreatPolicy{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK || result.Action != ActionNotify {
		t.Fatalf("expected OK notify result, got %+v", result)
	}
	want := "notification recorded for threat new_device on subject user4"
	if result.Detail != want {
		t.Errorf("Detail = %q, want %q", result.Detail, want)
	}
}
