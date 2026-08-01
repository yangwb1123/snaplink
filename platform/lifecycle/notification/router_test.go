package notification

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

type captureSender struct {
	mu     sync.Mutex
	events []*core.NotificationEvent
	fail   int
}

func (s *captureSender) SendNotification(_ context.Context, event *core.NotificationEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail > 0 {
		s.fail--
		return context.DeadlineExceeded
	}
	copyEvent := *event
	s.events = append(s.events, &copyEvent)
	return nil
}
func (s *captureSender) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.events) }

type testPrefs struct{ values []core.NotificationPreference }

func (p testPrefs) ListBySubject(context.Context, string) ([]core.NotificationPreference, error) {
	return p.values, nil
}
func (testPrefs) Put(context.Context, core.NotificationPreference) error { return nil }
func (testPrefs) DeleteForSubject(context.Context, string) error         { return nil }

type sessionLister struct{ sessions []*core.Session }

func (s sessionLister) Create(context.Context, string) (*core.Session, error)       { return nil, nil }
func (s sessionLister) Get(context.Context, string) (*core.Session, error)          { return nil, nil }
func (s sessionLister) Refresh(context.Context, string) (*core.Session, error)      { return nil, nil }
func (s sessionLister) Destroy(context.Context, string) error                       { return nil }
func (s sessionLister) DestroyAll(context.Context, string) error                    { return nil }
func (s sessionLister) ListByUser(context.Context, string) ([]*core.Session, error) { return nil, nil }
func (s sessionLister) ListAll(context.Context) ([]*core.Session, error)            { return s.sessions, nil }

type notificationUsers struct{ users []*core.User }

func (p notificationUsers) GetByID(_ context.Context, id string) (*core.User, error) {
	for _, user := range p.users {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, core.ErrNoSuchUser
}
func (p notificationUsers) GetByExternalID(_ context.Context, provider, externalID string) (*core.User, error) {
	for _, user := range p.users {
		if user.Provider == provider && user.ExternalID == externalID {
			return user, nil
		}
	}
	return nil, core.ErrNoSuchUser
}
func (notificationUsers) CreateOrUpdate(context.Context, *core.User) error { return nil }
func (p notificationUsers) List(context.Context) ([]*core.User, error)     { return p.users, nil }
func (notificationUsers) Delete(context.Context, string) error             { return nil }

func TestRouterPreferencesCooldownAndSubjectMetadata(t *testing.T) {
	inApp, email := &captureSender{}, &captureSender{}
	prefs := testPrefs{values: []core.NotificationPreference{{Type: core.NotificationNewDeviceLogin, Channel: core.NotificationChannelEmail, Enabled: false}}}
	router := NewRouter(nil, prefs, map[core.NotificationChannel]core.NotificationSender{
		core.NotificationChannelInApp: inApp, core.NotificationChannelEmail: email,
	}, nil, WithWorkers(1))
	ctx, cancel := context.WithCancel(context.Background())
	done := router.Start(ctx)
	event := &audit.Event{Type: audit.EventNewDeviceLogin, ActorID: "admin", Metadata: map[string]string{"subject_id": "alice"}}
	_ = router.Record(ctx, event)
	_ = router.Record(ctx, event)
	waitCount(t, inApp, 1)
	if email.count() != 0 {
		t.Fatalf("disabled email delivered %d times", email.count())
	}
	inApp.mu.Lock()
	if inApp.events[0].SubjectID != "alice" {
		t.Fatalf("subject=%q", inApp.events[0].SubjectID)
	}
	inApp.mu.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("router did not stop")
	}
}

func TestRouterEmailRetriesWithoutBlockingAuditRecord(t *testing.T) {
	email := &captureSender{fail: 2}
	router := NewRouter(map[audit.EventType]core.NotificationType{audit.EventAccountLocked: core.NotificationAccountLocked}, nil,
		map[core.NotificationChannel]core.NotificationSender{core.NotificationChannelEmail: email}, nil, WithWorkers(1), WithCooldown(0))
	ctx, cancel := context.WithCancel(context.Background())
	done := router.Start(ctx)
	start := time.Now()
	if err := router.Record(ctx, &audit.Event{Type: audit.EventAccountLocked, ActorID: "alice"}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 20*time.Millisecond {
		t.Fatal("audit record blocked on delivery")
	}
	waitCount(t, email, 1)
	cancel()
	<-done
}

func TestRouterCloseIsIdempotentAndBounded(t *testing.T) {
	router := NewRouter(nil, nil, nil, nil)
	if err := router.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := router.Start(context.Background())
	if err := router.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close did not stop workers")
	}
	if err := router.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRouterSweepsSessionsInsideWarningWindow(t *testing.T) {
	inApp := &captureSender{}
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	lister := sessionLister{sessions: []*core.Session{
		{UserID: "alice", TenantID: "tenant-a", ExpiresAt: now.Add(20 * time.Minute)},
		{UserID: "bob", ExpiresAt: now.Add(time.Hour)},
	}}
	router := NewRouter(nil, nil, map[core.NotificationChannel]core.NotificationSender{
		core.NotificationChannelInApp: inApp,
	}, nil, WithClock(func() time.Time { return now }), WithCooldown(0),
		WithSessionExpiry(lister, 30*time.Minute, time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	done := router.Start(ctx)
	waitCount(t, inApp, 1)
	inApp.mu.Lock()
	event := inApp.events[0]
	inApp.mu.Unlock()
	if event.SubjectID != "alice" || event.TenantID != "tenant-a" || event.Type != core.NotificationSessionExpiring {
		t.Fatalf("event=%#v", event)
	}
	cancel()
	<-done
}

func TestRouterPresentsPasswordChangeAndConsentRevoke(t *testing.T) {
	tests := []struct {
		event audit.Event
		title string
	}{
		{event: audit.Event{Type: audit.EventPasswordChanged}, title: "Password changed"},
		{event: audit.Event{Type: audit.EventConsentRevoked, ClientID: "app-1"}, title: "Application access revoked"},
		{event: audit.Event{Type: audit.EventAdminPasswordResetTokensRevoked}, title: "Password reset links revoked"},
		{event: audit.Event{Type: audit.EventAdminEmailChangeTokensRevoked}, title: "Email change requests revoked"},
		{event: audit.Event{Type: audit.EventAdminAccountUnlocked}, title: "Account unlocked by administrator"},
		{event: audit.Event{Type: audit.EventAdminTenantMemberAdded}, title: "Organization access changed"},
		{event: audit.Event{Type: audit.EventAdminUserLifecycleChanged, Metadata: map[string]string{"to_state": "suspended"}}, title: "Account status changed"},
		{event: audit.Event{Type: audit.EventAdminUserLifecycleChanged, Metadata: map[string]string{"to_state": "active"}}, title: "Account access restored"},
		{event: audit.Event{Type: audit.EventAdminTempTokenIssued}, title: "Temporary access token issued"},
		{event: audit.Event{Type: audit.EventAdminBreakGlassImpersonationStarted}, title: "Emergency access used"},
	}
	for _, test := range tests {
		title, _, _ := presentation(DefaultMappings()[test.event.Type], &test.event)
		if title != test.title {
			t.Fatalf("type=%s title=%q want=%q", test.event.Type, title, test.title)
		}
	}
}

func TestRouterResolvesAccountLockAndAdministrativeTargets(t *testing.T) {
	users := notificationUsers{users: []*core.User{
		{ID: "user-1", Username: "Alice"},
		{ID: "user-2", Email: "bob@example.com"},
		{ID: "user-3", Attributes: map[string]string{"phone": "+15551234567"}},
	}}
	router := NewRouter(nil, nil, nil, nil, WithUserProvider(users))
	tests := []struct {
		event audit.Event
		want  string
	}{
		{event: audit.Event{Type: audit.EventAccountLocked, ActorID: "web:alice", ClientID: "web", Provider: "password"}, want: "user-1"},
		{event: audit.Event{Type: audit.EventAccountLocked, ActorID: "web:bob@example.com", ClientID: "web", Provider: "email"}, want: "user-2"},
		{event: audit.Event{Type: audit.EventAccountLocked, ActorID: "web:+15551234567", ClientID: "web", Provider: "phone"}, want: "user-3"},
		{event: audit.Event{Type: audit.EventAdminRoleAssigned, ActorID: "admin", Metadata: map[string]string{"target_user_id": "user-1"}}, want: "user-1"},
		{event: audit.Event{Type: audit.EventAdminPasswordReset, ActorID: "admin", Metadata: map[string]string{"target_user": "user-2"}}, want: "user-2"},
		{event: audit.Event{Type: audit.EventAdminAccountUnlocked, ActorID: "admin", Metadata: map[string]string{"target_user": "alice"}}, want: "user-1"},
	}
	for _, test := range tests {
		if got := router.eventSubject(context.Background(), &test.event); got != test.want {
			t.Errorf("type=%s subject=%q want=%q", test.event.Type, got, test.want)
		}
	}
	unknown := &audit.Event{Type: audit.EventAccountLocked, ActorID: "web:unknown", ClientID: "web", Provider: "password"}
	if got := router.eventSubject(context.Background(), unknown); got != "" {
		t.Fatalf("unknown lock identity resolved to %q", got)
	}
}

func TestDefaultMappingsCoverAdministrativeSecurityActions(t *testing.T) {
	mappings := DefaultMappings()
	for _, eventType := range []audit.EventType{
		audit.EventAdminConsentRevoked, audit.EventAdminMFAFactorRemoved,
		audit.EventAdminRecoveryCodesReset, audit.EventAdminPasswordReset,
		audit.EventAdminUserEmailChanged, audit.EventAdminDeviceSecretsRevoked,
		audit.EventAdminRefreshTokensRevoked, audit.EventAdminPasswordResetTokensRevoked,
		audit.EventAdminEmailChangeTokensRevoked, audit.EventAdminAccountUnlocked,
		audit.EventAdminTenantMemberAdded, audit.EventAdminTenantMemberRemoved,
		audit.EventAdminUserLifecycleChanged, audit.EventAdminTempTokenIssued,
		audit.EventAdminBreakGlassImpersonationStarted,
	} {
		if _, ok := mappings[eventType]; !ok {
			t.Errorf("missing notification mapping for %s", eventType)
		}
	}
}

func waitCount(t *testing.T, sender *captureSender, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if sender.count() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("deliveries=%d want=%d", sender.count(), want)
}
