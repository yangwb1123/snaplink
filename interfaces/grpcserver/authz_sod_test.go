package grpcserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	authzv1 "github.com/yangwb1123/snaplink/gen/proto/authz/v1"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestAuthzCheckUsesActiveRoleProjection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	for _, role := range []permissions.Role{
		{Code: "approver", Permissions: []string{"request:approve"}},
		{Code: "requester", Permissions: []string{"request:create"}},
	} {
		if err := p.AddRole(ctx, "web", role); err != nil {
			t.Fatalf("add role: %v", err)
		}
	}
	if err := p.AssignRoles(ctx, "alice", "web", []string{"approver", "requester"}); err != nil {
		t.Fatalf("assign roles: %v", err)
	}
	if err := p.SetActivationConflictSets(ctx, "web", [][]string{{"approver", "requester"}}); err != nil {
		t.Fatalf("set dsod: %v", err)
	}
	if err := p.ActivateRoles(ctx, "alice", "web", "sid-1", []string{"approver"}); err != nil {
		t.Fatalf("activate role: %v", err)
	}
	client := authzv1.NewAuthorizerClient(startGRPC(t, nil, p, nil))
	allowed, err := client.Check(ctx, &authzv1.CheckRequest{
		SubjectId: "alice", ClientId: "web", Permission: "request:approve", SessionId: "sid-1",
	})
	if err != nil || !allowed.Allowed {
		t.Fatalf("active permission = %+v, %v", allowed, err)
	}
	denied, err := client.Check(ctx, &authzv1.CheckRequest{
		SubjectId: "alice", ClientId: "web", Permission: "request:create", SessionId: "sid-1",
	})
	if err != nil || denied.Allowed {
		t.Fatalf("inactive permission = %+v, %v", denied, err)
	}
	legacy, err := client.Check(ctx, &authzv1.CheckRequest{
		SubjectId: "alice", ClientId: "web", Permission: "request:create",
	})
	if err != nil || !legacy.Allowed {
		t.Fatalf("legacy assigned permission = %+v, %v", legacy, err)
	}
	if err := p.DeactivateSession(ctx, "alice", "web", "sid-1"); err != nil {
		t.Fatalf("deactivate session: %v", err)
	}
	stale, err := client.Check(ctx, &authzv1.CheckRequest{
		SubjectId: "alice", ClientId: "web", Permission: "request:approve", SessionId: "sid-1",
	})
	if err != nil || stale.Allowed {
		t.Fatalf("stale session permission = %+v, %v", stale, err)
	}
}

func TestAuthzCheckRecordsDecisionObservability(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "reader", Permissions: []string{"item:read"}})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"reader"})
	sink := audit.NewMemorySink(8)
	metricSet := metrics.New()
	service := grpcserver.NewAuthzServiceWithObservability(
		p, audit.New(sink), metricSet, spi.NopLogger{},
	)
	for _, permission := range []string{"item:read", "item:write"} {
		_, err := service.Check(ctx, &authzv1.CheckRequest{
			SubjectId: "alice", ClientId: "web", Permission: permission,
		})
		if err != nil {
			t.Fatalf("check %q: %v", permission, err)
		}
	}
	events, err := sink.Query(ctx, audit.Query{Type: audit.EventPermissionCheck, Limit: 8})
	if err != nil || len(events) != 2 {
		t.Fatalf("permission check events = %d, %v", len(events), err)
	}
	decisions := map[string]bool{}
	for _, event := range events {
		decisions[event.Metadata["decision"]] = true
	}
	if !decisions["allow"] || !decisions["deny"] {
		t.Fatalf("decision metadata = %v", decisions)
	}
	families, err := metricSet.Registry.Gather()
	if err != nil {
		t.Fatalf("gather authz metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() == metrics.NameAuthzChecksTotal {
			if len(family.Metric) != 2 {
				t.Fatalf("authz metric series = %d, want allow+deny", len(family.Metric))
			}
			return
		}
	}
	t.Fatalf("metric %s not registered", metrics.NameAuthzChecksTotal)
}

func TestAuthzCheckEnforcesLiveSessionAndLocalSubject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	if err := p.AddRole(ctx, "web", permissions.Role{Code: "reader", Permissions: []string{"item:read"}}); err != nil {
		t.Fatalf("add role: %v", err)
	}
	if err := p.AssignRoles(ctx, "local-alice", "web", []string{"reader"}); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	sessions := memorystoreidentity.NewMemorySessionManager(time.Hour)
	sess, err := sessions.CreateWithMeta(ctx, "local-alice", core.SessionMeta{ClientID: "web"})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := p.ActivateRoles(ctx, "local-alice", "web", sess.ID, []string{"reader"}); err != nil {
		t.Fatalf("activate role: %v", err)
	}
	service := grpcserver.NewAuthzServiceWithSessionBoundary(p, nil, nil, nil, grpcserver.AuthzSessionBoundary{
		SessionManager: sessions,
		ResolveSubject: func(context.Context, string) (string, error) { return "local-alice", nil },
	})
	allowed, err := service.Check(ctx, &authzv1.CheckRequest{
		SubjectId: "pairwise-alice", ClientId: "web", Permission: "item:read", SessionId: sess.ID,
	})
	if err != nil || !allowed.Allowed {
		t.Fatalf("live pairwise session = %+v, %v", allowed, err)
	}
	if err := sessions.Destroy(ctx, sess.ID); err != nil {
		t.Fatalf("destroy session: %v", err)
	}
	denied, err := service.Check(ctx, &authzv1.CheckRequest{
		SubjectId: "pairwise-alice", ClientId: "web", Permission: "item:read", SessionId: sess.ID,
	})
	if err != nil || denied.Allowed {
		t.Fatalf("destroyed session = %+v, %v", denied, err)
	}
}
