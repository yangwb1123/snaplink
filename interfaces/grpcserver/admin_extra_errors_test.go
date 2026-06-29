package grpcserver_test

// Additional admin-service branch coverage that the existing per-service
// error files don't reach: tenant store FailedPrecondition / InvalidArgument /
// Internal gates, the TokenAdmin ListSessions Unimplemented + Internal paths,
// nil proto-conversion branches, and the snapshot/release sentinel-to-code
// mappers exercised through the public RPC surface.

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/tenant"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- TenantAdmin error/branch coverage ---

// erroringTenantStore returns a configured error from every method.
type erroringTenantStore struct{ err error }

func (e *erroringTenantStore) GetTenant(context.Context, string) (*tenant.Tenant, error) {
	return nil, e.err
}
func (e *erroringTenantStore) ListTenants(context.Context) ([]*tenant.Tenant, error) {
	return nil, e.err
}
func (e *erroringTenantStore) PutTenant(context.Context, *tenant.Tenant) error { return e.err }
func (e *erroringTenantStore) DeleteTenant(context.Context, string) error      { return e.err }
func (e *erroringTenantStore) GetDomain(context.Context, string) (*tenant.Domain, error) {
	return nil, e.err
}
func (e *erroringTenantStore) ListDomains(context.Context) ([]*tenant.Domain, error) {
	return nil, e.err
}
func (e *erroringTenantStore) ListDomainsByTenant(context.Context, string) ([]*tenant.Domain, error) {
	return nil, e.err
}
func (e *erroringTenantStore) PutDomain(context.Context, *tenant.Domain) error { return e.err }
func (e *erroringTenantStore) DeleteDomain(context.Context, string) error      { return e.err }
func (e *erroringTenantStore) Close() error                                    { return nil }

var _ tenant.Store = (*erroringTenantStore)(nil)

func TestTenantAdmin_NilStoreFailsPrecondition(t *testing.T) {
	t.Parallel()
	conn := startTenantAdminGRPC(t, nil, nil, nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()
	cases := map[string]func() error{
		"ListTenants": func() error { _, e := c.ListTenants(ctx, &adminv1.ListTenantsRequest{}); return e },
		"GetTenant":   func() error { _, e := c.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "t"}); return e },
		"CreateTenant": func() error {
			_, e := c.CreateTenant(ctx, &adminv1.CreateTenantRequest{Tenant: &adminv1.Tenant{Id: "t"}})
			return e
		},
		"UpdateTenant": func() error {
			_, e := c.UpdateTenant(ctx, &adminv1.UpdateTenantRequest{Tenant: &adminv1.Tenant{Id: "t"}})
			return e
		},
		"DeleteTenant": func() error { _, e := c.DeleteTenant(ctx, &adminv1.DeleteTenantRequest{Id: "t"}); return e },
		"SetTenantStatus": func() error {
			_, e := c.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{Id: "t", Status: "active"})
			return e
		},
		"ListDomains": func() error { _, e := c.ListDomains(ctx, &adminv1.ListDomainsRequest{}); return e },
		"GetDomain":   func() error { _, e := c.GetDomain(ctx, &adminv1.GetDomainRequest{Hostname: "h"}); return e },
		"CreateDomain": func() error {
			_, e := c.CreateDomain(ctx, &adminv1.CreateDomainRequest{Domain: &adminv1.Domain{Hostname: "h"}})
			return e
		},
		"UpdateDomain": func() error {
			_, e := c.UpdateDomain(ctx, &adminv1.UpdateDomainRequest{Domain: &adminv1.Domain{Hostname: "h"}})
			return e
		},
		"DeleteDomain": func() error { _, e := c.DeleteDomain(ctx, &adminv1.DeleteDomainRequest{Hostname: "h"}); return e },
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", name, got)
		}
	}
}

func TestTenantAdmin_ValidationRejections(t *testing.T) {
	t.Parallel()
	store := &erroringTenantStore{} // passes nil-store gate
	conn := startTenantAdminGRPC(t, store, nil, nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()
	cases := map[string]func() error{
		"GetTenant-empty":    func() error { _, e := c.GetTenant(ctx, &adminv1.GetTenantRequest{}); return e },
		"CreateTenant-nil":   func() error { _, e := c.CreateTenant(ctx, &adminv1.CreateTenantRequest{}); return e },
		"UpdateTenant-nil":   func() error { _, e := c.UpdateTenant(ctx, &adminv1.UpdateTenantRequest{}); return e },
		"DeleteTenant-empty": func() error { _, e := c.DeleteTenant(ctx, &adminv1.DeleteTenantRequest{}); return e },
		"SetStatus-empty":    func() error { _, e := c.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{}); return e },
		"GetDomain-empty":    func() error { _, e := c.GetDomain(ctx, &adminv1.GetDomainRequest{}); return e },
		"CreateDomain-nil":   func() error { _, e := c.CreateDomain(ctx, &adminv1.CreateDomainRequest{}); return e },
		"UpdateDomain-nil":   func() error { _, e := c.UpdateDomain(ctx, &adminv1.UpdateDomainRequest{}); return e },
		"DeleteDomain-empty": func() error { _, e := c.DeleteDomain(ctx, &adminv1.DeleteDomainRequest{}); return e },
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", name, got)
		}
	}
}

func TestTenantAdmin_StoreErrorsAreInternal(t *testing.T) {
	t.Parallel()
	store := &erroringTenantStore{err: errors.New("db down")}
	conn := startTenantAdminGRPC(t, store, nil, nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()
	cases := map[string]func() error{
		"ListTenants":  func() error { _, e := c.ListTenants(ctx, &adminv1.ListTenantsRequest{}); return e },
		"GetTenant":    func() error { _, e := c.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "t"}); return e },
		"DeleteTenant": func() error { _, e := c.DeleteTenant(ctx, &adminv1.DeleteTenantRequest{Id: "t"}); return e },
		"ListDomains":  func() error { _, e := c.ListDomains(ctx, &adminv1.ListDomainsRequest{}); return e },
		"GetDomain":    func() error { _, e := c.GetDomain(ctx, &adminv1.GetDomainRequest{Hostname: "h"}); return e },
		"DeleteDomain": func() error { _, e := c.DeleteDomain(ctx, &adminv1.DeleteDomainRequest{Hostname: "h"}); return e },
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.Internal {
			t.Errorf("%s: code = %v, want Internal", name, got)
		}
	}
}

func TestTenantAdmin_GetTenantNotFound(t *testing.T) {
	t.Parallel()
	store := &erroringTenantStore{err: tenant.ErrTenantNotFound}
	conn := startTenantAdminGRPC(t, store, nil, nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	if _, err := c.GetTenant(context.Background(), &adminv1.GetTenantRequest{Id: "ghost"}); status.Code(err) != codes.NotFound {
		t.Fatalf("GetTenant: expected NotFound, got %v", err)
	}
}

func TestTenantAdmin_UpdateTenantNotFound(t *testing.T) {
	t.Parallel()
	store := &erroringTenantStore{err: tenant.ErrTenantNotFound}
	conn := startTenantAdminGRPC(t, store, nil, nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	if _, err := c.UpdateTenant(context.Background(), &adminv1.UpdateTenantRequest{Tenant: &adminv1.Tenant{Id: "ghost"}}); status.Code(err) != codes.NotFound {
		t.Fatalf("UpdateTenant: expected NotFound, got %v", err)
	}
}

func TestTenantAdmin_GetDomainNotFound(t *testing.T) {
	t.Parallel()
	store := &erroringTenantStore{err: tenant.ErrDomainNotFound}
	conn := startTenantAdminGRPC(t, store, nil, nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	if _, err := c.GetDomain(context.Background(), &adminv1.GetDomainRequest{Hostname: "ghost"}); status.Code(err) != codes.NotFound {
		t.Fatalf("GetDomain: expected NotFound, got %v", err)
	}
	if _, err := c.UpdateDomain(context.Background(), &adminv1.UpdateDomainRequest{Domain: &adminv1.Domain{Hostname: "ghost"}}); status.Code(err) != codes.NotFound {
		t.Fatalf("UpdateDomain: expected NotFound, got %v", err)
	}
}

// --- TokenAdmin: ListSessions Unimplemented + Internal ---

// unsupportedSessionManager reports ListAll as unsupported (the large-backend
// contract) and a generic error from ListByUser, driving both error branches
// of TokenAdminService.ListSessions.
type sessionManagerStub struct {
	listAllErr error
	byUserErr  error
}

func (s *sessionManagerStub) Create(context.Context, string) (*sso.Session, error) { return nil, nil }
func (s *sessionManagerStub) Get(context.Context, string) (*sso.Session, error)    { return nil, nil }
func (s *sessionManagerStub) Destroy(context.Context, string) error                { return nil }
func (s *sessionManagerStub) Refresh(context.Context, string) (*sso.Session, error) {
	return nil, nil
}
func (s *sessionManagerStub) ListByUser(context.Context, string) ([]*sso.Session, error) {
	return nil, s.byUserErr
}
func (s *sessionManagerStub) ListAll(context.Context) ([]*sso.Session, error) {
	return nil, s.listAllErr
}

var _ sso.SessionManager = (*sessionManagerStub)(nil)

func TestTokenAdmin_ListSessions_UnsupportedIsUnimplemented(t *testing.T) {
	t.Parallel()
	sm := &sessionManagerStub{listAllErr: sso.ErrUnsupportedOperation}
	conn := startAdminGRPC(t, nil, nil, sm, nil, nil, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)
	if _, err := c.ListSessions(context.Background(), &adminv1.ListSessionsRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got %v", err)
	}
}

func TestTokenAdmin_ListSessions_ErrorIsInternal(t *testing.T) {
	t.Parallel()
	sm := &sessionManagerStub{listAllErr: errors.New("boom"), byUserErr: errors.New("boom")}
	conn := startAdminGRPC(t, nil, nil, sm, nil, nil, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)
	if _, err := c.ListSessions(context.Background(), &adminv1.ListSessionsRequest{}); status.Code(err) != codes.Internal {
		t.Fatalf("ListAll error: expected Internal, got %v", err)
	}
	if _, err := c.ListSessions(context.Background(), &adminv1.ListSessionsRequest{UserId: "alice"}); status.Code(err) != codes.Internal {
		t.Fatalf("ListByUser error: expected Internal, got %v", err)
	}
}

func TestTokenAdmin_IssueTempToken_MissingUserIsInvalidArgument(t *testing.T) {
	t.Parallel()
	tempStore := authenticators.NewMemoryTempTokenStore()
	conn := startAdminGRPC(t, nil, nil, nil, nil, tempStore, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)
	if _, err := c.IssueTempToken(context.Background(), &adminv1.IssueTempTokenRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

// --- UserAdmin: nil proto branch of userToProto ---

func TestUserAdmin_GetReturnsNilProtoForNilUser(t *testing.T) {
	t.Parallel()
	// A provider that returns (nil, nil) exercises the nil branch of
	// userToProto via the public Get path. Reuses the existing
	// erroringUserProvider stub (declared in admin_user_token_errors_test.go).
	users := &nilUserProvider{}
	conn := startAdminGRPC(t, nil, users, nil, nil, nil, nil)
	c := adminv1.NewUserAdminServiceClient(conn)
	resp, err := c.Get(context.Background(), &adminv1.GetUserRequest{Id: "x"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.User != nil {
		t.Errorf("expected nil proto user, got %+v", resp.User)
	}
}

// nilUserProvider returns (nil, nil) from GetByID, an unusual-but-legal
// contract used to drive the nil branch of userToProto. Embeds the shared
// erroringUserProvider for the remaining UserProvider methods.
type nilUserProvider struct{ erroringUserProvider }

func (n *nilUserProvider) GetByID(context.Context, string) (*sso.User, error) { return nil, nil }

// --- TokenAdmin Revoke: token fan-out to issuers ---

// recognizingIssuer.Revoke succeeds (recognizes the token); rejectingIssuer
// returns an error so the fan-out moves on. Only Revoke is exercised.
type recognizingIssuer struct{ revoked []string }

func (i *recognizingIssuer) Issue(context.Context, *sso.Subject, []string) (*sso.Token, error) {
	return nil, nil
}
func (i *recognizingIssuer) Validate(context.Context, string) (*sso.TokenClaims, error) {
	return nil, nil
}
func (i *recognizingIssuer) Revoke(_ context.Context, token string) error {
	i.revoked = append(i.revoked, token)
	return nil
}

type rejectingIssuer struct{}

func (i *rejectingIssuer) Issue(context.Context, *sso.Subject, []string) (*sso.Token, error) {
	return nil, nil
}
func (i *rejectingIssuer) Validate(context.Context, string) (*sso.TokenClaims, error) {
	return nil, nil
}
func (i *rejectingIssuer) Revoke(context.Context, string) error {
	return errors.New("not my token")
}

var (
	_ sso.TokenIssuer = (*recognizingIssuer)(nil)
	_ sso.TokenIssuer = (*rejectingIssuer)(nil)
)

func TestTokenAdmin_RevokeTokenFanOut(t *testing.T) {
	t.Parallel()
	rec := &recognizingIssuer{}
	sink := audit.NewMemorySink(4)
	svc := grpcserver.NewTokenAdminService(grpcserver.TokenAdminConfig{
		Issuers:  map[string]sso.TokenIssuer{"reject": &rejectingIssuer{}, "jwt": rec},
		Recorder: audit.New(sink),
	})
	resp, err := svc.Revoke(context.Background(), &adminv1.RevokeRequest{Token: "opaque-token-abc"})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(resp.Revoked) != 1 || resp.Revoked[0] != sso.RevokedToken {
		t.Fatalf("expected one revoked-token tag, got %+v", resp.Revoked)
	}
	if len(rec.revoked) != 1 {
		t.Errorf("recognizing issuer should have seen the token once, got %d", len(rec.revoked))
	}
	// A token-only revoke that matched an issuer must emit one audit event.
	if sink.Len() != 1 {
		t.Errorf("expected 1 audit event, got %d", sink.Len())
	}
}

func TestTokenAdmin_RevokeTokenNoIssuerMatchIsNotFound(t *testing.T) {
	t.Parallel()
	svc := grpcserver.NewTokenAdminService(grpcserver.TokenAdminConfig{
		Issuers: map[string]sso.TokenIssuer{"reject": &rejectingIssuer{}},
	})
	if _, err := svc.Revoke(context.Background(), &adminv1.RevokeRequest{Token: "x"}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

// --- shared audit path: recordAdmin under no-actor context ---

// recordingDomainStore is a minimal tenant.Store that succeeds on PutDomain
// (and GetDomain-not-found before it) so a CreateDomain mutation fires the
// recordAdmin path. The bufconn context carries no admin actor, exercising
// the "missing actor" branch of recordAdmin (admin_shared.go).
type recordingDomainStore struct {
	erroringTenantStore
	created *tenant.Domain
}

func (r *recordingDomainStore) GetDomain(_ context.Context, hostname string) (*tenant.Domain, error) {
	if r.created != nil && r.created.Hostname == hostname {
		return r.created, nil
	}
	return nil, tenant.ErrDomainNotFound
}
func (r *recordingDomainStore) PutDomain(_ context.Context, d *tenant.Domain) error {
	r.created = d
	return nil
}

func TestRecordAdmin_NoActorContextStillAudits(t *testing.T) {
	t.Parallel()
	store := &recordingDomainStore{}
	sink := audit.NewMemorySink(4)
	conn := startTenantAdminGRPC(t, store, audit.New(sink), nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	if _, err := c.CreateDomain(context.Background(), &adminv1.CreateDomainRequest{
		Domain: &adminv1.Domain{Hostname: "acme.example.com", TenantId: "acme"},
	}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if sink.Len() != 1 {
		t.Fatalf("expected 1 audit event, got %d", sink.Len())
	}
	evts, _ := sink.Query(context.Background(), audit.Query{Limit: 1})
	// No admin actor was injected into the bufconn context -> ActorID empty.
	if evts[0].ActorID != "" {
		t.Errorf("expected empty actor, got %q", evts[0].ActorID)
	}
	if evts[0].Type != audit.EventAdminDomainCreated {
		t.Errorf("unexpected event type %s", evts[0].Type)
	}
}
