package grpcadmin

import (
	"context"
	"errors"
	"testing"
	"time"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestClientAdminService_NilStorePreconditionFails proves every RPC returns
// FailedPrecondition (not a panic) when the store dependency is unwired —
// the documented behavior for an embedder that hasn't configured a
// ClientStore.
func TestClientAdminService_NilStorePreconditionFails(t *testing.T) {
	t.Parallel()
	svc := NewClientAdminService(nil, nil, nil, nil)
	ctx := context.Background()

	_, err := svc.List(ctx, &adminv1.ListClientsRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.ListExpiring(ctx, &adminv1.ListExpiringClientsRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Get(ctx, &adminv1.GetClientRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Create(ctx, &adminv1.CreateClientRequest{Client: &adminv1.Client{Id: "x"}})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Update(ctx, &adminv1.UpdateClientRequest{Client: &adminv1.Client{Id: "x"}})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Delete(ctx, &adminv1.DeleteClientRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.RotateSecret(ctx, &adminv1.RotateSecretRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Approve(ctx, &adminv1.ApproveClientRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Reject(ctx, &adminv1.RejectClientRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
}

// TestClientAdminService_InvalidArgument covers the missing/blank-id guard
// clauses that run before the store is ever touched.
func TestClientAdminService_InvalidArgument(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	svc := NewClientAdminService(store, nil, nil, nil)
	ctx := context.Background()

	_, err := svc.Get(ctx, &adminv1.GetClientRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Create(ctx, &adminv1.CreateClientRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Update(ctx, &adminv1.UpdateClientRequest{Client: &adminv1.Client{}})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Create(ctx, &adminv1.CreateClientRequest{Client: &adminv1.Client{
		Id: "unsafe-login", LoginPageUri: "http://public.example/login",
	}})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Delete(ctx, &adminv1.DeleteClientRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.RotateSecret(ctx, &adminv1.RotateSecretRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Approve(ctx, &adminv1.ApproveClientRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Reject(ctx, &adminv1.RejectClientRequest{})
	requireCode(t, err, codes.InvalidArgument)
}

// TestClientAdminService_CRUDAndCallbacks drives Create/Get/List/Update/
// Delete directly (no gRPC transport) and proves the onDiscoveryChange /
// onClientChange hooks fire on every mutation with the affected client ID —
// the mechanism (*sso.Server).InvalidateDiscoveryCache / InvalidateClientCache
// rely on.
func TestClientAdminService_CRUDAndCallbacks(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	var discoveryCalls int
	var lastChangedClient string
	svc := NewClientAdminService(store, rec, func() { discoveryCalls++ }, func(id string) { lastChangedClient = id })
	ctx := context.Background()

	created, err := svc.Create(ctx, &adminv1.CreateClientRequest{
		Client: &adminv1.Client{Id: "web-app", Name: "Web", Active: true, AllowedAuthenticators: []string{"password"}, LoginPageUri: "https://login.example/authorize"},
	})
	requireOK(t, err, "Create")
	if created.Client.Id != "web-app" || created.Client.Secret != "" || created.Client.LoginPageUri == "" {
		t.Errorf("Create response = %+v", created.Client)
	}
	if discoveryCalls != 1 || lastChangedClient != "web-app" {
		t.Errorf("expected callbacks to fire once for web-app, got discoveryCalls=%d lastChangedClient=%q", discoveryCalls, lastChangedClient)
	}

	_, err = svc.Create(ctx, &adminv1.CreateClientRequest{Client: &adminv1.Client{Id: "web-app"}})
	requireCode(t, err, codes.AlreadyExists)

	got, err := svc.Get(ctx, &adminv1.GetClientRequest{Id: "web-app"})
	requireOK(t, err, "Get")
	if got.Client.Name != "Web" {
		t.Errorf("Get Name = %q", got.Client.Name)
	}

	_, err = svc.Get(ctx, &adminv1.GetClientRequest{Id: "missing"})
	requireCode(t, err, codes.NotFound)

	list, err := svc.List(ctx, &adminv1.ListClientsRequest{})
	requireOK(t, err, "List")
	if len(list.Clients) != 1 {
		t.Errorf("List len = %d", len(list.Clients))
	}

	_, err = svc.Update(ctx, &adminv1.UpdateClientRequest{Client: &adminv1.Client{Id: "web-app", Name: "Web v2", Active: true, LoginPageUri: "http://127.0.0.1:8081/login/"}})
	requireOK(t, err, "Update")
	if discoveryCalls != 2 {
		t.Errorf("expected Update to fire onDiscoveryChange again, count=%d", discoveryCalls)
	}
	got, _ = svc.Get(ctx, &adminv1.GetClientRequest{Id: "web-app"})
	if got.Client.Name != "Web v2" || got.Client.LoginPageUri != "http://127.0.0.1:8081/login/" {
		t.Errorf("after Update Name=%q", got.Client.Name)
	}

	_, err = svc.Update(ctx, &adminv1.UpdateClientRequest{Client: &adminv1.Client{Id: "missing"}})
	requireCode(t, err, codes.NotFound)

	rot, err := svc.RotateSecret(ctx, &adminv1.RotateSecretRequest{Id: "web-app"})
	requireOK(t, err, "RotateSecret")
	if rot.Secret == "" {
		t.Error("RotateSecret returned empty secret")
	}
	if err := store.ValidateSecret(ctx, "web-app", rot.Secret); err != nil {
		t.Errorf("rotated secret does not validate: %v", err)
	}

	_, err = svc.Delete(ctx, &adminv1.DeleteClientRequest{Id: "web-app"})
	requireOK(t, err, "Delete")
	if lastChangedClient != "web-app" {
		t.Errorf("expected Delete to fire onClientChange with web-app, got %q", lastChangedClient)
	}
	_, err = svc.Get(ctx, &adminv1.GetClientRequest{Id: "web-app"})
	requireCode(t, err, codes.NotFound)

	_, err = svc.RotateSecret(ctx, &adminv1.RotateSecretRequest{Id: "web-app"})
	requireCode(t, err, codes.NotFound)

	events, err := sink.Query(ctx, audit.Query{})
	requireOK(t, err, "sink.Query")
	if len(events) == 0 {
		t.Error("expected mutations to record audit events")
	}
}

func TestClientAdminService_RotateSecretUsesDefaultOverlap(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	if err := store.Add(ctx, &sso.Client{ID: "overlap-client", Secret: "old-secret", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	svc := NewClientAdminService(store, nil, nil, nil)
	rotated, err := svc.RotateSecret(ctx, &adminv1.RotateSecretRequest{Id: "overlap-client"})
	requireOK(t, err, "RotateSecret")
	if err := store.ValidateSecret(ctx, "overlap-client", rotated.Secret); err != nil {
		t.Fatalf("new secret rejected: %v", err)
	}
	if err := store.ValidateSecret(ctx, "overlap-client", "old-secret"); err != nil {
		t.Fatalf("old secret must remain valid during default overlap: %v", err)
	}
	client, err := store.Get(ctx, "overlap-client")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	remaining := time.Until(client.SecretOverlapUntil)
	if remaining < 23*time.Hour || remaining > 24*time.Hour {
		t.Fatalf("default overlap remaining = %v, want approximately 24h", remaining)
	}
}

func TestClientAdminService_ExpiringAndCustomRotationPolicy(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	now := time.Now()
	for _, client := range []*sso.Client{
		{ID: "expired", Secret: "s", Active: true, SecretExpiresAt: now.Add(-time.Hour)},
		{ID: "soon", Secret: "s", Active: true, SecretExpiresAt: now.Add(2 * time.Hour)},
		{ID: "far", Secret: "s", Active: true, SecretExpiresAt: now.Add(60 * 24 * time.Hour)},
		{ID: "public", Active: true},
	} {
		if err := store.Add(ctx, client); err != nil {
			t.Fatalf("Add(%s): %v", client.ID, err)
		}
	}
	svc := NewClientAdminService(store, nil, nil, nil)
	listed, err := svc.ListExpiring(ctx, &adminv1.ListExpiringClientsRequest{})
	requireOK(t, err, "ListExpiring")
	if len(listed.Clients) != 2 || listed.Clients[0].Id != "expired" || listed.Clients[1].Id != "soon" {
		t.Fatalf("default expiring list = %+v, want [expired soon]", listed.Clients)
	}
	rotated, err := svc.RotateSecret(ctx, &adminv1.RotateSecretRequest{
		Id: "soon", OverlapSeconds: 3600, LifetimeSeconds: 7200,
	})
	requireOK(t, err, "RotateSecret(custom policy)")
	remaining := time.Until(time.Unix(rotated.ClientSecretExpiresAt, 0))
	if remaining < 119*time.Minute || remaining > 2*time.Hour {
		t.Fatalf("custom expiry remaining = %v, want approximately 2h", remaining)
	}
	if err := store.ValidateSecret(ctx, "soon", "s"); err != nil {
		t.Fatalf("old secret should work inside custom overlap: %v", err)
	}
	_, err = svc.RotateSecret(ctx, &adminv1.RotateSecretRequest{
		Id: "soon", OverlapSeconds: 1800, LifetimeSeconds: 7200,
	})
	requireCode(t, err, codes.InvalidArgument)
}

// TestClientAdminService_ApproveActivatesPendingClient covers the
// developer-app registration review workflow's approval half: a client
// registered with active=false (the DCR default_active=false posture)
// starts unable to authenticate, and Approve flips it to active and
// records a distinct EventAdminClientApproved (not the generic Updated).
func TestClientAdminService_ApproveActivatesPendingClient(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	var lastChangedClient string
	svc := NewClientAdminService(store, rec, nil, func(id string) { lastChangedClient = id })
	ctx := context.Background()

	if err := store.Add(ctx, &sso.Client{ID: "pending-app", Name: "Pending App", Active: false}); err != nil {
		t.Fatalf("seed pending client: %v", err)
	}

	resp, err := svc.Approve(ctx, &adminv1.ApproveClientRequest{Id: "pending-app"})
	requireOK(t, err, "Approve")
	if !resp.Client.Active {
		t.Error("Approve response client should be active")
	}
	if lastChangedClient != "pending-app" {
		t.Errorf("expected onClientChange to fire for pending-app, got %q", lastChangedClient)
	}
	got, err := store.Get(ctx, "pending-app")
	requireOK(t, err, "Get after Approve")
	if !got.Active {
		t.Error("stored client should be active after Approve")
	}

	events, err := sink.Query(ctx, audit.Query{})
	requireOK(t, err, "sink.Query")
	found := false
	for _, e := range events {
		if e.Type == audit.EventAdminClientApproved {
			found = true
		}
		if e.Type == audit.EventAdminClientUpdated {
			t.Error("Approve must not also emit the generic EventAdminClientUpdated")
		}
	}
	if !found {
		t.Error("expected an EventAdminClientApproved audit event")
	}

	_, err = svc.Approve(ctx, &adminv1.ApproveClientRequest{Id: "missing"})
	requireCode(t, err, codes.NotFound)
}

// TestClientAdminService_RejectDeletesClientAndRecordsReason covers the
// review workflow's rejection half: the never-activated client is
// deleted outright (not left permanently inactive), and the audit event
// carries the client's name plus the operator-supplied reason, captured
// before the record is gone.
func TestClientAdminService_RejectDeletesClientAndRecordsReason(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	var lastChangedClient string
	svc := NewClientAdminService(store, rec, nil, func(id string) { lastChangedClient = id })
	ctx := context.Background()

	if err := store.Add(ctx, &sso.Client{ID: "spammy-app", Name: "Spammy App", Active: false}); err != nil {
		t.Fatalf("seed pending client: %v", err)
	}

	_, err := svc.Reject(ctx, &adminv1.RejectClientRequest{Id: "spammy-app", Reason: "redirect_uri not owned by requester"})
	requireOK(t, err, "Reject")
	if lastChangedClient != "spammy-app" {
		t.Errorf("expected onClientChange to fire for spammy-app, got %q", lastChangedClient)
	}
	if _, err := store.Get(ctx, "spammy-app"); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("expected the rejected client to be deleted, Get err = %v", err)
	}

	events, err := sink.Query(ctx, audit.Query{})
	requireOK(t, err, "sink.Query")
	var rejectEvent *audit.Event
	for _, e := range events {
		if e.Type == audit.EventAdminClientRejected {
			rejectEvent = e
		}
	}
	if rejectEvent == nil {
		t.Fatal("expected an EventAdminClientRejected audit event")
	}
	if rejectEvent.Metadata["client_name"] != "Spammy App" {
		t.Errorf("reject event client_name = %q, want %q", rejectEvent.Metadata["client_name"], "Spammy App")
	}
	if rejectEvent.Metadata["reason"] != "redirect_uri not owned by requester" {
		t.Errorf("reject event reason = %q", rejectEvent.Metadata["reason"])
	}

	_, err = svc.Reject(ctx, &adminv1.RejectClientRequest{Id: "missing"})
	requireCode(t, err, codes.NotFound)
}

// TestClientAdminService_UpdatePreservesSecretAndAttributes proves the
// documented anti-footgun behavior: an Update whose proto Client carries no
// secret (the admin proto has no way to express "leave attributes alone"
// either, since it has no Attributes field at all) must NOT wipe the
// existing bcrypt-hashed secret or the server-side Attributes map (e.g. a
// registered CAEP receiver endpoint) already on the stored client.
func TestClientAdminService_UpdatePreservesSecretAndAttributes(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	// Seed directly (bypassing the admin proto, which has no Attributes
	// field) to simulate a client that already carries server-side
	// attributes from another write path (YAML config, DCR, ...).
	requireOK(t, store.Add(context.Background(), &sso.Client{
		ID:         "app-1",
		Name:       "App",
		Secret:     "s3cr3t-plaintext",
		Active:     true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: "https://receiver.example/events"},
	}), "seed Add")

	svc := NewClientAdminService(store, nil, nil, nil)
	ctx := context.Background()

	_, err := svc.Update(ctx, &adminv1.UpdateClientRequest{
		Client: &adminv1.Client{Id: "app-1", Name: "App Renamed", Active: true},
	})
	requireOK(t, err, "Update")

	if err := store.ValidateSecret(ctx, "app-1", "s3cr3t-plaintext"); err != nil {
		t.Errorf("Update wiped the existing secret: ValidateSecret failed: %v", err)
	}
	stored, err := store.Get(ctx, "app-1")
	requireOK(t, err, "Get after Update")
	if stored.Attributes[caep.AttrReceiverEndpoint] != "https://receiver.example/events" {
		t.Errorf("Update wiped Attributes, got %+v", stored.Attributes)
	}
	if stored.Name != "App Renamed" {
		t.Errorf("Update did not apply the new Name, got %q", stored.Name)
	}
}

// TestClientAdminService_UpdatePreservesFieldsNotInAdminProto is the
// regression test for a real data-loss bug: Update used to build the
// updated client from protoToClient's blank Client (only the ~8 fields the
// admin.v1.Client message carries), zeroing every other core.Client field —
// most notably TenantID, which governs tenant-affinity login enforcement.
// Proves TenantID, RequirePKCE, and AllowedResources (three representative
// fields absent from the admin wire contract) all survive an Update that
// only touches Name.
func TestClientAdminService_UpdatePreservesFieldsNotInAdminProto(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	requireOK(t, store.Add(context.Background(), &sso.Client{
		ID:               "app-2",
		Name:             "App",
		Active:           true,
		TenantID:         "tenant-acme",
		RequirePKCE:      true,
		AllowedResources: []string{"https://api.example/"},
	}), "seed Add")

	svc := NewClientAdminService(store, nil, nil, nil)
	ctx := context.Background()
	_, err := svc.Update(ctx, &adminv1.UpdateClientRequest{
		Client: &adminv1.Client{Id: "app-2", Name: "App Renamed", Active: true},
	})
	requireOK(t, err, "Update")

	stored, err := store.Get(ctx, "app-2")
	requireOK(t, err, "Get after Update")
	if stored.TenantID != "tenant-acme" {
		t.Errorf("Update wiped TenantID, got %q", stored.TenantID)
	}
	if !stored.RequirePKCE {
		t.Error("Update wiped RequirePKCE")
	}
	if len(stored.AllowedResources) != 1 || stored.AllowedResources[0] != "https://api.example/" {
		t.Errorf("Update wiped AllowedResources, got %+v", stored.AllowedResources)
	}
	if stored.Name != "App Renamed" {
		t.Errorf("Update did not apply the new Name, got %q", stored.Name)
	}
}

// TestClientAdminService_UpdateUnknownClientReturnsNotFound proves Update
// fails fast with NotFound (checked up front via Get) rather than
// constructing a client from a nonexistent record.
func TestClientAdminService_UpdateUnknownClientReturnsNotFound(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	svc := NewClientAdminService(store, nil, nil, nil)
	_, err := svc.Update(context.Background(), &adminv1.UpdateClientRequest{
		Client: &adminv1.Client{Id: "ghost", Name: "X"},
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("Update unknown client: got %v, want NotFound", err)
	}
}

// TestValidateClientCAEP is a direct unit test of the standalone validator
// (not reachable with a rejecting value through Create/Update, since the
// admin proto Client has no Attributes field to submit one — see the
// preserve-then-validate integration case above for how a bad attribute
// already in the store gets caught).
func TestValidateClientCAEP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		client  *sso.Client
		wantErr bool
	}{
		{"nil client", nil, false},
		{"nil attributes", &sso.Client{}, false},
		{"empty endpoint", &sso.Client{Attributes: map[string]string{}}, false},
		{"https endpoint valid", &sso.Client{Attributes: map[string]string{caep.AttrReceiverEndpoint: "https://ok.example/events"}}, false},
		{"http endpoint rejected", &sso.Client{Attributes: map[string]string{caep.AttrReceiverEndpoint: "http://insecure.example/events"}}, true},
		{"relative endpoint rejected", &sso.Client{Attributes: map[string]string{caep.AttrReceiverEndpoint: "/events"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateClientCAEP(tc.client)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateClientCAEP(%+v) error = %v, wantErr %v", tc.client, err, tc.wantErr)
			}
		})
	}
}
