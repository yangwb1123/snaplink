package grpcadmin

import (
	"context"
	"errors"
	"testing"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/caep"
	"google.golang.org/grpc/codes"
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
		Client: &adminv1.Client{Id: "web-app", Name: "Web", Active: true, AllowedAuthenticators: []string{"password"}},
	})
	requireOK(t, err, "Create")
	if created.Client.Id != "web-app" || created.Client.Secret != "" {
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

	_, err = svc.Update(ctx, &adminv1.UpdateClientRequest{Client: &adminv1.Client{Id: "web-app", Name: "Web v2", Active: true}})
	requireOK(t, err, "Update")
	if discoveryCalls != 2 {
		t.Errorf("expected Update to fire onDiscoveryChange again, count=%d", discoveryCalls)
	}
	got, _ = svc.Get(ctx, &adminv1.GetClientRequest{Id: "web-app"})
	if got.Client.Name != "Web v2" {
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

// TestClientAdminService_UpdatePreservesUnexposedSecurityFields proves the
// admin Update RPC can't silently downgrade a client's security posture: the
// proto has no RequirePKCE/TenantID/AllowedResources fields at all, so an
// Update built from a fresh protoToClient() would zero them on every call —
// e.g. dropping PKCE enforcement from a public client. Regression test for
// that bug: applyProtoClientFields must overlay only the proto-exposed
// fields onto the EXISTING record.
func TestClientAdminService_UpdatePreservesUnexposedSecurityFields(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	requireOK(t, store.Add(context.Background(), &sso.Client{
		ID:               "spa-1",
		Name:             "SPA",
		Active:           true,
		RequirePKCE:      true,
		TenantID:         "acme",
		AllowedResources: []string{"https://api.example/"},
	}), "seed Add")

	svc := NewClientAdminService(store, nil, nil, nil)
	ctx := context.Background()

	_, err := svc.Update(ctx, &adminv1.UpdateClientRequest{
		Client: &adminv1.Client{Id: "spa-1", Name: "SPA Renamed", Active: true},
	})
	requireOK(t, err, "Update")

	stored, err := store.Get(ctx, "spa-1")
	requireOK(t, err, "Get after Update")
	if !stored.RequirePKCE {
		t.Error("Update dropped RequirePKCE — public client now has no PKCE enforcement")
	}
	if stored.TenantID != "acme" {
		t.Errorf("Update wiped TenantID, got %q", stored.TenantID)
	}
	if len(stored.AllowedResources) != 1 || stored.AllowedResources[0] != "https://api.example/" {
		t.Errorf("Update wiped AllowedResources, got %+v", stored.AllowedResources)
	}
	if stored.Name != "SPA Renamed" {
		t.Errorf("Update did not apply the new Name, got %q", stored.Name)
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
