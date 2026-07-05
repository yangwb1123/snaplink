package grpcadmin

import (
	"context"
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
