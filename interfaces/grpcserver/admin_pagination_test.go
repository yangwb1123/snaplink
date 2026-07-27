package grpcserver_test

import (
	"context"
	"strings"
	"testing"
	"time"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestClientAdmin_ListPagination walks the ClientAdmin.List RPC one row at a
// time via NextPageToken and asserts stable id-order + accurate TotalSize,
// then exercises the InvalidArgument error paths for a malformed page_token
// and an unsupported order_by field.
func TestClientAdmin_ListPagination(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	for _, id := range []string{"c1", "c2", "c3"} {
		if err := store.Add(ctx, &sso.Client{ID: id, Name: "n-" + id, Active: true}); err != nil {
			t.Fatal(err)
		}
	}
	conn := startAdminGRPC(t, store, nil, nil, nil, nil, audit.New(audit.NewMemorySink(10)))
	c := adminv1.NewClientAdminServiceClient(conn)

	var ids []string
	token := ""
	for {
		resp, err := c.List(ctx, &adminv1.ListClientsRequest{PageSize: 1, PageToken: token})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if resp.TotalSize != 3 {
			t.Fatalf("TotalSize=%d want 3", resp.TotalSize)
		}
		for _, cl := range resp.Clients {
			ids = append(ids, cl.Id)
			if cl.Secret != "" {
				t.Fatal("secret leaked in List")
			}
		}
		if resp.NextPageToken == "" {
			break
		}
		token = resp.NextPageToken
	}
	if got := strings.Join(ids, ","); got != "c1,c2,c3" {
		t.Fatalf("order=%q want c1,c2,c3", got)
	}
	if _, err := c.List(ctx, &adminv1.ListClientsRequest{PageToken: "!!bad!!"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad token: got %v want InvalidArgument", err)
	}
	if _, err := c.List(ctx, &adminv1.ListClientsRequest{OrderBy: "bogus"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad order_by: got %v", err)
	}
}

// TestClientAdmin_ListFilterAndOrder covers the 'active:false' filter and a
// descending order_by ('-id'), and confirms an unsupported filter field is
// rejected.
func TestClientAdmin_ListFilterAndOrder(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	seed := []*sso.Client{
		{ID: "c1", Name: "n-c1", Active: true},
		{ID: "c2", Name: "n-c2", Active: false},
		{ID: "c3", Name: "n-c3", Active: true},
	}
	for _, c := range seed {
		if err := store.Add(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	conn := startAdminGRPC(t, store, nil, nil, nil, nil, nil)
	c := adminv1.NewClientAdminServiceClient(conn)

	// Filter narrows to the single inactive client.
	resp, err := c.List(ctx, &adminv1.ListClientsRequest{Filter: "active:false"})
	if err != nil {
		t.Fatalf("List filter: %v", err)
	}
	if resp.TotalSize != 1 || len(resp.Clients) != 1 || resp.Clients[0].Id != "c2" {
		t.Fatalf("filter active:false = %+v", resp.Clients)
	}

	// order_by '-id' reverses the stable default order.
	resp, err = c.List(ctx, &adminv1.ListClientsRequest{OrderBy: "-id"})
	if err != nil {
		t.Fatalf("List order_by -id: %v", err)
	}
	var ids []string
	for _, cl := range resp.Clients {
		ids = append(ids, cl.Id)
	}
	if got := strings.Join(ids, ","); got != "c3,c2,c1" {
		t.Fatalf("order_by -id = %q want c3,c2,c1", got)
	}

	// Unsupported filter field -> InvalidArgument.
	if _, err := c.List(ctx, &adminv1.ListClientsRequest{Filter: "bogus:x"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bogus filter field: got %v want InvalidArgument", err)
	}
}

// TestUserAdmin_ListPagination mirrors the client walk for users and also
// exercises created_at ordering + a provider filter, which are user-only
// fields (core.User has CreatedAt; core.Client does not).
func TestUserAdmin_ListPagination(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, seed := range []*sso.User{
		{ID: "u1", Provider: "password", Name: "Alice"},
		{ID: "u2", Provider: "password", Name: "Bob"},
		{ID: "u3", Provider: "ldap", Name: "Carol"},
	} {
		// Distinct CreatedAt so order_by=created_at is deterministic —
		// MemoryUserProvider.CreateOrUpdate does not stamp it itself.
		seed.CreatedAt = base.Add(time.Duration(i) * time.Minute)
		if err := users.CreateOrUpdate(ctx, seed); err != nil {
			t.Fatal(err)
		}
	}
	conn := startAdminGRPC(t, nil, users, nil, nil, nil, nil)
	c := adminv1.NewUserAdminServiceClient(conn)

	var ids []string
	token := ""
	for {
		resp, err := c.List(ctx, &adminv1.ListUsersRequest{PageSize: 1, PageToken: token, OrderBy: "created_at"})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if resp.TotalSize != 3 {
			t.Fatalf("TotalSize=%d want 3", resp.TotalSize)
		}
		for _, u := range resp.Users {
			ids = append(ids, u.Id)
		}
		if resp.NextPageToken == "" {
			break
		}
		token = resp.NextPageToken
	}
	if got := strings.Join(ids, ","); got != "u1,u2,u3" {
		t.Fatalf("created_at order=%q want u1,u2,u3", got)
	}

	// provider filter narrows to the ldap user.
	resp, err := c.List(ctx, &adminv1.ListUsersRequest{Filter: "provider:ldap"})
	if err != nil {
		t.Fatalf("List provider filter: %v", err)
	}
	if resp.TotalSize != 1 || len(resp.Users) != 1 || resp.Users[0].Id != "u3" {
		t.Fatalf("filter provider:ldap = %+v", resp.Users)
	}

	// Unsupported order_by field -> InvalidArgument.
	if _, err := c.List(ctx, &adminv1.ListUsersRequest{OrderBy: "bogus"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bogus order_by: got %v want InvalidArgument", err)
	}
	// Unsupported filter field -> InvalidArgument. Users have their own
	// matcher switch (userMatches), distinct from clients', so this must be
	// exercised here too rather than relying on the client-side coverage.
	if _, err := c.List(ctx, &adminv1.ListUsersRequest{Filter: "bogus:x"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bogus filter field: got %v want InvalidArgument", err)
	}
	// Malformed page_token -> InvalidArgument.
	if _, err := c.List(ctx, &adminv1.ListUsersRequest{PageToken: "!!bad!!"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad token: got %v want InvalidArgument", err)
	}
}
