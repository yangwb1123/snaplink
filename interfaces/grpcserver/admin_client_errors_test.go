package grpcserver_test

import (
	"context"
	"errors"
	"testing"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// erroringClientStore returns a configured error from every read/write call.
// Used to exercise the codes.Internal branches in ClientAdminService.
type erroringClientStore struct{ err error }

func (e *erroringClientStore) Get(context.Context, string) (*sso.Client, error) {
	return nil, e.err
}
func (e *erroringClientStore) ValidateSecret(context.Context, string, string) error {
	return e.err
}
func (e *erroringClientStore) List(context.Context) ([]*sso.Client, error) {
	return nil, e.err
}
func (e *erroringClientStore) Add(context.Context, *sso.Client) error    { return e.err }
func (e *erroringClientStore) Update(context.Context, *sso.Client) error { return e.err }
func (e *erroringClientStore) Delete(context.Context, string) error      { return e.err }
func (e *erroringClientStore) RotateSecret(context.Context, string) (string, error) {
	return "", e.err
}

// ---------- nil-store → FailedPrecondition ----------

func TestClientAdmin_NilStore_FailedPrecondition(t *testing.T) {
	t.Parallel()
	conn := startAdminGRPC(t, nil, nil, nil, nil, nil, nil)
	c := adminv1.NewClientAdminServiceClient(conn)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"List", func() error { _, e := c.List(ctx, &adminv1.ListClientsRequest{}); return e }},
		{"Get", func() error {
			_, e := c.Get(ctx, &adminv1.GetClientRequest{Id: "x"})
			return e
		}},
		{"Create", func() error {
			_, e := c.Create(ctx, &adminv1.CreateClientRequest{Client: &adminv1.Client{Id: "x"}})
			return e
		}},
		{"Update", func() error {
			_, e := c.Update(ctx, &adminv1.UpdateClientRequest{Client: &adminv1.Client{Id: "x"}})
			return e
		}},
		{"Delete", func() error {
			_, e := c.Delete(ctx, &adminv1.DeleteClientRequest{Id: "x"})
			return e
		}},
		{"RotateSecret", func() error {
			_, e := c.RotateSecret(ctx, &adminv1.RotateSecretRequest{Id: "x"})
			return e
		}},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", tc.name, got)
		}
	}
}

// ---------- empty Id → InvalidArgument ----------

func TestClientAdmin_EmptyID_InvalidArgument(t *testing.T) {
	t.Parallel()
	store := &erroringClientStore{} // any non-nil store passes the FailedPrecondition gate
	conn := startAdminGRPC(t, store, nil, nil, nil, nil, nil)
	c := adminv1.NewClientAdminServiceClient(conn)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"Get-empty", func() error { _, e := c.Get(ctx, &adminv1.GetClientRequest{}); return e }},
		{"Create-nil-client", func() error {
			_, e := c.Create(ctx, &adminv1.CreateClientRequest{})
			return e
		}},
		{"Create-empty-id", func() error {
			_, e := c.Create(ctx, &adminv1.CreateClientRequest{Client: &adminv1.Client{}})
			return e
		}},
		{"Update-nil-client", func() error {
			_, e := c.Update(ctx, &adminv1.UpdateClientRequest{})
			return e
		}},
		{"Update-empty-id", func() error {
			_, e := c.Update(ctx, &adminv1.UpdateClientRequest{Client: &adminv1.Client{}})
			return e
		}},
		{"Delete-empty", func() error { _, e := c.Delete(ctx, &adminv1.DeleteClientRequest{}); return e }},
		{"RotateSecret-empty", func() error {
			_, e := c.RotateSecret(ctx, &adminv1.RotateSecretRequest{})
			return e
		}},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", tc.name, got)
		}
	}
}

// ---------- store error → Internal ----------

func TestClientAdmin_StoreError_Internal(t *testing.T) {
	t.Parallel()
	store := &erroringClientStore{err: errors.New("db unavailable")}
	conn := startAdminGRPC(t, store, nil, nil, nil, nil, nil)
	c := adminv1.NewClientAdminServiceClient(conn)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"List", func() error { _, e := c.List(ctx, &adminv1.ListClientsRequest{}); return e }},
		{"Get", func() error {
			_, e := c.Get(ctx, &adminv1.GetClientRequest{Id: "x"})
			return e
		}},
		{"Create", func() error {
			_, e := c.Create(ctx, &adminv1.CreateClientRequest{Client: &adminv1.Client{Id: "x"}})
			return e
		}},
		{"Delete", func() error {
			_, e := c.Delete(ctx, &adminv1.DeleteClientRequest{Id: "x"})
			return e
		}},
		{"RotateSecret", func() error {
			_, e := c.RotateSecret(ctx, &adminv1.RotateSecretRequest{Id: "x"})
			return e
		}},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.Internal {
			t.Errorf("%s: code = %v, want Internal", tc.name, got)
		}
	}
}

// Get on a missing-but-otherwise-functional store maps ErrNoSuchClient to
// codes.NotFound. The existing CRUD test triggers this indirectly via
// post-delete Get; pinning it explicitly so a refactor to that path
// doesn't accidentally drop the mapping.
func TestClientAdmin_Get_NotFound(t *testing.T) {
	t.Parallel()
	store := &erroringClientStore{err: sso.ErrNoSuchClient}
	conn := startAdminGRPC(t, store, nil, nil, nil, nil, nil)
	c := adminv1.NewClientAdminServiceClient(conn)

	_, err := c.Get(context.Background(), &adminv1.GetClientRequest{Id: "ghost"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

func TestClientAdmin_RotateSecret_NotFound(t *testing.T) {
	t.Parallel()
	store := &erroringClientStore{err: sso.ErrNoSuchClient}
	conn := startAdminGRPC(t, store, nil, nil, nil, nil, nil)
	c := adminv1.NewClientAdminServiceClient(conn)

	_, err := c.RotateSecret(context.Background(), &adminv1.RotateSecretRequest{Id: "ghost"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

// ---------- helper-coverage smoke checks ----------

func TestClientToProto_Nil(t *testing.T) {
	t.Parallel()
	// Round-trips the nil branch of the unexported clientToProto helper
	// via the public API: when ClientStore.Get returns (nil, nil), Get
	// must not panic and the returned proto's Client field is nil too.
	store := &nilClientStore{}
	conn := startAdminGRPC(t, store, nil, nil, nil, nil, nil)
	c := adminv1.NewClientAdminServiceClient(conn)
	resp, err := c.Get(context.Background(), &adminv1.GetClientRequest{Id: "x"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.Client != nil {
		t.Errorf("expected nil proto Client for nil sso.Client, got %+v", resp.Client)
	}
}

// nilClientStore returns (nil, nil) — an unusual but legal contract that
// exercises the nil branch in clientToProto.
type nilClientStore struct{ erroringClientStore }

func (n *nilClientStore) Get(context.Context, string) (*sso.Client, error) { return nil, nil }
