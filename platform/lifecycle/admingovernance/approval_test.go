package admingovernance

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryApprovalStore_ProposeApproveLifecycle(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()

	c, err := store.Propose(ctx, ChangeRequest{
		ID: "chg1", ActionType: "tenant_delete", Payload: []byte(`{"id":"acme"}`),
		Reason: "customer offboarding", ProposedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if c.Status != ChangeStatusPending {
		t.Fatalf("Status = %q; want pending", c.Status)
	}

	got, err := store.Get(ctx, "chg1")
	if err != nil || got.ID != "chg1" {
		t.Fatalf("Get = %+v, %v", got, err)
	}

	list, err := store.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}

	approved, err := store.Approve(ctx, "chg1", "admin-b")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if approved.Status != ChangeStatusApproved || approved.ApprovedBy != "admin-b" {
		t.Fatalf("approved = %+v", approved)
	}
}

func assertStoredPayload(t *testing.T, store *MemoryApprovalStore, ctx context.Context, id, want string) {
	t.Helper()
	got, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get(%q): %v", id, err)
	}
	if string(got.Payload) != want {
		t.Fatalf("stored payload = %q; want %q", got.Payload, want)
	}
}

func TestMemoryApprovalStore_PayloadCopiesOnProposeAndRead(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	const want = `{"id":"acme"}`
	payload := []byte(want)

	proposed, err := store.Propose(ctx, ChangeRequest{
		ID: "chg1", ActionType: "tenant_delete", Payload: payload, ProposedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	payload[0] = 'x'
	proposed.Payload[0] = 'y'
	assertStoredPayload(t, store, ctx, "chg1", want)

	got, err := store.Get(ctx, "chg1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got.Payload[0] = 'z'
	assertStoredPayload(t, store, ctx, "chg1", want)

	list, err := store.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	list[0].Payload[0] = 'q'
	assertStoredPayload(t, store, ctx, "chg1", want)
}

func TestMemoryApprovalStore_PostApprovalPayloadSnapshot(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	const want = `{"id":"acme"}`

	_, err := store.Propose(ctx, ChangeRequest{
		ID: "approved", ActionType: "tenant_delete", Payload: []byte(want), ProposedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("Propose approved: %v", err)
	}
	approved, err := store.Approve(ctx, "approved", "admin-b")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	approved.Payload[0] = 'a'
	assertStoredPayload(t, store, ctx, "approved", want)

	applied, err := store.MarkApplied(ctx, "approved")
	if err != nil {
		t.Fatalf("MarkApplied: %v", err)
	}
	applied.Payload[0] = 'p'
	assertStoredPayload(t, store, ctx, "approved", want)

	_, err = store.Propose(ctx, ChangeRequest{
		ID: "rejected", ActionType: "tenant_delete", Payload: []byte(want), ProposedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("Propose rejected: %v", err)
	}
	rejected, err := store.Reject(ctx, "rejected", "admin-b")
	if err != nil {
		t.Fatalf("Reject: %v", err)
	}
	rejected.Payload[0] = 'r'
	assertStoredPayload(t, store, ctx, "rejected", want)

	_, err = store.Propose(ctx, ChangeRequest{
		ID: "failed", ActionType: "tenant_delete", Payload: []byte(want), ProposedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("Propose failed: %v", err)
	}
	if _, err = store.Approve(ctx, "failed", "admin-b"); err != nil {
		t.Fatalf("Approve failed: %v", err)
	}
	failed, err := store.MarkFailed(ctx, "failed", "apply failed")
	if err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	failed.Payload[0] = 'f'
	assertStoredPayload(t, store, ctx, "failed", want)
}

func TestMemoryApprovalStore_PreservesPayloadNilSemantics(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		wantNil bool
	}{
		{name: "nil", payload: nil, wantNil: true},
		{name: "empty", payload: []byte{}, wantNil: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryApprovalStore()
			ctx := context.Background()
			proposed, err := store.Propose(ctx, ChangeRequest{ID: tc.name, Payload: tc.payload})
			if err != nil {
				t.Fatalf("Propose: %v", err)
			}
			if (proposed.Payload == nil) != tc.wantNil {
				t.Fatalf("Propose payload nil = %v; want %v", proposed.Payload == nil, tc.wantNil)
			}
			got, err := store.Get(ctx, tc.name)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if (got.Payload == nil) != tc.wantNil {
				t.Fatalf("Get payload nil = %v; want %v", got.Payload == nil, tc.wantNil)
			}
		})
	}
}

func TestMemoryApprovalStore_SelfApprovalRejected(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "x", ProposedBy: "admin-a"})

	_, err := store.Approve(ctx, "chg1", "admin-a")
	if !errors.Is(err, ErrChangeSelfApproval) {
		t.Fatalf("Approve self = %v; want ErrChangeSelfApproval", err)
	}
	_, err = store.Approve(ctx, "chg1", "")
	if !errors.Is(err, ErrChangeSelfApproval) {
		t.Fatalf("Approve empty approver = %v; want ErrChangeSelfApproval", err)
	}
}

func TestMemoryApprovalStore_NotPendingAfterDecision(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "x", ProposedBy: "admin-a"})
	if _, err := store.Approve(ctx, "chg1", "admin-b"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if _, err := store.Approve(ctx, "chg1", "admin-c"); !errors.Is(err, ErrChangeNotPending) {
		t.Fatalf("second approve = %v; want ErrChangeNotPending", err)
	}
	if _, err := store.Reject(ctx, "chg1", "admin-c"); !errors.Is(err, ErrChangeNotPending) {
		t.Fatalf("reject already-approved = %v; want ErrChangeNotPending", err)
	}
}

func TestMemoryApprovalStore_Reject(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "x", ProposedBy: "admin-a"})
	rejected, err := store.Reject(ctx, "chg1", "admin-b")
	if err != nil || rejected.Status != ChangeStatusRejected {
		t.Fatalf("Reject = %+v, %v", rejected, err)
	}
}

func TestMemoryApprovalStore_UnknownID(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	if _, err := store.Get(ctx, "nope"); !errors.Is(err, ErrChangeNotFound) {
		t.Fatalf("Get unknown = %v; want ErrChangeNotFound", err)
	}
	if _, err := store.Approve(ctx, "nope", "admin-b"); !errors.Is(err, ErrChangeNotFound) {
		t.Fatalf("Approve unknown = %v; want ErrChangeNotFound", err)
	}
}

func TestApproveAndApply_InvokesRegisteredApplier(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{
		ID: "chg1", ActionType: "tenant_delete", Payload: []byte(`{"id":"acme"}`), ProposedBy: "admin-a",
	})

	var appliedPayload []byte
	reg := NewRegistry()
	reg.Register("tenant_delete", func(_ context.Context, payload []byte) error {
		appliedPayload = payload
		return nil
	})

	c, err := ApproveAndApply(ctx, store, reg, "chg1", "admin-b")
	if err != nil {
		t.Fatalf("ApproveAndApply: %v", err)
	}
	if c.Status != ChangeStatusApplied {
		t.Fatalf("Status = %q; want applied", c.Status)
	}
	if string(appliedPayload) != `{"id":"acme"}` {
		t.Fatalf("applier payload = %q", appliedPayload)
	}
}

func TestApproveAndApply_NoRegisteredApplierStaysApproved(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "unregistered", ProposedBy: "admin-a"})

	c, err := ApproveAndApply(ctx, store, nil, "chg1", "admin-b")
	if err != nil {
		t.Fatalf("ApproveAndApply: %v", err)
	}
	if c.Status != ChangeStatusApproved {
		t.Fatalf("Status = %q; want approved (no applier registered)", c.Status)
	}
}

func TestApproveAndApply_FailedApplierMarksFailed(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "boom", ProposedBy: "admin-a"})

	reg := NewRegistry()
	reg.Register("boom", func(context.Context, []byte) error { return errors.New("downstream unavailable") })

	c, err := ApproveAndApply(ctx, store, reg, "chg1", "admin-b")
	if err != nil {
		t.Fatalf("ApproveAndApply: %v", err)
	}
	if c.Status != ChangeStatusFailed {
		t.Fatalf("Status = %q; want failed", c.Status)
	}
	if c.FailureNote == "" {
		t.Fatal("FailureNote empty; want the applier error recorded")
	}
}

func TestApproveAndApply_PropagatesApproveError(t *testing.T) {
	store := NewMemoryApprovalStore()
	ctx := context.Background()
	_, _ = store.Propose(ctx, ChangeRequest{ID: "chg1", ActionType: "x", ProposedBy: "admin-a"})

	if _, err := ApproveAndApply(ctx, store, nil, "chg1", "admin-a"); !errors.Is(err, ErrChangeSelfApproval) {
		t.Fatalf("ApproveAndApply self-approval = %v; want ErrChangeSelfApproval", err)
	}
}

func TestRequiredActionTypes(t *testing.T) {
	empty := NewRequiredActionTypes(nil)
	if !empty.Allows("anything") {
		t.Error("empty set must allow any action type")
	}
	restricted := NewRequiredActionTypes([]string{"tenant_delete", "client_delete"})
	if !restricted.Allows("tenant_delete") {
		t.Error("restricted set must allow a listed type")
	}
	if restricted.Allows("unrelated_action") {
		t.Error("restricted set must reject an unlisted type")
	}
}
