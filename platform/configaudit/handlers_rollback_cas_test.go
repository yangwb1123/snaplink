package configaudit_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/platform/configaudit"
	"github.com/yangwb1123/snaplink/shared/core"
)

type rollbackStoreWithoutCAS struct{ configaudit.Store }

func TestHandleRollback_ExpectedVersionConflictPreservesBaseline(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store, running: map[string]any{"v": 3}, actor: "operator"}
	apply := func(v int) string {
		t.Helper()
		snapshot := map[string]any{"v": v}
		body := `{"snapshot":` + mustJSON(t, snapshot) + `,"digest":"` + digestOf(t, snapshot) + `","reason":"apply"}`
		ctx, w := httpCtxApply("/api/v1/admin/config/apply", "approve=true", body)
		configaudit.HandleApply(d, ctx)
		if w.Code != 200 {
			t.Fatalf("apply status = %d, body=%s", w.Code, w.Body.String())
		}
		version, err := store.Applied(context.Background())
		if err != nil {
			t.Fatalf("Applied: %v", err)
		}
		return version.ID
	}
	first := apply(1)
	second := apply(2)
	ctx, w := httpCtxApply("/api/v1/admin/config/rollback", "approve=true", `{"reason":"rollback","expected_version_id":"`+first+`"}`)
	configaudit.HandleRollback(d, ctx)
	if w.Code != 409 || decodeBody(t, w)[core.KeyError] != core.ErrConfigApplyConflict {
		t.Fatalf("status = %d body=%s, want CAS conflict", w.Code, w.Body.String())
	}
	current, err := store.Applied(context.Background())
	if err != nil || current.ID != second {
		t.Fatalf("CAS conflict changed baseline: %+v, err=%v", current, err)
	}
}

func TestHandleRollback_ExpectedVersionWithoutCASReturns501(t *testing.T) {
	store := rollbackStoreWithoutCAS{Store: configaudit.NewMemoryStore(0)}
	d := handlerDeps{store: store}
	ctx, w := httpCtxApply("/api/v1/admin/config/rollback", "approve=true",
		`{"reason":"rollback","expected_version_id":"v2"}`)
	configaudit.HandleRollback(d, ctx)
	if w.Code != 501 || decodeBody(t, w)[core.KeyError] != core.ErrConfigRollbackNotAvailable {
		t.Fatalf("status = %d body=%s, want 501 %q", w.Code, w.Body.String(), core.ErrConfigRollbackNotAvailable)
	}
}
