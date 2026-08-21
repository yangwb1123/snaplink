package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	drift "github.com/yangwb1123/snaplink/cmd/sso-operator/apiv1alpha1"
)

type recordedRollback struct {
	method string
	path   string
	query  string
	auth   string
	body   rollbackRequestBody
}

type rollbackRecorder struct {
	calls []recordedRollback
}

func (r *rollbackRecorder) len() int { return len(r.calls) }

func (r *rollbackRecorder) at(i int) recordedRollback { return r.calls[i] }

func rollbackRecordingServer(t *testing.T, wantToken string, status int, response string) (*httptest.Server, *rollbackRecorder) {
	t.Helper()
	rec := &rollbackRecorder{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_token"}`)
			return
		}
		switch req.URL.Path {
		case clusterDiffPath:
			var body map[string]interface{}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body["snapshot"] == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"patch": testDriftOps})
		case rollbackPath:
			var call recordedRollback
			call.method, call.path, call.query = req.Method, req.URL.Path, req.URL.RawQuery
			call.auth = req.Header.Get("Authorization")
			if err := json.NewDecoder(req.Body).Decode(&call.body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			rec.calls = append(rec.calls, call)
			w.WriteHeader(status)
			_, _ = io.WriteString(w, response)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv, rec
}

func buildRollbackReconciler(t *testing.T, serverA, serverB *httptest.Server, spec drift.RollbackSpec, annotations map[string]string) (*Reconciler, types.NamespacedName) {
	t.Helper()
	r, key := buildReconciler(t, serverA, serverB, "1m")
	var cr drift.SSOConfigDrift
	if err := r.Get(t.Context(), key, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	cr.Spec.Rollback = spec
	cr.Annotations = annotations
	if err := r.Update(t.Context(), &cr); err != nil {
		t.Fatalf("update CR: %v", err)
	}
	return r, key
}

func TestReconcile_Rollback_OptInApproved_UsesExpectedVersion(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB, rec := rollbackRecordingServer(t, "token-b-secret-value", http.StatusOK,
		`{"applied":{"issuer":"https://old.example"},"version":"v4","prev_version":"v3","patch":[]}`)
	defer serverB.Close()
	r, key := buildRollbackReconciler(t, serverA, serverB, drift.RollbackSpec{
		Enabled: true, Reason: "rollback-ticket", ExpectedVersionID: "v3",
	}, map[string]string{rollbackApprovalAnnotationKey: "true"})

	res, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if res.RequeueAfter != time.Minute {
		t.Errorf("RequeueAfter = %v, want PollInterval after successful rollback", res.RequeueAfter)
	}
	if rec.len() != 1 {
		t.Fatalf("rollback calls = %d, want 1", rec.len())
	}
	call := rec.at(0)
	if call.method != http.MethodPost || call.path != rollbackPath || call.query != approveQuery {
		t.Errorf("rollback request shape = %+v", call)
	}
	if call.auth != "Bearer token-b-secret-value" || call.body.ExpectedVersionID != "v3" || call.body.Reason != "rollback-ticket" {
		t.Errorf("rollback request credentials/body = %+v", call)
	}
	status := fetchStatus(t, r, key)
	if status.Rollback.State != rollbackStateRolledBack || status.Rollback.VersionID != "v4" {
		t.Errorf("rollback status = %+v", status.Rollback)
	}
	cr := fetchCR(t, r, key)
	if cr.Annotations[rollbackApprovalAnnotationKey] != "" {
		t.Errorf("rollback approval was not consumed: %v", cr.Annotations)
	}
}

func TestReconcile_Rollback_ConflictRetainsApproval(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB, rec := rollbackRecordingServer(t, "token-b-secret-value", http.StatusConflict,
		`{"error":"config_apply_conflict"}`)
	defer serverB.Close()
	r, key := buildRollbackReconciler(t, serverA, serverB, drift.RollbackSpec{
		Enabled: true, Reason: "stale-ticket", ExpectedVersionID: "v2",
	}, map[string]string{rollbackApprovalAnnotationKey: "true"})

	res, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if res.RequeueAfter != shortRequeueInterval {
		t.Errorf("RequeueAfter = %v, want short retry", res.RequeueAfter)
	}
	if rec.len() != 1 || fetchStatus(t, r, key).Rollback.State != rollbackStateConflict {
		t.Errorf("conflict outcome = calls %d status %+v", rec.len(), fetchStatus(t, r, key).Rollback)
	}
	if fetchCR(t, r, key).Annotations[rollbackApprovalAnnotationKey] != "true" {
		t.Error("rollback approval must remain for retry after conflict")
	}
}

func TestReconcile_RollbackAndApplyApprovalsRefuseBoth(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", testRunningConfig)
	defer serverA.Close()
	serverB, rec := rollbackRecordingServer(t, "token-b-secret-value", http.StatusOK, `{}`)
	defer serverB.Close()
	r, key := buildRollbackReconciler(t, serverA, serverB, drift.RollbackSpec{
		Enabled: true, Reason: "rollback-ticket", ExpectedVersionID: "v3",
	}, map[string]string{approvalAnnotationKey: "true", rollbackApprovalAnnotationKey: "true"})
	var cr drift.SSOConfigDrift
	if err := r.Get(t.Context(), key, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	cr.Spec.Apply = drift.ApplySpec{Enabled: true, Reason: testApplyReason}
	if err := r.Update(t.Context(), &cr); err != nil {
		t.Fatalf("update CR: %v", err)
	}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	status := fetchStatus(t, r, key)
	if rec.len() != 0 || status.Apply.State != applyStateRejected || status.Rollback.State != rollbackStateRejected {
		t.Errorf("combined approvals = calls %d apply=%+v rollback=%+v", rec.len(), status.Apply, status.Rollback)
	}
}
