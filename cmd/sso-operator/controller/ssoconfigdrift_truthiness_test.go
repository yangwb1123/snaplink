package controller

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	drift "github.com/yangwb1123/snaplink/cmd/sso-operator/apiv1alpha1"
)

// rawRunningServer behaves like runningServer but serves an exact raw
// JSON body — the map-typed helper cannot express the decode-fail pins
// {"running": [1,2,3]} and {"running": "x"}.
func rawRunningServer(t *testing.T, wantToken, rawBody string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_token"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, rawBody)
	}))
}

// mustNotContact returns a handler that fails the test if any request
// reaches it — used to assert "the POST to cluster B never happens".
func mustNotContact(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t.Errorf("cluster B must not be contacted, got %s %s", req.Method, req.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})
}

// buildReconcilerWithStatus is buildReconciler plus a pre-seeded status,
// for the sharp "never reset to false" variant: a failed check must keep
// prior DriftDetected/PatchOpCount values exactly.
func buildReconcilerWithStatus(t *testing.T, serverA, serverB *httptest.Server, pollInterval string, status drift.SSOConfigDriftStatus) (*Reconciler, types.NamespacedName) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("register corev1: %v", err)
	}
	if err := drift.AddToScheme(scheme); err != nil {
		t.Fatalf("register drift v1alpha1: %v", err)
	}

	secretA := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-a-token", Namespace: testNamespace},
		Data:       map[string][]byte{tokenAKey: []byte("token-a-secret-value")},
	}
	secretB := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-b-token", Namespace: testNamespace},
		Data:       map[string][]byte{tokenBKey: []byte("token-b-secret-value")},
	}
	cr := &drift.SSOConfigDrift{
		ObjectMeta: metav1.ObjectMeta{Name: testName, Namespace: testNamespace},
		Spec: drift.SSOConfigDriftSpec{
			ClusterA: drift.ClusterEndpoint{
				BaseURL:         serverA.URL,
				BearerSecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "cluster-a-token"}, Key: tokenAKey},
			},
			ClusterB: drift.ClusterEndpoint{
				BaseURL:         serverB.URL,
				BearerSecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "cluster-b-token"}, Key: tokenBKey},
			},
			PollInterval: pollInterval,
		},
		Status: status,
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&drift.SSOConfigDrift{}).
		WithObjects(cr, secretA, secretB).
		Build()
	return &Reconciler{Client: c, HTTPClient: testHTTPClient()}, types.NamespacedName{Namespace: testNamespace, Name: testName}
}

// TestReconcile_InvalidOpSet_FailsPreservingStatus pins acceptance (a)
// op-set rule at the observable Status level: a move op (which the
// server's documented emit set never produces) fails the check with the
// exact static message, and DriftDetected/PatchOpCount keep their
// previous values — fresh (false/0) AND pre-seeded (true/3): never reset
// to a false "no drift" on unverifiable data.
func TestReconcile_InvalidOpSet_FailsPreservingStatus(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", map[string]interface{}{"issuer": "https://a.example"})
	defer serverA.Close()
	serverB := diffServer(t, "token-b-secret-value", []map[string]interface{}{
		{"op": "move", "path": "/issuer"},
	})
	defer serverB.Close()

	t.Run("fresh status stays false/0", func(t *testing.T) {
		r, key := buildReconciler(t, serverA, serverB, "1m")
		res, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("Reconcile returned error: %v", err)
		}
		if res.RequeueAfter != shortRequeueInterval {
			t.Errorf("RequeueAfter = %v, want %v on failure", res.RequeueAfter, shortRequeueInterval)
		}
		status := fetchStatus(t, r, key)
		want := "cluster B diff response failed structural validation: op[0]: unsupported operation"
		if status.Message != want {
			t.Errorf("Message = %q, want exact static message %q", status.Message, want)
		}
		if strings.Contains(status.Message, "token-a-secret-value") || strings.Contains(status.Message, "token-b-secret-value") {
			t.Errorf("Message leaked a bearer token: %q", status.Message)
		}
		if status.DriftDetected {
			t.Errorf("DriftDetected = true, want unchanged (false)")
		}
		if status.PatchOpCount != 0 {
			t.Errorf("PatchOpCount = %d, want unchanged (0)", status.PatchOpCount)
		}
	})

	t.Run("pre-seeded true/3 stays true/3", func(t *testing.T) {
		r, key := buildReconcilerWithStatus(t, serverA, serverB, "1m", drift.SSOConfigDriftStatus{
			DriftDetected: true,
			PatchOpCount:  3,
		})
		if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("Reconcile returned error: %v", err)
		}
		status := fetchStatus(t, r, key)
		if !status.DriftDetected {
			t.Errorf("DriftDetected = false, want preserved (true) — never reset on unverifiable data")
		}
		if status.PatchOpCount != 3 {
			t.Errorf("PatchOpCount = %d, want preserved (3)", status.PatchOpCount)
		}
	})
}

// TestReconcile_UnresolvablePath_FailsPreservingStatus pins acceptance
// (a) resolution rule at reconcile level (the unit-level matrix covers
// the rest).
func TestReconcile_UnresolvablePath_FailsPreservingStatus(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", map[string]interface{}{"issuer": "https://a.example"})
	defer serverA.Close()
	serverB := diffServer(t, "token-b-secret-value", []map[string]interface{}{
		{"op": "remove", "path": "/no_such_key"},
	})
	defer serverB.Close()

	r, key := buildReconciler(t, serverA, serverB, "1m")
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	want := "cluster B diff response failed structural validation: op[0]: remove path does not resolve into the snapshot"
	if status.Message != want {
		t.Errorf("Message = %q, want %q", status.Message, want)
	}
	if status.DriftDetected {
		t.Errorf("DriftDetected = true, want unchanged (false)")
	}
	if status.PatchOpCount != 0 {
		t.Errorf("PatchOpCount = %d, want unchanged (0)", status.PatchOpCount)
	}
}

// TestReconcile_EmptyRunning_FailsWithoutContactingClusterB pins
// acceptance (b): an empty running snapshot is rejected BEFORE the POST
// to cluster B (the server itself 400s len(snapshot)==0, handlers.go:105,
// so a 200 empty-patch pair is unverifiable), and the decode-fail pins
// keep failing as today.
func TestReconcile_EmptyRunning_FailsWithoutContactingClusterB(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", map[string]interface{}{})
	defer serverA.Close()
	serverB := httptest.NewTLSServer(mustNotContact(t))
	defer serverB.Close()

	r, key := buildReconciler(t, serverA, serverB, "1m")
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	if status.Message == "" || status.Message == "no drift: cluster B matches cluster A's running config" {
		t.Errorf("Message = %q, want a structural-validation failure, not the no-drift summary", status.Message)
	}
	if !strings.Contains(status.Message, "cluster A running config failed structural validation: running snapshot is empty") {
		t.Errorf("Message = %q, want the exact empty-snapshot failure", status.Message)
	}
	if status.DriftDetected {
		t.Errorf("DriftDetected = true, want unchanged (false)")
	}
	if status.PatchOpCount != 0 {
		t.Errorf("PatchOpCount = %d, want unchanged (0)", status.PatchOpCount)
	}
}

// TestReconcile_DecodeInvalidRunning_FailsPins pins the pre-existing
// decode-fail regression lock from acceptance (b): non-object running
// bodies already fail in fetchRunningConfig today and must keep failing.
func TestReconcile_DecodeInvalidRunning_FailsPins(t *testing.T) {
	for _, raw := range []string{`{"running": [1,2,3]}`, `{"running": "x"}`} {
		serverA := rawRunningServer(t, "token-a-secret-value", raw)
		defer serverA.Close()
		serverB := httptest.NewTLSServer(mustNotContact(t))
		defer serverB.Close()

		r, key := buildReconciler(t, serverA, serverB, "1m")
		if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("Reconcile returned error: %v", err)
		}
		status := fetchStatus(t, r, key)
		if status.Message == "" || status.Message == "no drift: cluster B matches cluster A's running config" {
			t.Errorf("body %s: Message = %q, want a failure", raw, status.Message)
		}
	}
}

// TestReconcile_ServerLegitimatePatch_AcceptedUnchanged pins acceptance
// (c): the server-legitimate fixture is accepted unchanged with the exact
// observable outcome of TestReconcile_DriftDetected today.
func TestReconcile_ServerLegitimatePatch_AcceptedUnchanged(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", map[string]interface{}{"issuer": "https://a.example"})
	defer serverA.Close()
	serverB := diffServer(t, "token-b-secret-value", []map[string]interface{}{
		{"op": "replace", "path": "/issuer", "value": "https://b.example"},
		{"op": "add", "path": "/new_field", "value": true},
	})
	defer serverB.Close()

	r, key := buildReconciler(t, serverA, serverB, "1m")
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	if !status.DriftDetected {
		t.Errorf("DriftDetected = false, want true")
	}
	if status.PatchOpCount != 2 {
		t.Errorf("PatchOpCount = %d, want 2", status.PatchOpCount)
	}
	if want := "drift detected: 2 patch operation(s) needed on cluster B"; status.Message != want {
		t.Errorf("Message = %q, want %q", status.Message, want)
	}
}

// TestReconcile_NoDrift_ExactMessage strengthens the regression lock on
// acceptance (c): the success-path no-drift wording must stay exact (the
// existing TestReconcile_NoDrift asserts only DriftDetected/PatchOpCount;
// this test pins the full message so a future drift of the success path
// is caught).
func TestReconcile_NoDrift_ExactMessage(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", map[string]interface{}{"issuer": "https://same.example"})
	defer serverA.Close()
	serverB := diffServer(t, "token-b-secret-value", []map[string]interface{}{})
	defer serverB.Close()

	r, key := buildReconciler(t, serverA, serverB, "1m")
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	if want := "no drift: cluster B matches cluster A's running config"; status.Message != want {
		t.Errorf("Message = %q, want %q", status.Message, want)
	}
	if status.DriftDetected {
		t.Errorf("DriftDetected = true, want false")
	}
}
