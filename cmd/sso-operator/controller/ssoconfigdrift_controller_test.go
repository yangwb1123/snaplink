package controller

import (
	"crypto/tls"
	"encoding/json"
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

// testHTTPClient trusts ONLY self-signed httptest.NewTLSServer certs — a
// test-only simplification (production traffic goes through
// defaultHTTPClient, which does full verification). The real fix under
// test is validateBaseURL's https:// requirement, which needs real TLS
// servers (not httptest.NewServer's plain HTTP) to exercise the success
// path at all.
func testHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test-only, see comment above
}

const (
	testNamespace = "default"
	testName      = "prod-vs-staging"
	tokenAKey     = "token"
	tokenBKey     = "token"
)

// newScheme builds a runtime.Scheme with both corev1 (for Secret) and the
// SSOConfigDrift CRD registered, mirroring what main.go wires in production.
func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("register corev1: %v", err)
	}
	if err := drift.AddToScheme(s); err != nil {
		t.Fatalf("register drift v1alpha1: %v", err)
	}
	return s
}

// buildReconciler seeds a fake client with a CR pointed at the two given
// httptest servers plus their bearer-token Secrets, and returns a
// Reconciler ready to run against it.
func buildReconciler(t *testing.T, serverA, serverB *httptest.Server, pollInterval string) (*Reconciler, types.NamespacedName) {
	t.Helper()
	scheme := newScheme(t)

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
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&drift.SSOConfigDrift{}).
		WithObjects(cr, secretA, secretB).
		Build()

	return &Reconciler{Client: c, HTTPClient: testHTTPClient()}, types.NamespacedName{Namespace: testNamespace, Name: testName}
}

// fetchStatus re-reads the CR from the fake client so assertions see the
// post-reconcile state.
func fetchStatus(t *testing.T, r *Reconciler, key types.NamespacedName) drift.SSOConfigDriftStatus {
	t.Helper()
	var cr drift.SSOConfigDrift
	if err := r.Get(t.Context(), key, &cr); err != nil {
		t.Fatalf("get CR: %v", err)
	}
	return cr.Status
}

// runningServer simulates GET /api/v1/admin/config/running: it checks the
// bearer token (wantToken) and, if it matches, replies with runningBody;
// otherwise 401 like the real endpoint's bearer-auth middleware would.
func runningServer(t *testing.T, wantToken string, runningBody map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"running": runningBody})
	}))
}

// diffServer simulates POST /api/v1/admin/config/cluster-diff, replying
// with patchOps when the bearer token matches wantToken.
func diffServer(t *testing.T, wantToken string, patchOps []map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body["snapshot"] == nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": "missing snapshot"})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"patch": patchOps})
	}))
}

func TestReconcile_DriftDetected(t *testing.T) {
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
	if status.Message == "" {
		t.Errorf("Message is empty, want a summary")
	}
	if status.LastCheckedAt.IsZero() {
		t.Errorf("LastCheckedAt not set")
	}
}

func TestReconcile_NoDrift(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", map[string]interface{}{"issuer": "https://same.example"})
	defer serverA.Close()
	serverB := diffServer(t, "token-b-secret-value", []map[string]interface{}{})
	defer serverB.Close()

	r, key := buildReconciler(t, serverA, serverB, "1m")
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	if status.DriftDetected {
		t.Errorf("DriftDetected = true, want false")
	}
	if status.PatchOpCount != 0 {
		t.Errorf("PatchOpCount = %d, want 0", status.PatchOpCount)
	}
}

func TestReconcile_BadBearerTokenOnClusterA_SetsErrorMessage(t *testing.T) {
	serverA := runningServer(t, "the-real-token", nil)
	defer serverA.Close()
	serverB := diffServer(t, "token-b-secret-value", nil)
	defer serverB.Close()

	// buildReconciler wires the Secret's actual value ("token-a-secret-value"),
	// which will NOT match serverA's expected "the-real-token" — simulating a
	// stale/wrong bearer token.
	r, key := buildReconciler(t, serverA, serverB, "1m")
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	if status.Message == "" {
		t.Errorf("Message is empty, want an error summary")
	}
	if status.DriftDetected {
		t.Errorf("DriftDetected = true on a failed check, want unchanged (false)")
	}
}

func TestReconcile_ClusterBNon2xx_SetsErrorMessageNoPanic(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", map[string]interface{}{"issuer": "https://a.example"})
	defer serverA.Close()
	// A 500 from cluster B, simulating config_audit_not_available.
	serverB := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal_error"})
	}))
	defer serverB.Close()

	r, key := buildReconciler(t, serverA, serverB, "1m")
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	if status.Message == "" {
		t.Errorf("Message is empty, want an error summary")
	}
}

func TestReconcile_SecretLookupFailure_WrongKey_HandledGracefully(t *testing.T) {
	serverA := runningServer(t, "token-a-secret-value", map[string]interface{}{"issuer": "https://a.example"})
	defer serverA.Close()
	serverB := diffServer(t, "token-b-secret-value", nil)
	defer serverB.Close()

	scheme := newScheme(t)
	// Secret A exists but under a DIFFERENT key than the CR references,
	// simulating a misconfigured BearerSecretRef.Key.
	secretA := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-a-token", Namespace: testNamespace},
		Data:       map[string][]byte{"wrong-key": []byte("token-a-secret-value")},
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
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&drift.SSOConfigDrift{}).
		WithObjects(cr, secretA, secretB).
		Build()
	r := &Reconciler{Client: c, HTTPClient: testHTTPClient()}
	key := types.NamespacedName{Namespace: testNamespace, Name: testName}

	res, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if res.RequeueAfter != shortRequeueInterval {
		t.Errorf("RequeueAfter = %v, want short backoff %v on failure", res.RequeueAfter, shortRequeueInterval)
	}

	status := fetchStatus(t, r, key)
	if status.Message == "" {
		t.Errorf("Message is empty, want an error summary")
	}
	if status.DriftDetected || status.PatchOpCount != 0 {
		t.Errorf("status mutated on a secret-lookup failure: %+v", status)
	}
}

func TestReconcile_MissingCR_NoRequeueNoError(t *testing.T) {
	scheme := newScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &Reconciler{Client: c}

	res, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "does-not-exist"}})
	if err != nil {
		t.Fatalf("Reconcile returned error for a missing CR: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0 for a deleted/missing CR", res.RequeueAfter)
	}
}

// TestReconcile_PlainHTTPBaseURLRejected proves the confused-deputy
// mitigation: a CR pointing ClusterA at a plain http:// URL must be
// rejected BEFORE any bearer token is attached to a request, rather than
// silently sending the token in plaintext to whatever host the CR names.
func TestReconcile_PlainHTTPBaseURLRejected(t *testing.T) {
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t.Error("plain-HTTP cluster A must never be contacted — validateBaseURL should reject it first")
	}))
	defer serverA.Close()
	serverB := diffServer(t, "token-b-secret-value", nil)
	defer serverB.Close()

	r, key := buildReconciler(t, serverA, serverB, "1m")
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	if !strings.Contains(status.Message, "https") {
		t.Errorf("Message = %q, want it to mention the https:// requirement", status.Message)
	}
	if status.DriftDetected {
		t.Errorf("DriftDetected = true, want unchanged (false) on a rejected baseURL")
	}
}

func TestReconcile_MessageNeverContainsBearerToken(t *testing.T) {
	// Cluster A returns 401 (wrong token supplied), and the response error
	// path must never leak the token value that WAS sent.
	serverA := runningServer(t, "the-real-token-A", nil)
	defer serverA.Close()
	serverB := diffServer(t, "token-b-secret-value", nil)
	defer serverB.Close()

	r, key := buildReconciler(t, serverA, serverB, "1m")
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	status := fetchStatus(t, r, key)
	if strings.Contains(status.Message, "token-a-secret-value") {
		t.Errorf("Status.Message leaked the bearer token: %q", status.Message)
	}
}
