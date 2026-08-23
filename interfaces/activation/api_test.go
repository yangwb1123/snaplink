package activationhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant/activation"
	"github.com/yangwb1123/snaplink/shared/core"
)

type testVerifier struct {
	claims *core.TokenClaims
}

func (v testVerifier) MeClaimsOrChallenge(core.HandlerContext) (*core.TokenClaims, bool) {
	return v.claims, v.claims != nil
}

func TestActivationRoutesPrepareClaimAndReadContext(t *testing.T) {
	store := activation.NewMemoryStore()
	if err := store.AddCode(context.Background(), activation.Code{
		ID: "code-1", ProductID: "console", TenantID: "acme", Key: "license-1",
	}); err != nil {
		t.Fatal(err)
	}
	router := core.NewStdRouter()
	verifier := testVerifier{claims: &core.TokenClaims{ClientID: "client", Subject: "user-1"}}
	if err := Mount(router, store, verifier); err != nil {
		t.Fatal(err)
	}
	prepare := requestJSON(t, router, http.MethodPost, PathPrepare, map[string]string{
		"client_id": "client", "product_id": "console", "license_key": "license-1",
	})
	if prepare.Code != http.StatusOK || prepare.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("prepare response = %d, headers=%v, body=%s", prepare.Code, prepare.Header(), prepare.Body.String())
	}
	var prepared struct {
		Ticket string `json:"activation_ticket"`
	}
	if err := json.Unmarshal(prepare.Body.Bytes(), &prepared); err != nil || prepared.Ticket == "" {
		t.Fatalf("prepare body = %s, %v", prepare.Body.String(), err)
	}
	claim := requestJSON(t, router, http.MethodPost, PathClaim, map[string]string{
		"product_id": "console", "activation_ticket": prepared.Ticket,
	})
	if claim.Code != http.StatusOK {
		t.Fatalf("claim response = %d: %s", claim.Code, claim.Body.String())
	}
	current := requestJSON(t, router, http.MethodGet, PathContext+"?product_id=console", nil)
	if current.Code != http.StatusOK || !bytes.Contains(current.Body.Bytes(), []byte(`"tenant_id":"acme"`)) {
		t.Fatalf("context response = %d: %s", current.Code, current.Body.String())
	}
}

func requestJSON(t *testing.T, handler http.Handler, method, path string, value map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	if value != nil {
		if err := json.NewEncoder(&body).Encode(value); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, "http://sso.test"+path, &body)
	if value != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}
