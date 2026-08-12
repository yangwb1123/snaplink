package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	commercehttp "github.com/yangwb1123/snaplink/interfaces/commerce"
	"github.com/yangwb1123/snaplink/interfaces/scopecontract"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestContractRouterEnforcesExactReadAndWriteScopes(t *testing.T) {
	router := core.NewStdRouter()
	protected, err := newAdminContractRouter(router)
	if err != nil {
		t.Fatal(err)
	}
	protected.GET(commercehttp.PathPlans, statusHandler(http.StatusOK))
	protected.POST(commercehttp.PathPlans, statusHandler(http.StatusCreated))
	if err := protected.Err(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, method, scope string
		want                int
	}{
		{"reader reads", http.MethodGet, commercehttp.ScopeAdminRead, http.StatusOK},
		{"reader cannot write", http.MethodPost, commercehttp.ScopeAdminRead, http.StatusForbidden},
		{"writer writes", http.MethodPost, commercehttp.ScopeAdminWrite, http.StatusCreated},
		{"writer is not reader", http.MethodGet, commercehttp.ScopeAdminWrite, http.StatusForbidden},
		{"admin wildcard reads", http.MethodGet, "admin:*", http.StatusOK},
		{"admin wildcard writes", http.MethodPost, "admin:*", http.StatusCreated},
		{"missing claims", http.MethodGet, "", http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serveWithClaims(router, test.method, commercehttp.PathPlans, test.scope)
			if response.Code != test.want {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			if test.want == http.StatusForbidden &&
				!strings.Contains(response.Header().Get("WWW-Authenticate"), `scope="`) {
				t.Fatalf("challenge = %q", response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestContractRouterRefusesUndeclaredRoute(t *testing.T) {
	router := core.NewStdRouter()
	protected, err := newAdminContractRouter(router)
	if err != nil {
		t.Fatal(err)
	}
	protected.GET("/api/v1/admin/commerce/undeclared", statusHandler(http.StatusOK))
	if protected.Err() == nil {
		t.Fatal("undeclared admin route did not fail registration")
	}
	response := serveWithClaims(router, http.MethodGet, "/api/v1/admin/commerce/undeclared", commercehttp.ScopeAdminRead)
	if response.Code != http.StatusNotFound {
		t.Fatalf("undeclared route status = %d", response.Code)
	}
}

func TestContractRouterDetectsIncompleteRegistration(t *testing.T) {
	protected, err := newAdminContractRouter(core.NewStdRouter())
	if err != nil {
		t.Fatal(err)
	}
	protected.GET(commercehttp.PathPlans, statusHandler(http.StatusOK))
	if !errors.Is(protected.ValidateComplete(), errRouteContract) {
		t.Fatalf("ValidateComplete() error = %v", protected.ValidateComplete())
	}
}

func statusHandler(status int) core.HandlerFunc {
	return func(ctx core.HandlerContext) { ctx.ResponseWriter().WriteHeader(status) }
}

// TestContractRouter_MatrixProvisionedNo403 (B4-2 acceptance row 5): a token
// minted under the scope-matrix-v2 registry carries scopes from
// interfaces/scopecontract (the registry's matrix); every matrix scope that
// maps to a commerce route must pass the billing admin gate — no 403 — and
// the audit relay scope must never collide with the admin read/write gates.
func TestContractRouter_MatrixProvisionedNo403(t *testing.T) {
	router := core.NewStdRouter()
	protected, err := newAdminContractRouter(router)
	if err != nil {
		t.Fatal(err)
	}
	protected.GET(commercehttp.PathPlans, statusHandler(http.StatusOK))
	protected.POST(commercehttp.PathPlans, statusHandler(http.StatusCreated))
	if err := protected.Err(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, method, scope string
		want                int
	}{
		{"matrix admin:read reads", http.MethodGet, scopecontract.ScopeAdminRead, http.StatusOK},
		{"matrix admin:write writes", http.MethodPost, scopecontract.ScopeAdminWrite, http.StatusCreated},
		{"matrix admin:* reads", http.MethodGet, scopecontract.ScopeAdminWildcard, http.StatusOK},
		{"matrix admin:* writes", http.MethodPost, scopecontract.ScopeAdminWildcard, http.StatusCreated},
		{"audit relay scope is not admin", http.MethodGet, scopecontract.ScopeAuditEventWrite, http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serveWithClaims(router, test.method, commercehttp.PathPlans, test.scope)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d (body=%s)", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func serveWithClaims(router http.Handler, method, path, scope string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	if scope != "" {
		claims := &rs.Claims{Subject: "operator", ClientID: "console", Scope: scope}
		request = request.WithContext(rs.NewContext(request.Context(), claims))
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}
