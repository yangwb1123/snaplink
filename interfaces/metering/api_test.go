package meteringhttp

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestRouteContractsPinMachineScopesAndTenantlessPaths(t *testing.T) {
	want := map[string]string{
		http.MethodPost + " " + PathUsageAppend:       ScopeMeteringWrite,
		http.MethodPost + " " + PathReservations:      ScopeMeteringWrite,
		http.MethodPost + " " + PathReservationCommit: ScopeMeteringWrite,
		http.MethodDelete + " " + PathReservation:     ScopeMeteringWrite,
		http.MethodGet + " " + PathEntitlement:        ScopeEntitlementRead,
	}
	contracts := RouteContracts()
	if len(contracts) != len(want) {
		t.Fatalf("RouteContracts() count = %d, want %d", len(contracts), len(want))
	}
	for _, contract := range contracts {
		key := contract.Method + " " + contract.Path
		if want[key] != contract.RequiredScope {
			t.Errorf("contract %q scope = %q", key, contract.RequiredScope)
		}
		if strings.Contains(contract.Path, "tenant") || strings.Contains(contract.Path, "source") {
			t.Errorf("machine path accepts authority identity: %q", contract.Path)
		}
	}
}

func TestMachineAuthorizationRequiresClientCredentialsShapeAndExactScope(t *testing.T) {
	deps, _, _ := defaultDeps()
	router := testRouter(t, deps)
	body := `{"dimension":"messages_per_month","quantity":1}`
	tests := []struct {
		name   string
		claims *rs.Claims
		status int
		code   string
	}{
		{name: "no validated claims", status: http.StatusUnauthorized, code: core.ErrInvalidToken},
		{name: "user-shaped token", claims: &rs.Claims{
			Subject: "user-1", ClientID: "aero-im-machine", Scope: ScopeMeteringWrite,
		}, status: http.StatusForbidden, code: ErrorInsufficientScope},
		{name: "missing exact scope", claims: defaultClaims("metering:write-extra"),
			status: http.StatusForbidden, code: ErrorInsufficientScope},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serveRequest(router, test.claims, http.MethodPost, PathUsageAppend,
				body, jsonHeaders("auth-test"))
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
			if response.Header().Get(headerCacheControl) != cacheControlNoStore ||
				response.Header().Get(headerAuthenticate) == "" {
				t.Fatalf("security headers = %v", response.Header())
			}
		})
	}
}

func TestUnknownDisabledAndAmbiguousSourcesHaveIdenticalWireResponse(t *testing.T) {
	body := `{"dimension":"messages_per_month","quantity":1}`
	var baseline string
	for _, name := range []string{"unknown", "disabled", "ambiguous"} {
		deps, _, _ := defaultDeps()
		deps.Sources = sourceResolverStub{err: usageledger.ErrSourceBindingUnauthorized}
		response := serveRequest(testRouter(t, deps), defaultClaims(ScopeMeteringWrite),
			http.MethodPost, PathUsageAppend, body, jsonHeaders("source-test"))
		wire := response.Result().Status + "\n" + response.Header().Get(headerAuthenticate) + "\n" +
			response.Body.String()
		if response.Code != http.StatusForbidden || !strings.Contains(wire, ErrorSourceUnauthorized) {
			t.Fatalf("%s response = %s", name, wire)
		}
		if baseline == "" {
			baseline = wire
		} else if wire != baseline {
			t.Fatalf("%s response differs:\n%s\nwant:\n%s", name, wire, baseline)
		}
	}
}

func TestAppendDerivesTenantAndSourceAndRejectsBodyAuthority(t *testing.T) {
	deps, usage, _ := defaultDeps()
	router := testRouter(t, deps)
	malicious := `{"tenant_id":"tenant-other","source_system":"evil",` +
		`"dimension":"messages_per_month","quantity":1}`
	response := serveRequest(router, defaultClaims(ScopeMeteringWrite), http.MethodPost,
		PathUsageAppend, malicious, jsonHeaders("malicious"))
	if response.Code != http.StatusBadRequest || usage.appendCalls != 0 {
		t.Fatalf("malicious response/calls = %d/%d: %s", response.Code, usage.appendCalls, response.Body.String())
	}
	body := `{"id":"usage-1","dimension":"messages_per_month","quantity":2}`
	response = serveRequest(router, defaultClaims(ScopeMeteringWrite), http.MethodPost,
		PathUsageAppend, body, jsonHeaders("message-1"))
	if response.Code != http.StatusCreated || response.Header().Get(headerCacheControl) != cacheControlNoStore {
		t.Fatalf("append response = %d %s", response.Code, response.Body.String())
	}
	if usage.appendEvidence != defaultBinding().Evidence() ||
		usage.appendCommand.IdempotencyKey != "message-1" {
		t.Fatalf("derived append evidence/command = %+v %+v", usage.appendEvidence, usage.appendCommand)
	}
}

func TestAllowedDimensionsAreEnforcedBeforeUsageService(t *testing.T) {
	deps, usage, _ := defaultDeps()
	body := `{"dimension":"storage_bytes","quantity":1}`
	response := serveRequest(testRouter(t, deps), defaultClaims(ScopeMeteringWrite),
		http.MethodPost, PathUsageAppend, body, jsonHeaders("wrong-dimension"))
	if response.Code != http.StatusForbidden || usage.appendCalls != 0 ||
		!strings.Contains(response.Body.String(), ErrorDimensionNotAllowed) ||
		!strings.Contains(response.Header().Get(headerAuthenticate), ErrorInsufficientScope) {
		t.Fatalf("dimension response = %d %s %v", response.Code, response.Body.String(), response.Header())
	}
}

func TestMachineJSONIsStrictBoundedAndIdempotent(t *testing.T) {
	deps, _, _ := defaultDeps()
	router := testRouter(t, deps)
	base := `{"dimension":"messages_per_month","quantity":1`
	tests := []struct {
		name    string
		body    string
		headers map[string]string
		status  int
	}{
		{name: "unknown", body: base + `,"unknown":true}`, headers: jsonHeaders("strict"), status: 400},
		{name: "caller period", body: base + `,"period":` + periodJSON() + `}`,
			headers: jsonHeaders("strict"), status: 400},
		{name: "trailing", body: base + `} {}`, headers: jsonHeaders("strict"), status: 400},
		{name: "wrong content type", body: base + `}`, headers: map[string]string{
			headerIdempotency: "strict",
		}, status: 400},
		{name: "missing idempotency", body: base + `}`, headers: map[string]string{
			core.HeaderContentType: core.ContentTypeJSON,
		}, status: 400},
		{name: "oversized", body: base + `,"metadata":{"note":"` +
			strings.Repeat("x", maxRequestBodyBytes) + `"}}`, headers: jsonHeaders("strict"), status: 413},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serveRequest(router, defaultClaims(ScopeMeteringWrite),
				http.MethodPost, PathUsageAppend, test.body, test.headers)
			if response.Code != test.status || response.Header().Get(headerCacheControl) != cacheControlNoStore {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestStableUsageErrors(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{usageledger.ErrQuotaExceeded, http.StatusConflict, ErrorQuotaExceeded},
		{usageledger.ErrIdempotencyConflict, http.StatusConflict, ErrorIdempotencyConflict},
		{usageledger.ErrPeriodClosed, http.StatusConflict, ErrorPeriodClosed},
		{errors.New("backend detail"), http.StatusInternalServerError, core.ErrInternal},
	}
	for _, test := range tests {
		deps, usage, _ := defaultDeps()
		usage.appendError = test.err
		body := `{"dimension":"messages_per_month","quantity":1}`
		response := serveRequest(testRouter(t, deps), defaultClaims(ScopeMeteringWrite),
			http.MethodPost, PathUsageAppend, body, jsonHeaders("stable-error"))
		if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
			t.Fatalf("error %v response = %d %s", test.err, response.Code, response.Body.String())
		}
	}
}
