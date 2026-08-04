package commercehttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWalletAdjustmentAndReadModels(t *testing.T) {
	environment := newTestEnvironment(t)
	path := "/api/v1/admin/commerce/tenants/tenant-1/wallet/adjustments"
	response := serveJSON(t, environment.router, http.MethodPost, path, map[string]any{
		"tenant_id": "tenant-1", "currency": "USD", "amount_minor": 5000,
		"idempotency_key": "manual:ticket-1", "reference": "ticket-1",
	})
	assertWalletBalance(t, response, http.StatusCreated, 5000)
	response = serveJSON(t, environment.router, http.MethodPost, path, map[string]any{
		"tenant_id": "tenant-1", "currency": "USD", "amount_minor": -1250,
		"idempotency_key": "manual:ticket-2", "reference": "ticket-2",
	})
	assertWalletBalance(t, response, http.StatusCreated, 3750)

	path = "/api/v1/admin/commerce/tenants/tenant-1/wallet?currency=USD"
	response = serveJSON(t, environment.router, http.MethodGet, path, nil)
	assertWalletBalance(t, response, http.StatusOK, 3750)
	path = "/api/v1/admin/commerce/tenants/tenant-1/wallet/entries?currency=USD&limit=10"
	response = serveJSON(t, environment.router, http.MethodGet, path, nil)
	var ledger struct {
		Entries []map[string]any `json:"entries"`
		Total   int              `json:"total"`
	}
	decodeResponse(t, response, &ledger)
	if response.Code != http.StatusOK || ledger.Total != 2 || len(ledger.Entries) != 2 {
		t.Fatalf("ledger = %+v, status=%d", ledger, response.Code)
	}
}

func TestWalletAdjustmentUsesIdempotencyHeader(t *testing.T) {
	environment := newTestEnvironment(t)
	body := `{"tenant_id":"tenant-1","currency":"USD","amount_minor":500,"reference":"ticket-1"}`
	path := "/api/v1/admin/commerce/tenants/tenant-1/wallet/adjustments"
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(headerIdempotency, "manual:ticket-1")
	response := httptest.NewRecorder()
	environment.router.ServeHTTP(response, request)
	assertWalletBalance(t, response, http.StatusCreated, 500)
}

func TestWalletAdjustmentRejectsMismatchAndOverdraft(t *testing.T) {
	environment := newTestEnvironment(t)
	path := "/api/v1/admin/commerce/tenants/tenant-1/wallet/adjustments"
	mismatch := map[string]any{
		"tenant_id": "tenant-2", "currency": "USD", "amount_minor": 100,
		"idempotency_key": "manual:1", "reference": "ticket-1",
	}
	response := serveJSON(t, environment.router, http.MethodPost, path, mismatch)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("mismatch status = %d, body=%s", response.Code, response.Body.String())
	}
	overdraft := map[string]any{
		"tenant_id": "tenant-1", "currency": "USD", "amount_minor": -100,
		"idempotency_key": "manual:2", "reference": "ticket-2",
	}
	response = serveJSON(t, environment.router, http.MethodPost, path, overdraft)
	var body map[string]string
	decodeResponse(t, response, &body)
	if response.Code != http.StatusConflict || body["error"] != ErrorInsufficientFunds {
		t.Fatalf("overdraft status=%d body=%v", response.Code, body)
	}
}

func TestLedgerLimitIsBounded(t *testing.T) {
	environment := newTestEnvironment(t)
	path := "/api/v1/admin/commerce/tenants/tenant-1/wallet/entries?currency=USD&limit=1001"
	response := serveJSON(t, environment.router, http.MethodGet, path, nil)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("limit status = %d, body=%s", response.Code, response.Body.String())
	}
}

func assertWalletBalance(t *testing.T, response *httptest.ResponseRecorder, status int, balance int64) {
	t.Helper()
	var body struct {
		Wallet struct {
			BalanceMinor int64 `json:"balance_minor"`
		} `json:"wallet"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != status || body.Wallet.BalanceMinor != balance {
		t.Fatalf("wallet balance = %d, status=%d body=%s", body.Wallet.BalanceMinor, response.Code, response.Body.String())
	}
}
