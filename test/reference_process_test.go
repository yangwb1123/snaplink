package ssotest

import (
	"bytes"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func refProcessActive(t *testing.T, h *referenceApps, tokens refAppTokens) {
	t.Helper()
	response := h.postForm(t, core.PathIntrospect, tokens.binding, url.Values{"token": {tokens.access}})
	refAppWant(t, response, http.StatusOK, "")
	if response.body["active"] != true || response.body["client_id"] != tokens.binding.ID || response.body["sub"] != "user-"+tokens.binding.Tenant {
		t.Fatal("peer introspection lost live credential/client/subject binding")
	}
	claims := h.accessClaims(t, tokens)
	if claims.TenantID != tokens.binding.Tenant || claims.ClientID != tokens.binding.ID || claims.Raw["sid"] != tokens.session ||
		!slices.Equal(claims.Scopes(), refAppFullScopes(tokens.binding)) || claims.JTI == "" {
		t.Fatal("signed peer access token lost tenant/client/session/scope/JTI binding")
	}
}

func TestE2E_ReferenceProcessesCrossReplicaGrants(t *testing.T) {
	runReferenceProcessGrants(t, newReferenceProcesses(t))
}

func runReferenceProcessGrants(t *testing.T, h *referenceProcesses) {
	t.Helper()
	a, b := h.pair(t)
	for _, tenantID := range refTenantIDs {
		h.route(t, a)
		ordersBinding := h.app.clients["orders/"+tenantID]
		ordersGrant := h.app.begin(t, ordersBinding, false, refAppFullScopes(ordersBinding))
		h.route(t, b)
		orders := h.app.exchange(t, ordersGrant)
		reportsBinding := h.app.clients["reports/"+tenantID]
		reportsGrant := h.app.begin(t, reportsBinding, true, refAppFullScopes(reportsBinding))
		h.route(t, a)
		reports := h.app.exchange(t, reportsGrant)
		if reports.session == orders.session || reports.refresh == orders.refresh || reports.access == orders.access {
			t.Fatal("independent PostgreSQL-backed RP grants shared session/credentials")
		}
		refProcessActive(t, h.app, orders)
		h.route(t, b)
		refProcessActive(t, h.app, reports)
		rotated := h.app.refresh(t, orders)
		h.route(t, a)
		refProcessActive(t, h.app, rotated)
	}
	// A mismatched tenant/client must not redeem another RP's durable code.
	h.route(t, a)
	binding := h.app.clients["orders/tenant-a"]
	grant := h.app.begin(t, binding, false, refAppFullScopes(binding))
	h.route(t, b)
	bad := h.app.postForm(t, core.PathToken, h.app.clients["reports/tenant-b"], grant.form())
	refAppWant(t, bad, http.StatusBadRequest, core.ErrInvalidGrant)
}

func refProcessCodeRequest(t *testing.T, h *referenceProcesses, p *refProcess, grant refAppGrant) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, p.ready.URL+core.PathToken, strings.NewReader(grant.form().Encode()))
	refProcessCheck(t, err, "create process-pinned exchange request")
	origin, err := url.Parse(h.app.base)
	refProcessCheck(t, err, "parse canonical fixture origin")
	req.Host = origin.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(grant.binding.ID, grant.binding.Secret)
	return req
}

func TestE2E_ReferenceProcessesAtomicCodeConsume(t *testing.T) {
	runReferenceProcessCodeConsume(t, newReferenceProcesses(t))
}

func runReferenceProcessCodeConsume(t *testing.T, h *referenceProcesses) {
	t.Helper()
	a, b := h.pair(t)
	binding := h.app.clients["orders/tenant-a"]
	grant := h.app.begin(t, binding, false, refAppFullScopes(binding))
	requests := []*http.Request{refProcessCodeRequest(t, h, a, grant), refProcessCodeRequest(t, h, b, grant)}
	type result struct {
		response *http.Response
		err      error
	}
	start, results := make(chan struct{}), make(chan result, 2)
	for _, request := range requests {
		go func() {
			<-start
			response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
			results <- result{response, err}
		}()
	}
	close(start)
	replies := []result{<-results, <-results}
	var rejected refAppResponse
	succeeded := 0
	for _, reply := range replies {
		response := refAppRead(t, reply.response, reply.err)
		refAppNoStore(t, response)
		switch response.status {
		case http.StatusOK:
			succeeded++
			access, _ := response.body[core.KeyAccessToken].(string)
			refresh, _ := response.body[core.KeyRefreshToken].(string)
			id, _ := response.body[core.KeyIDToken].(string)
			if access == "" || refresh == "" || id == "" {
				t.Fatal("winning process-pinned exchange omitted credentials")
			}
			tokens := refAppTokens{binding: binding, session: grant.session, access: access, refresh: refresh, id: id}
			h.app.verifyID(t, tokens, grant.nonce)
			refProcessActive(t, h.app, tokens)
		case http.StatusBadRequest:
			refAppWant(t, response, http.StatusBadRequest, core.ErrInvalidGrant)
			rejected = response
		default:
			t.Fatalf("unexpected competing exchange status=%d", response.status)
		}
	}
	if succeeded != 1 || rejected.body == nil {
		t.Fatal("two independent processes did not enforce single-use code consume")
	}
	consumed := h.app.postForm(t, core.PathToken, binding, grant.form())
	refAppWant(t, consumed, http.StatusBadRequest, core.ErrInvalidGrant)
	unknownForm := grant.form()
	unknownForm.Set("code", refAppRandom(t))
	h.route(t, b)
	unknown := h.app.postForm(t, core.PathToken, binding, unknownForm)
	refAppWant(t, unknown, http.StatusBadRequest, core.ErrInvalidGrant)
	if !bytes.Equal(rejected.raw, consumed.raw) || !bytes.Equal(consumed.raw, unknown.raw) {
		t.Fatal("unknown/consumed cross-process code failures distinguish hidden causes")
	}
}

func refProcessInvalidRefresh(t *testing.T, h *referenceApps, tokens refAppTokens) {
	t.Helper()
	response := h.postForm(t, core.PathToken, tokens.binding, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.refresh}})
	refAppWant(t, response, http.StatusBadRequest, core.ErrInvalidGrant)
}

func TestE2E_ReferenceProcessesCrashRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("crash evidence requires POSIX SIGKILL status; Windows crash acceptance is not claimed")
	}
	runReferenceProcessRecovery(t, newReferenceProcesses(t))
}

func runReferenceProcessRecovery(t *testing.T, h *referenceProcesses) {
	t.Helper()
	a, b := h.pair(t)
	orders := h.app.login(t, "orders", "tenant-a", false)
	reportsBinding := h.app.clients["reports/tenant-a"]
	outstanding := h.app.begin(t, reportsBinding, true, refAppFullScopes(reportsBinding))
	a.stop(t, true)
	h.route(t, b)
	reports := h.app.exchange(t, outstanding)
	rotated := h.app.refresh(t, orders)
	refProcessActive(t, h.app, rotated)

	restarted := h.start(t)
	if restarted.ready.PID == b.ready.PID {
		t.Fatal("restarted replica is not an independent process")
	}
	h.route(t, restarted)
	refProcessActive(t, h.app, reports)
	consumed := h.app.postForm(t, core.PathToken, outstanding.binding, outstanding.form())
	refAppWant(t, consumed, http.StatusBadRequest, core.ErrInvalidGrant)
	refProcessInvalidRefresh(t, h.app, orders) // Restarted issuer sees persisted reuse evidence.
	h.route(t, b)
	refProcessInvalidRefresh(t, h.app, rotated) // Family kill reaches the surviving peer's leaf.
	refProcessActive(t, h.app, reports)

	h.route(t, restarted)
	independent := h.app.login(t, "orders", "tenant-b", false)
	refProcessActive(t, h.app, independent) // New signer uses the pre-provisioned key.
	h.route(t, b)
	logout := h.app.postJSON(t, "tenant-a", core.PathLogout, map[string]any{"session_id": reports.session}, reports.access)
	refAppWant(t, logout, http.StatusOK, "")
	h.route(t, restarted)
	refProcessInvalidRefresh(t, h.app, reports) // Shared-session liveness, not JWT deny-set propagation.
	refProcessActive(t, h.app, h.app.refresh(t, independent))
}
