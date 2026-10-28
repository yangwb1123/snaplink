package ssotest

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func refOutageProbe(t *testing.T, ctx context.Context, p *refProcess, path string, ready bool) {
	t.Helper()
	select {
	case <-p.done:
		t.Fatal("stock process exited instead of reporting dependency health")
	default:
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.ready.URL+path, nil)
	refProcessCheck(t, err, "create pinned health request")
	response, err := (&http.Client{Timeout: 500 * time.Millisecond}).Do(req)
	out := refAppRead(t, response, err)
	if path == core.PathLivez {
		if out.status != http.StatusOK || out.body["status"] != "alive" || len(out.body) != 1 {
			t.Fatal("stock liveness changed during PostgreSQL path outage")
		}
	} else {
		wantStatus, wantState, wantPG := http.StatusServiceUnavailable, "unready", "check failed"
		if ready {
			wantStatus, wantState, wantPG = http.StatusOK, "ready", "ok"
		}
		checks, ok := out.body["checks"].(map[string]any)
		if !ok || out.status != wantStatus || out.body["status"] != wantState || checks["postgres"] != wantPG {
			names := make([]string, 0, len(checks))
			for name := range checks {
				names = append(names, name)
			}
			slices.Sort(names)
			_, hasPG := checks["postgres"]
			t.Fatalf("stock readiness contract mismatch: HTTP=%d expected=%d state_matches=%t postgres_present=%t check_names=%q (values withheld)", out.status, wantStatus, out.body["status"] == wantState, hasPG, names)
		}
		for _, value := range checks {
			if value != "ok" && value != "check failed" {
				t.Fatal("readiness exposed unsanitized dependency details")
			}
		}
	}
	t.Logf("pinned health: pid=%d path=%s HTTP=%d", p.ready.PID, path, out.status)
}

func refOutageRejected(t *testing.T, ctx context.Context, h *referenceProcesses, p *refProcess, binding refAppClient, form url.Values) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.ready.URL+core.PathToken, strings.NewReader(form.Encode()))
	refProcessCheck(t, err, "create pinned outage credential request")
	origin, err := url.Parse(h.app.base)
	refProcessCheck(t, err, "parse canonical outage origin")
	req.Host = origin.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(binding.ID, binding.Secret)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req) // No credential retry.
	out := refAppRead(t, response, err)
	refAppNoStore(t, out)
	if out.status != http.StatusUnauthorized || out.body["error"] != core.ErrInvalidClient {
		t.Fatal("fully cut PG path did not refuse at the existing client-auth boundary")
	}
	for key, value := range out.body {
		if key == "error" {
			continue
		}
		trace, ok := value.(string)
		if key != "trace_id" || !ok || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(trace) || trace == strings.Repeat("0", 32) {
			t.Fatal("outage error exposed credentials/backend detail or an invalid trace envelope")
		}
	}
	t.Logf("pinned credential refusal: pid=%d grant=%s HTTP=401 invalid_client; no-store; no credentials", p.ready.PID, form.Get("grant_type"))
}

func refOutageSession(t *testing.T, state refOutageState, sid string, binding refAppClient) {
	t.Helper()
	row := state.row(t, "sessions", "id", sid)
	if refOutageText(t, row, "user_id") != "user-"+binding.Tenant || refOutageText(t, row, "client_id") != binding.ID ||
		refOutageText(t, row, "tenant_id") != binding.Tenant || refOutageInt(t, row, "revoked") != 0 ||
		refOutageInt(t, row, "expires_at") <= time.Now().UnixNano() || refOutageInt(t, row, "auth_time") <= 0 {
		t.Fatal("protected session lacks the expected live subject/client/tenant/authentication binding")
	}
}

func refOutageSigned(t *testing.T, h *referenceApps, tokens refAppTokens) {
	t.Helper()
	refProcessActive(t, h, tokens)
	claims := h.accessClaims(t, tokens)
	if !slices.Equal(claims.Audience, []string{tokens.binding.Audience}) || claims.Raw["aud"] != tokens.binding.Audience ||
		claims.Subject != "user-"+tokens.binding.Tenant {
		t.Fatal("recovered signed token lost its original subject/resource audience")
	}
}

func TestE2E_StockProcessesPostgresOutageRecovery(t *testing.T) {
	fixture := newRefStockFixture(t)
	directDSN := fixture.dsn
	// Validate before opening the observer or starting any stock process.
	_, err := refOutageDSN(directDSN, "127.0.0.1:1")
	refProcessCheck(t, err, "validate direct loopback PostgreSQL target")
	observer := refOutageObserver(t, directDSN)
	u, err := url.Parse(directDSN)
	refProcessCheck(t, err, "parse validated direct target")
	gate := newRefOutageGate(t, u.Host, nil)
	fixture.h.schemaTeardownSafe = gate.teardownSafe
	fixture.dsn, err = refOutageDSN(directDSN, gate.listener.Addr().String())
	refProcessCheck(t, err, "bind both stock configurations to TCP gate")
	h := fixture.h
	a, b := h.pair(t)
	pids := [2]int{a.ready.PID, b.ready.PID}
	if pids[0] == pids[1] || pids[0] == os.Getpid() || pids[1] == os.Getpid() {
		t.Fatal("outage fixture does not have two independent stock OS children")
	}
	h.route(t, a)
	original := h.app.login(t, "orders", "tenant-a", false)
	h.route(t, b)
	independent := h.app.login(t, "orders", "tenant-b", false)
	refOutageSigned(t, h.app, independent)
	h.route(t, a)
	refOutageSigned(t, h.app, original)
	for _, process := range []*refProcess{a, b} {
		refOutageProbe(t, t.Context(), process, core.PathReadyz, true)
	}
	_, _, attached, _ := gate.counts()
	if attached < 2 {
		t.Fatal("healthy stock processes did not actually connect through the gate")
	}

	pendingStart := time.Now()
	binding := h.app.clients["reports/tenant-a"]
	pending := h.app.begin(t, binding, false, refAppFullScopes(binding))
	faultCtx, cancel := context.WithDeadline(t.Context(), pendingStart.Add(15*time.Second))
	defer cancel()
	before := refOutageSnapshot(t, faultCtx, observer)
	codeKey := refOutageLookup(t, fixture, "auth_code", pending.code)
	refreshKey := refOutageLookup(t, fixture, "refresh_token", original.refresh)
	otherKey := refOutageLookup(t, fixture, "refresh_token", independent.refresh)
	codeRow := before.row(t, "codes", "code", codeKey)
	refreshRow := before.row(t, "refresh", "token", refreshKey)
	family := refOutageText(t, refreshRow, "family_id")
	if refOutageText(t, codeRow, "client_id") != binding.ID || refOutageText(t, codeRow, "sid") != pending.session ||
		refOutageText(t, refreshRow, "client_id") != original.binding.ID || refOutageText(t, refreshRow, "sid") != original.session ||
		family == "" || refOutageInt(t, refreshRow, "generation") != 0 ||
		refOutageText(t, before.row(t, "families", "token", refreshKey), "family_id") != family {
		t.Fatal("pending code/refresh/ledger identities are not bound to the original grants")
	}
	for _, tokens := range []refAppTokens{original, independent, {binding: binding, session: pending.session}} {
		refOutageSession(t, before, tokens.session, tokens.binding)
	}
	otherRow := before.row(t, "refresh", "token", otherKey)
	if refOutageText(t, otherRow, "family_id") == family {
		t.Fatal("two tenants unexpectedly share a refresh family")
	}

	refProcessCheck(t, gate.Cut(faultCtx), "cut and join all original PostgreSQL TCP paths")
	started, finished, _, active := gate.counts()
	if active != 0 || started != finished {
		t.Fatal("outage began without complete forwarding/dial drain")
	}
	t.Logf("fault cut completed: started=%d finished=%d active=0; no AS restart or DB stop", started, finished)
	refProcessCheck(t, observer.PingContext(faultCtx), "direct PG health while stock path is cut")
	for _, process := range []*refProcess{a, b} {
		refOutageProbe(t, faultCtx, process, core.PathReadyz, false)
		refOutageProbe(t, faultCtx, process, core.PathLivez, false)
		refOutageRejected(t, faultCtx, h, process, binding, pending.form())
		refOutageRejected(t, faultCtx, h, process, original.binding, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {original.refresh}})
	}
	refOutageSame(t, before, refOutageSnapshot(t, faultCtx, observer))
	if faultCtx.Err() != nil || time.Since(pendingStart) >= 15*time.Second {
		t.Fatal("pending-code outage phase exceeded its original aggregate budget")
	}
	expires := time.Unix(0, refOutageInt(t, codeRow, "expires_at"))
	if time.Until(expires) < 35*time.Second {
		t.Fatal("original pending code lacks the unchanged readiness window and safety reserve")
	}
	cancel()
	refProcessCheck(t, gate.Restore(), "restore identical PostgreSQL TCP endpoint")
	a.awaitStockReady(t)
	b.awaitStockReady(t)
	if a.cmd.Process.Pid != pids[0] || b.cmd.Process.Pid != pids[1] || len(h.children) != 2 {
		t.Fatal("recovery replaced or restarted stock processes")
	}
	for _, process := range []*refProcess{a, b} {
		refOutageProbe(t, t.Context(), process, core.PathReadyz, true)
	}
	if !time.Now().Before(expires) {
		t.Fatal("original pending code expired before recovery exchange")
	}
	h.route(t, b)
	recovered := h.app.exchange(t, pending) // Verifies original signature, nonce, SID and at_hash.
	refOutageSigned(t, h.app, recovered)
	h.route(t, a)
	consumed := h.app.postForm(t, core.PathToken, binding, pending.form())
	refAppWant(t, consumed, http.StatusBadRequest, core.ErrInvalidGrant)
	unknownForm := pending.form()
	unknownForm.Set("code", refAppRandom(t))
	h.route(t, b)
	unknown := h.app.postForm(t, core.PathToken, binding, unknownForm)
	refAppWant(t, unknown, http.StatusBadRequest, core.ErrInvalidGrant)
	if !bytes.Equal(consumed.raw, unknown.raw) {
		t.Fatal("recovered consumed/unknown code errors distinguish hidden causes")
	}
	rotated := h.app.refresh(t, original)
	refOutageSigned(t, h.app, rotated)
	recoveryCtx, recoveryCancel := context.WithTimeout(t.Context(), 5*time.Second)
	after := refOutageSnapshot(t, recoveryCtx, observer)
	recoveryCancel()
	successorKey := refOutageLookup(t, fixture, "refresh_token", rotated.refresh)
	successor := after.row(t, "refresh", "token", successorKey)
	refOutageBindingsEqual(t, refreshRow, successor)
	if refOutageText(t, after.row(t, "families", "token", successorKey), "family_id") != family {
		t.Fatal("recovered rotation lost successor reuse-ledger binding")
	}
	h.route(t, a)
	refProcessInvalidRefresh(t, h.app, original)
	h.route(t, b)
	refProcessInvalidRefresh(t, h.app, rotated)
	killedCtx, killedCancel := context.WithTimeout(t.Context(), 5*time.Second)
	killed := refOutageSnapshot(t, killedCtx, observer)
	killedCancel()
	for _, table := range []string{"refresh", "families"} {
		for _, row := range killed[table] {
			if refOutageText(t, row, "family_id") == family {
				t.Fatal("peer reuse did not delete the complete recovered family")
			}
		}
	}
	if !reflect.DeepEqual(otherRow, killed.row(t, "refresh", "token", otherKey)) ||
		!reflect.DeepEqual(before.row(t, "families", "token", otherKey), killed.row(t, "families", "token", otherKey)) {
		t.Fatal("recovered family reuse changed the other tenant's independent state")
	}
	refOutageSigned(t, h.app, h.app.refresh(t, independent))
	a.stop(t, false)
	b.stop(t, false)
	refProcessCheck(t, gate.Close(), "join gate after both stock Waits")
	refProcessCheck(t, observer.Close(), "close direct observer before schema DROP")
	if !h.canDropSchema() {
		t.Fatal("stock Wait/proxy join proof missing; schema must be retained")
	}
	t.Logf("recovery verified on original PIDs %d/%d; code single-use, refresh lineage/reuse and tenant isolation; both Waits and gate join complete", pids[0], pids[1])
}
