package ssotest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
)

type refProcess struct {
	cmd      *exec.Cmd
	stdin    io.Closer
	done     chan struct{}
	err      error
	ready    refProcessReady
	logPath  string
	reaped   bool
	stopWait time.Duration
}

type referenceProcesses struct {
	app        *referenceApps
	configPath string
	target     atomic.Pointer[httputil.ReverseProxy]
	children   []*refProcess
	launch     func(*testing.T) *refProcess
	// Optional additional owner proof; it can never override child Waits.
	schemaTeardownSafe func() bool
}

func (h *referenceProcesses) canDropSchema() bool {
	return h.allReaped() && (h.schemaTeardownSafe == nil || h.schemaTeardownSafe())
}

func (h *referenceProcesses) allReaped() bool {
	for _, child := range h.children {
		select {
		case <-child.done:
		default:
			return false
		}
	}
	return true
}

// Unlike an unconditional schema cleanup, an unreaped child must never race
// DROP. On an unkillable host failure, fail and retain this isolated schema.
func (h *referenceProcesses) schema(t *testing.T) string {
	t.Helper()
	base := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if base == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set; real PostgreSQL process acceptance not executed")
	}
	db, err := postgres.Open(postgres.Config{DSN: base, MaxOpenConns: 1, MaxIdleConns: 1})
	refProcessCheck(t, err, "open reference schema owner")
	t.Cleanup(func() { _ = db.Close() })
	var nonce [16]byte
	_, err = rand.Read(nonce[:])
	refProcessCheck(t, err, "generate private schema identifier")
	name := "refprocess_" + hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	_, err = db.ExecContext(ctx, "CREATE SCHEMA "+name)
	cancel()
	refProcessCheck(t, err, "create private reference schema")
	t.Cleanup(func() {
		if !h.canDropSchema() {
			t.Error("unreaped reference child or unfinished teardown owner: retaining isolated schema instead of DROP")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := db.ExecContext(ctx, "DROP SCHEMA "+name+" CASCADE")
		if err != nil {
			t.Error("drop isolated reference schema failed (backend diagnostics omitted)")
		}
	})
	separator := "?"
	if strings.Contains(base, "?") {
		separator = "&"
	}
	return base + separator + "search_path=" + name
}

func newReferenceProcesses(t *testing.T) *referenceProcesses {
	t.Helper()
	h := &referenceProcesses{}
	dsn := h.schema(t)
	stores := newRefProcessStores(t, dsn)
	h.app = &referenceApps{clients: stores.seed(t), browsers: map[string]*http.Client{}}
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if proxy := h.target.Load(); proxy != nil {
			proxy.ServeHTTP(w, r)
			return
		}
		refAppJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "reference_backend_unavailable"})
	}))
	t.Cleanup(gateway.Close)
	h.app.base = gateway.URL
	cfg := refProcessConfig{DSN: dsn, Issuer: gateway.URL, SigningSeed: make([]byte, 32), LookupKey: make([]byte, 32)}
	_, err := rand.Read(cfg.SigningSeed)
	refProcessCheck(t, err, "generate reference signing seed")
	_, err = rand.Read(cfg.LookupKey)
	refProcessCheck(t, err, "generate independent lookup key")
	raw, err := json.Marshal(cfg)
	refProcessCheck(t, err, "encode private process configuration")
	h.configPath = filepath.Join(t.TempDir(), "private-config.json")
	refProcessCheck(t, os.WriteFile(h.configPath, raw, 0o600), "write private process configuration")
	for _, tenantID := range refTenantIDs {
		jar, err := cookiejar.New(nil)
		refProcessCheck(t, err, "create reference browser jar")
		h.app.browsers[tenantID] = &http.Client{Jar: jar, Timeout: 5 * time.Second}
	}
	h.app.cache = rs.NewJWKSCache(gateway.URL+core.PathJWKS, remote.WithJWKSHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	t.Cleanup(h.app.cache.Close)
	return h
}

func (h *referenceProcesses) start(t *testing.T) *refProcess {
	t.Helper()
	if h.launch != nil {
		return h.launch(t)
	}
	bin, err := os.Executable()
	refProcessCheck(t, err, "find instrumented reference test executable")
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready.json")
	p := &refProcess{done: make(chan struct{}), logPath: filepath.Join(dir, "private-child.log")}
	p.cmd = exec.Command(bin, "-test.run=^TestReferenceProcessChild$", "-test.timeout=90s", "-test.v")
	p.cmd.Env = append(os.Environ(), refProcessConfigEnv+"="+h.configPath, refProcessReadyEnv+"="+readyPath)
	p.stdin, err = p.cmd.StdinPipe()
	refProcessCheck(t, err, "create child lifetime pipe")
	output, err := os.OpenFile(p.logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = p.stdin.Close()
		t.Fatal("create private child diagnostic file failed")
	}
	p.cmd.Stdout, p.cmd.Stderr = output, output
	err = p.cmd.Start()
	_ = output.Close()
	if err != nil {
		_ = p.stdin.Close()
		t.Fatal("launch reference process failed")
	}
	h.children = append(h.children, p)
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.stop(t, false) })
	p.awaitReady(t, readyPath)
	t.Logf("independent reference AS ready: parent_pid=%d child_pid=%d", os.Getpid(), p.ready.PID)
	return p
}

func (p *refProcess) awaitReady(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		raw, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(raw, &p.ready) == nil {
			u, err := url.Parse(p.ready.URL)
			if err != nil || u.Scheme != "http" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() ||
				u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
				p.ready.PID != p.cmd.Process.Pid || p.ready.PID == os.Getpid() {
				t.Fatal("reference process readiness is not bound to its loopback child")
			}
			return
		}
		select {
		case <-p.done:
			t.Fatal("reference child exited before readiness (private diagnostics withheld)")
		case <-ctx.Done():
			t.Fatal("reference child readiness deadline/cancellation")
		case <-tick.C:
		}
	}
}

func refProcessWasKilled(killErr error, state *os.ProcessState) bool {
	if killErr != nil || state == nil {
		return false
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

func refProcessBadDiagnostics(output string) bool {
	return strings.Contains(output, "WARNING: DATA RACE") || strings.Contains(output, "panic:") || strings.Contains(output, "--- FAIL:")
}

func (p *refProcess) stop(t *testing.T, crash bool) {
	t.Helper()
	if p.reaped {
		return
	}
	select {
	case <-p.done:
		t.Error("reference child exited before its requested stop")
	default:
	}
	var killErr error
	if crash {
		killErr = p.cmd.Process.Kill()
	}
	if err := p.stdin.Close(); err != nil && !crash {
		t.Error("reference process graceful-stop request failed")
	}
	p.reaped = p.reap(t)
	if !p.reaped {
		return // Later cleanup may retry; the schema guard refuses DROP meanwhile.
	}
	if (!crash && p.err != nil) || (crash && !refProcessWasKilled(killErr, p.cmd.ProcessState)) {
		t.Error("reference child exit did not match EOF stop or explicit SIGKILL")
	}
	output, err := os.ReadFile(p.logPath)
	if err != nil || refProcessBadDiagnostics(string(output)) {
		t.Error("reference child diagnostics missing or contain a failure/panic/race")
	}
}

func (p *refProcess) reap(t *testing.T) bool {
	t.Helper()
	wait := p.stopWait
	if wait <= 0 {
		wait = 10 * time.Second
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-p.done:
		return true
	case <-timer.C:
		t.Error("reference process exceeded shutdown deadline")
	}
	if err := p.cmd.Process.Kill(); err != nil {
		t.Error("reference forced-cleanup kill failed")
	}
	timer.Reset(5 * time.Second)
	select {
	case <-p.done:
		return true
	case <-timer.C:
		t.Error("reference child not reaped; schema teardown must be refused")
		return false
	}
}

// Routing is controlled only by the test, never a browser header or token claim.
func (h *referenceProcesses) route(t *testing.T, p *refProcess) {
	t.Helper()
	if p.reaped {
		t.Fatal("cannot route acceptance traffic to a stopped reference process")
	}
	u, err := url.Parse(p.ready.URL)
	refProcessCheck(t, err, "parse reference process route")
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		refAppJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "reference_backend_unavailable"})
	}
	h.target.Store(proxy)
}

func (h *referenceProcesses) pair(t *testing.T) (*refProcess, *refProcess) {
	t.Helper()
	a, b := h.start(t), h.start(t)
	if a.ready.PID == b.ready.PID {
		t.Fatal("reference replicas share an OS process")
	}
	h.route(t, a)
	return a, b
}
