package ssotest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

const refStockBinaryEnv = "SSO_TEST_STOCK_BINARY"

type refStockFixture struct {
	h                                 *referenceProcesses
	binary, dsn, signingFile, keyFile string
}

type refStockStop func() error

func (stop refStockStop) Close() error { return stop() }

func refStockBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv(refStockBinaryEnv)
	if path == "" {
		t.Skip("SSO_TEST_STOCK_BINARY not set; actual stock command acceptance not executed")
	}
	if runtime.GOOS == "windows" {
		t.Skip("stock process fixture requires POSIX SIGTERM/SIGKILL evidence")
	}
	stat, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || !stat.Mode().IsRegular() || stat.Mode().Perm()&0o111 == 0 {
		t.Fatal("stock binary must be a trusted absolute regular executable")
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil || info.Path != "github.com/yangwb1123/snaplink/cmd/sso-server" {
		t.Fatal("stock binary build info does not name the real command")
	}
	race := false
	for _, setting := range info.Settings {
		if setting.Key == "-race" && setting.Value == "true" {
			race = true
		}
	}
	if !race {
		t.Fatal("stock acceptance requires a freshly built race-instrumented command")
	}
	file, err := os.Open(path)
	refProcessCheck(t, err, "open selected stock executable")
	defer file.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	refProcessCheck(t, err, "hash selected stock executable")
	t.Logf("stock command selected: sha256=%s (local file binding, not builder authentication)", hex.EncodeToString(hash.Sum(nil)))
	return path
}

func newRefStockFixture(t *testing.T) *refStockFixture {
	t.Helper()
	binary := refStockBinary(t)
	h := newReferenceProcesses(t)
	raw, err := os.ReadFile(h.configPath)
	refProcessCheck(t, err, "read private provisioned reference state")
	var cfg refProcessConfig
	refProcessCheck(t, json.Unmarshal(raw, &cfg), "decode private provisioned reference state")
	privateKey, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(cfg.SigningSeed))
	refProcessCheck(t, err, "encode pre-provisioned signing key")
	fixture := &refStockFixture{h: h, binary: binary, dsn: cfg.DSN,
		signingFile: filepath.Join(filepath.Dir(h.configPath), "signing.pem"), keyFile: filepath.Join(filepath.Dir(h.configPath), "lookup.key")}
	refProcessCheck(t, os.WriteFile(fixture.signingFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), 0o600), "write private signing key")
	refProcessCheck(t, os.WriteFile(fixture.keyFile, cfg.LookupKey, 0o600), "write private lookup key")
	h.launch = fixture.start
	return fixture
}

// JSON is valid YAML. These are real stock config keys, not SDK options; the
// stock command still parses/defaults/validates and wires every selected store.
func (fixture *refStockFixture) config(address string) map[string]any {
	return map[string]any{
		"version": 1,
		"server": map[string]any{"issuer": fixture.h.app.base, "base_url": fixture.h.app.base, "listen": address,
			"required_capabilities": []string{"core.runtime.v1", "server.stock.v1"},
			"topology":              map[string]any{"mode": "multi", "allow_per_pod_state": false},
			"session_ttl":           "1h", "token_ttl": "10m", "default_token_strategy": "jwt"},
		"postgres":       map[string]any{"dsn": fixture.dsn, "max_open_conns": 8, "max_idle_conns": 2},
		"identity":       map[string]any{"backend": "postgres", "session_backend": "postgres"},
		"tenant":         map[string]any{"enabled": true, "backend": "postgres"},
		"self_service":   map[string]any{"password": map[string]any{"backend": "postgres"}},
		"authenticators": map[string]any{"password": map[string]any{"enabled": true, "users": []any{}}},
		"oauth": map[string]any{"backend": "postgres", "postgres": map[string]any{"lookup_hmac_key_file": fixture.keyFile},
			"auth_code":     map[string]any{"enabled": true, "ttl": "1m", "reap_interval": "1m"},
			"refresh_token": map[string]any{"enabled": true, "ttl": "1h", "reap_interval": "1m", "rotation_grace_window": "0s"}},
		"oidc":        map[string]any{"browser_sso": map[string]any{"enabled": true}},
		"keys":        map[string]any{"signing": map[string]any{"alg": "eddsa", "key_file": fixture.signingFile}},
		"security":    map[string]any{"trusted_proxies": map[string]any{"cidrs": []string{"127.0.0.1/32", "::1/128"}}},
		"bootstrap":   map[string]any{"disabled": true},
		"admin":       map[string]any{"enabled": false},
		"permissions": map[string]any{"enabled": false},
		"network":     map[string]any{"enabled": false},
		"audit":       map[string]any{"enabled": false},
		"logging":     map[string]any{"level": "error"},
		"clients":     []any{},
	}
}

func refStockEnvironment() []string {
	var env []string
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "SSO_") && !strings.HasPrefix(variable, "SNAPLINK_REFERENCE_PROCESS_") {
			env = append(env, variable)
		}
	}
	return env
}

func (fixture *refStockFixture) command(t *testing.T, dir string, cfg map[string]any) *exec.Cmd {
	t.Helper()
	raw, err := json.Marshal(cfg)
	refProcessCheck(t, err, "encode private stock configuration")
	path := filepath.Join(dir, "config.yaml")
	refProcessCheck(t, os.WriteFile(path, raw, 0o600), "write private stock configuration")
	cmd := exec.Command(fixture.binary, "--config="+path, "--grpc-listen=")
	cmd.Dir, cmd.Env = dir, refStockEnvironment()
	return cmd
}

func (fixture *refStockFixture) start(t *testing.T) *refProcess {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	refProcessCheck(t, err, "reserve a stock loopback port")
	defer listener.Close()
	address := listener.Addr().String()
	dir := t.TempDir()
	p := &refProcess{done: make(chan struct{}), logPath: filepath.Join(dir, "private-stock.log"), stopWait: 20 * time.Second}
	p.cmd = fixture.command(t, dir, fixture.config(address))
	output, err := os.OpenFile(p.logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = listener.Close()
		t.Fatal("create private stock diagnostic file failed")
	}
	p.cmd.Stdout, p.cmd.Stderr = output, output
	_ = listener.Close() // Stock has no inherited-listener flag; trusted fixture only.
	err = p.cmd.Start()
	_ = output.Close()
	refProcessCheck(t, err, "launch actual stock command")
	p.stdin = refStockStop(func() error { return p.cmd.Process.Signal(syscall.SIGTERM) })
	p.ready = refProcessReady{PID: p.cmd.Process.Pid, URL: "http://" + address}
	fixture.h.children = append(fixture.h.children, p)
	go func() { p.err = p.cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.stop(t, false) })
	p.awaitStockReady(t)
	t.Logf("actual stock AS ready: parent_pid=%d child_pid=%d (PID from launched OS handle)", os.Getpid(), p.ready.PID)
	return p
}

func (p *refProcess) awaitStockReady(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-p.done:
			t.Fatal("actual stock process exited before readiness (private diagnostics withheld)")
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.ready.URL+core.PathReadyz, nil)
		refProcessCheck(t, err, "create stock readiness request")
		response, err := client.Do(req)
		if err == nil {
			_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK && readErr == nil {
				select {
				case <-p.done:
					t.Fatal("actual stock process exited during readiness")
				default:
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual stock readiness deadline/cancellation")
		case <-p.done:
			t.Fatal("actual stock process exited while becoming ready")
		case <-tick.C:
		}
	}
}

func TestE2E_StockProcessesCrossReplicaGrants(t *testing.T) {
	runReferenceProcessGrants(t, newRefStockFixture(t).h)
}

func TestE2E_StockProcessesAtomicCodeConsume(t *testing.T) {
	runReferenceProcessCodeConsume(t, newRefStockFixture(t).h)
}

func TestE2E_StockProcessesCrashRecovery(t *testing.T) {
	runReferenceProcessRecovery(t, newRefStockFixture(t).h)
}

func TestE2E_StockProcessesRejectLocalState(t *testing.T) {
	fixture := newRefStockFixture(t)
	cfg := fixture.config("127.0.0.1:0")
	cfg["identity"] = map[string]any{"backend": "memory", "session_backend": "memory"}
	template := fixture.command(t, t.TempDir(), cfg)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, template.Path, template.Args[1:]...)
	cmd.Dir, cmd.Env = template.Dir, template.Env
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil || err == nil || !strings.Contains(string(output), "multi-replica topology requires shared critical stores") ||
		!strings.Contains(string(output), "identity.backend") || !strings.Contains(string(output), "identity.session_backend") {
		t.Fatal("actual stock command did not reject process-local state for the expected multi-topology reason")
	}
	if refProcessBadDiagnostics(string(output)) {
		t.Fatal("multi-topology refusal hid a panic/race instead of a normal startup error")
	}
}
