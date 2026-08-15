package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/auditexport"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	pgbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	libexport "github.com/yangwb1123/snaplink/platform/audit/auditexport"
)

const (
	exportTokenClient = "export-tok-client"
	exportTokenSecret = "export-tok-secret"
	exportAdminToken  = "export-good-bearer"
)

// exportServerOptions returns the stock-shaped server options: a recorder
// over the given sink (hash-chained) plus an issuer + client store so the
// /token endpoint can issue a real token, and the audit API mounted.
func exportServerOptions(sink audit.Sink) []sso.Option {
	rec := audit.New(sink, audit.WithHashChain())
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("audit-export-e2e"),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    exportTokenClient,
		Secret:                exportTokenSecret,
		Name:                  "Audit Export E2E",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	return []sso.Option{
		sso.WithAuditRecorder(rec),
		sso.WithAuditAPI(),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithClientStore(clients),
	}
}

// issueExportToken performs a client-credentials POST /token against srv
// and fails the test if no token is minted (the request must emit a
// token_issued audit event into the chained sink).
func issueExportToken(t *testing.T, srv *httptest.Server) {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     exportTokenClient,
		"client_secret": exportTokenSecret,
	})
	resp, err := http.Post(srv.URL+"/token", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || out["access_token"] == nil {
		t.Fatalf("token issuance failed: status=%d body=%s", resp.StatusCode, body)
	}
}

// adminProtectedMW builds the admin middleware (the same Bearer +
// admin:read gate cmd/sso-server applies), so the audit query API answers
// 401 without a bearer and 200 with a valid one.
func adminProtectedMW(t *testing.T) *sso.AdminMiddleware {
	t.Helper()
	prov := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, "user-alice", "", []string{"root"})
	return sso.NewAdminMiddleware(stubValidator{good: exportAdminToken, claims: &sso.TokenClaims{Subject: "user-alice"}}, prov)
}

// TestAuditExport_PostgresLeg (REQ-4 acceptance A1-A3): a stock-shaped
// server with a hash-chained POSTGRES audit sink issues a token; the
// exported bundle's HeadHash equals the store chain head; --verify exits
// 0; byte-tampering one event's hash makes --verify exit 1 with the
// "bundle FAILED verification" diagnostic. Gated on SSO_TEST_POSTGRES_DSN
// (repo convention); without it the leg is reported skipped.
func TestAuditExport_PostgresLeg(t *testing.T) {
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set — skipping postgres export e2e (A1-A3)")
	}

	sink, err := pgbackend.NewAuditSink(pgbackend.Config{DSN: dsn}) // writable: test setup migrates
	if err != nil {
		t.Fatalf("NewAuditSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	if _, err := sink.DB().ExecContext(context.Background(), "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit_events: %v", err)
	}

	srv := sso.NewServer(exportServerOptions(sink)...)
	httpSrv := httptest.NewServer(adminProtectedMW(t).HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	issueExportToken(t, httpSrv)

	// A1: export over the postgres pager.
	dir := t.TempDir()
	out := filepath.Join(dir, "evidence.json")
	if code := auditexport.Run([]string{"--dsn", dsn, "--out", out}); code != 0 {
		t.Fatalf("audit-export --dsn postgres exit=%d, want 0", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if b.EventCount == 0 {
		t.Fatal("exported bundle is empty — token issuance must have recorded events")
	}
	// A2: HeadHash equals the postgres chain head.
	head, err := sink.LastHash(context.Background())
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if b.HeadHash != head {
		t.Errorf("bundle HeadHash=%q, store chain head=%q", b.HeadHash, head)
	}
	// A3a: --verify exits 0.
	if code := auditexport.Run([]string{"--verify", out}); code != 0 {
		t.Fatalf("audit-export --verify exit=%d, want 0", code)
	}
	// A3b: byte-tamper one event's hash → --verify exits 1.
	tampered := tamperBundleHash(t, raw)
	tamperedPath := filepath.Join(dir, "tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	stderr := captureTestStderr(t, func() { code = auditexport.Run([]string{"--verify", tamperedPath}) })
	if code != 1 {
		t.Fatalf("--verify over tampered bundle exit=%d, want 1", code)
	}
	if !strings.Contains(stderr, "bundle FAILED verification") {
		t.Errorf("stderr missing tamper diagnostic:\n%s", stderr)
	}
}

// TestAuditExport_FromURL (REQ-4 acceptance B1-B2): the advertised
// /api/v1/audit/events endpoint never 404s on an audit+admin-enabled
// server; no/weak bearer → 401 (server), and the CLI enforces
// --from-url requires --bearer with exit 2. The export over the real HTTP
// wire yields a bundle that verifies.
func TestAuditExport_FromURL(t *testing.T) {
	sink := audit.NewMemorySink(100)
	srv := sso.NewServer(exportServerOptions(sink)...)
	httpSrv := httptest.NewServer(adminProtectedMW(t).HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)
	// 200 with a valid admin:read bearer, 401 for a garbage bearer.
	advertised := "/api/v1/audit/events"
	for _, tc := range []struct {
		name   string
		bearer string
		want   int
	}{
		{"no-bearer", "", http.StatusUnauthorized},
		{"weak-bearer", "garbage-token", http.StatusUnauthorized},
		{"valid-bearer", exportAdminToken, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, httpSrv.URL+advertised, nil)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", advertised, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusNotFound {
				t.Fatalf("advertised endpoint %s must never 404 (T-2 sweep invariant)", advertised)
			}
			if resp.StatusCode != tc.want {
				t.Errorf("GET %s with bearer=%q status=%d, want %d", advertised, tc.bearer, resp.StatusCode, tc.want)
			}
		})
	}

	// B2 CLI: --from-url without --bearer is exit-2 misuse.
	if code := auditexport.Run([]string{"--from-url", httpSrv.URL}); code != 2 {
		t.Errorf("--from-url without --bearer exit=%d, want 2", code)
	}

	// The full --from-url export over the real HTTP wire verifies offline.
	issueExportToken(t, httpSrv)
	dir := t.TempDir()
	out := filepath.Join(dir, "url.json")
	if code := auditexport.Run([]string{"--from-url", httpSrv.URL, "--bearer", exportAdminToken, "--out", out}); code != 0 {
		t.Fatalf("audit-export --from-url exit=%d, want 0", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.EventCount == 0 {
		t.Fatal("URL export empty — expected the token_issued events")
	}
	if code := auditexport.Run([]string{"--verify", out}); code != 0 {
		t.Fatalf("--verify of URL export exit=%d, want 0", code)
	}
	// The URL-exported rows equal the sink's rows in chain order.
	rows, _ := sink.Query(context.Background(), audit.Query{Limit: 1000})
	if len(rows) != b.EventCount {
		t.Errorf("sink rows=%d, bundle EventCount=%d", len(rows), b.EventCount)
	}
}

// tamperBundleHash flips the persisted hash of the FIRST event in a
// serialized bundle, leaving every other field (including head_hash)
// untouched, so --verify fails the chain check rather than a format check.
func tamperBundleHash(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b libexport.ExportBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal for tamper: %v", err)
	}
	if len(b.Events) == 0 {
		t.Fatal("cannot tamper an empty bundle")
	}
	b.Events[0].Hash = strings.Repeat("0", len(b.Events[0].Hash))
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	return out
}

// captureTestStderr redirects os.Stderr while fn runs and returns the
// captured bytes as a string.
func captureTestStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string)
	go func() {
		var b strings.Builder
		buf := make([]byte, 1024)
		for {
			n, e := r.Read(buf)
			b.Write(buf[:n])
			if e != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	out := <-done
	os.Stderr = orig
	return out
}
