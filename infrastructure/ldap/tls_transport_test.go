package ldapauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Record operation names only, never credentials. The memory directory still
// performs the binds/searches; the wrapper observes the existing connection seam.
type tlsRecordingConn struct {
	conn
	mu        sync.Mutex
	events    []string
	tlsConfig *tls.Config
}

func newTLSRecordingConn(dir *fakeDirectory) *tlsRecordingConn {
	return &tlsRecordingConn{conn: &fakeConn{dir: dir}}
}

func (c *tlsRecordingConn) record(event string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
}

func (c *tlsRecordingConn) StartTLS(cfg *tls.Config) error {
	c.mu.Lock()
	c.tlsConfig = cfg
	c.events = append(c.events, "starttls")
	c.mu.Unlock()
	if err := c.conn.StartTLS(cfg); err != nil {
		c.record("tls-failed")
		return err
	}
	c.record("tls-ready")
	return nil
}

func (c *tlsRecordingConn) Bind(dn, password string) error {
	c.record("bind")
	return c.conn.Bind(dn, password)
}

func (c *tlsRecordingConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	c.record("search")
	return c.conn.Search(req)
}

func (c *tlsRecordingConn) Close() error {
	c.record("close")
	return c.conn.Close()
}

type tlsRecordingDialer struct {
	connections []*tlsRecordingConn
	dialed      []string
	tlsConfigs  []*tls.Config
}

func (d *tlsRecordingDialer) Dial(rawURL string, _ time.Duration, cfg *tls.Config) (conn, error) {
	index := len(d.dialed)
	d.dialed = append(d.dialed, rawURL)
	d.tlsConfigs = append(d.tlsConfigs, cfg)
	if index >= len(d.connections) {
		return nil, errors.New("unexpected dial")
	}
	c := d.connections[index]
	c.record("dial")
	return c, nil
}

func tlsRecordingConfig(dir *fakeDirectory) Config {
	cfg := baseValidCfg()
	cfg.BindDN = dir.serviceDN
	cfg.BindPassword = dir.servicePassword
	cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "dir.example.com"}
	return cfg
}

func newTLSRecordingAuth(t *testing.T, cfg Config, connections ...*tlsRecordingConn) (*Authenticator, *tlsRecordingDialer) {
	t.Helper()
	d := &tlsRecordingDialer{connections: connections}
	a, err := New(cfg, withDialer(d))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(d.dialed) != 0 {
		t.Fatal("New dialed the directory instead of deferring I/O to Authenticate")
	}
	return a, d
}

func assertTLSTransport(t *testing.T, c *tlsRecordingConn, wantEvents []string, wantConfig *tls.Config) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !slices.Equal(c.events, wantEvents) {
		t.Errorf("transport events = %v, want %v", c.events, wantEvents)
	}
	if c.tlsConfig != wantConfig {
		t.Error("StartTLS did not receive the expected TLSConfig")
	}
}

func TestAuthenticate_TLSConfigTransportModes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		url           string
		startTLS      bool
		allowInsecure bool
		wantEvents    []string
	}{
		{
			name: "LDAPS", url: "ldaps://dir.example.com:636",
			wantEvents: []string{"dial", "bind", "search", "bind", "close"},
		},
		{
			name: "StartTLS", url: "ldap://dir.example.com:389", startTLS: true,
			wantEvents: []string{"dial", "starttls", "tls-ready", "bind", "search", "bind", "close"},
		},
		{
			name: "development plaintext opt-out", url: "ldap://dir.example.com:389", allowInsecure: true,
			wantEvents: []string{"dial", "bind", "search", "bind", "close"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := newFakeDirectory()
			standardUser(dir)
			cfg := tlsRecordingConfig(dir)
			cfg.URLs = []string{tc.url}
			cfg.StartTLS = tc.startTLS
			cfg.AllowInsecure = tc.allowInsecure
			c := newTLSRecordingConn(dir)
			a, d := newTLSRecordingAuth(t, cfg, c)
			res, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if res == nil || res.ExternalID != "alice" {
				t.Fatal("Authenticate did not return the directory user")
			}
			var wantDialConfig, wantStartTLSConfig *tls.Config
			if !tc.allowInsecure {
				wantDialConfig = cfg.TLSConfig
			}
			if tc.startTLS {
				wantStartTLSConfig = cfg.TLSConfig
			}
			if !slices.Equal(d.dialed, cfg.URLs) || len(d.tlsConfigs) != 1 || d.tlsConfigs[0] != wantDialConfig {
				t.Error("dial did not preserve the explicit transport and TLSConfig")
			}
			assertTLSTransport(t, c, tc.wantEvents, wantStartTLSConfig)
		})
	}
}

// These are failures reported by the connection boundary, not real TLS
// handshakes. Every failed upgrade must stop before any credential operation.
func TestAuthenticate_StartTLSFailure_NoBindOrSearch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		err           error
		allowInsecure bool
	}{
		{name: "unsupported", err: errors.New("StartTLS unavailable")},
		{name: "untrusted certificate", err: x509.UnknownAuthorityError{Cert: &x509.Certificate{}}},
		{name: "handshake failure", err: tls.RecordHeaderError{Msg: "invalid TLS record"}},
		{name: "explicit upgrade cannot downgrade", err: errors.New("StartTLS unavailable"), allowInsecure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := newFakeDirectory()
			standardUser(dir)
			dir.startTLSErr = tc.err
			cfg := tlsRecordingConfig(dir)
			cfg.URLs = []string{"ldap://dir.example.com:389"}
			cfg.StartTLS = true
			cfg.AllowInsecure = tc.allowInsecure
			c := newTLSRecordingConn(dir)
			a, d := newTLSRecordingAuth(t, cfg, c)
			res, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
			if res != nil || !errors.Is(err, ErrDirectoryUnavailable) || errors.Is(err, ErrAuthFailed) {
				t.Fatalf("failed upgrade must return no result and ErrDirectoryUnavailable, got err = %v", err)
			}
			if len(d.dialed) != 1 || len(d.tlsConfigs) != 1 || d.tlsConfigs[0] != cfg.TLSConfig {
				t.Error("failed upgrade did not use the supplied TLSConfig for its single dial")
			}
			assertTLSTransport(t, c, []string{"dial", "starttls", "tls-failed", "close"}, cfg.TLSConfig)
			filters, binds := dir.recorded()
			if len(filters) != 0 || len(binds) != 0 {
				t.Error("failed upgrade performed a search or bind")
			}
		})
	}
}

func TestAuthenticate_StartTLSFailover_OnlyUpgradedConnectionBinds(t *testing.T) {
	t.Parallel()
	failedDir, readyDir := newFakeDirectory(), newFakeDirectory()
	failedDir.startTLSErr = errors.New("StartTLS unavailable")
	standardUser(readyDir)
	cfg := tlsRecordingConfig(readyDir)
	cfg.URLs = []string{"ldap://first.example.com:389", "ldap://second.example.com:389"}
	cfg.StartTLS = true
	failed, ready := newTLSRecordingConn(failedDir), newTLSRecordingConn(readyDir)
	a, d := newTLSRecordingAuth(t, cfg, failed, ready)
	res, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if err != nil || res == nil || res.ExternalID != "alice" {
		t.Fatalf("Authenticate must succeed only on the upgraded failover connection, got err = %v", err)
	}
	if !slices.Equal(d.dialed, cfg.URLs) || len(d.tlsConfigs) != 2 {
		t.Fatal("did not dial both failover URLs in order")
	}
	for _, got := range d.tlsConfigs {
		if got != cfg.TLSConfig {
			t.Error("failover did not preserve the supplied TLSConfig")
		}
	}
	assertTLSTransport(t, failed, []string{"dial", "starttls", "tls-failed", "close"}, cfg.TLSConfig)
	assertTLSTransport(t, ready, []string{"dial", "starttls", "tls-ready", "bind", "search", "bind", "close"}, cfg.TLSConfig)
}

func TestAuthenticate_StartTLS_CredentialFailuresIndistinguishable(t *testing.T) {
	t.Parallel()
	for _, username := range []string{"alice", "nobody"} {
		t.Run(username, func(t *testing.T) {
			dir := newFakeDirectory()
			userDN := standardUser(dir)
			cfg := tlsRecordingConfig(dir)
			cfg.URLs = []string{"ldap://dir.example.com:389"}
			cfg.StartTLS = true
			c := newTLSRecordingConn(dir)
			a, _ := newTLSRecordingAuth(t, cfg, c)
			log := &fakeLogger{}
			a.logger = log
			const suppliedPassword = "supplied-pw"
			res, err := a.Authenticate(context.Background(), authReq(username, suppliedPassword))
			if res != nil || err != ErrAuthFailed {
				t.Fatalf("credential failure must return no result and the identical ErrAuthFailed, got err = %v", err)
			}
			assertTLSTransport(t, c, []string{"dial", "starttls", "tls-ready", "bind", "search", "bind", "close"}, cfg.TLSConfig)
			_, binds := dir.recorded()
			if len(binds) != 2 {
				t.Fatalf("got %d binds, want service plus user/dummy bind", len(binds))
			}
			wantDN := userDN
			if username == "nobody" {
				wantDN = "cn=" + dummyBindRDN + "," + cfg.BaseDN
			}
			if binds[1].dn != wantDN || binds[1].password != suppliedPassword {
				t.Error("user/dummy bind did not use the expected DN and supplied password")
			}
			if len(log.msgs) != 0 {
				t.Error("credential failure was logged as an operational error")
			}
		})
	}
}

var _ conn = (*tlsRecordingConn)(nil)
var _ dialer = (*tlsRecordingDialer)(nil)
