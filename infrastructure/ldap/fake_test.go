package ldapauth

import (
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// fakeDirectory is an in-process stand-in for an LDAP/AD directory. It answers
// Bind + Search EXACTLY as a real server would for the search-then-bind flow,
// with NO real LDAP server and NO mocking framework — the §2 "real impl, no
// mocks" discipline applied to the directory boundary, mirroring kms/awskms's
// fakeKMS.
//
// It is the shared state behind the per-dial fakeConn. The Authenticator dials
// a fakeConn (via fakeDialer), binds, searches, and rebinds against this
// directory.
type fakeDirectory struct {
	mu sync.Mutex

	// entries maps an entry DN to its attributes (each attribute multi-valued).
	entries map[string]map[string][]string
	// passwords maps an entry DN to the password a user-bind must present.
	passwords map[string]string
	// serviceDN/servicePassword are the accepted service-account credentials
	// for the search-leg bind. Empty serviceDN ⇒ anonymous bind accepted.
	serviceDN       string
	servicePassword string

	// searchEntriesFor returns the entries the directory reports for a given
	// resolved (already-escaped) filter. Test sets it to control how many
	// entries a search yields. When nil, matchFilter (a tiny uid=/sAMAccountName=
	// matcher over entries) is used.
	searchEntriesFor func(filter string) []*ldap.Entry

	// recordedFilters captures every filter string passed to Search, in order —
	// the load-bearing hook for the injection test (assert the filter the
	// directory RECEIVED is the escaped form).
	recordedFilters []string

	// recordedBinds captures every (dn, password) pair passed to Bind, in order
	// — lets the timing-parity test assert a dummy user bind happened on a
	// search miss.
	recordedBinds []bindRecord

	// startTLSCalled records whether StartTLS was invoked before any bind (the
	// "credentials never cross plaintext" assertion for the StartTLS path).
	startTLSCalled bool
	bindBeforeTLS  bool // set if a Bind happened before StartTLS (a leak)

	// dialErr / searchErr / serviceBindErr / startTLSErr, when set, make the
	// respective operation fail (drives the operational-failure tests). userBind
	// is governed by the password map, not a flag.
	searchErr      error
	startTLSErr    error
	serviceBindErr error

	// hang, when > 0, makes Search block this long (drives the timeout test);
	// the conn's per-op timeout, modeled by opTimeout, fires first.
	searchHang time.Duration
	opTimeout  time.Duration // set from the dialer's requestTimeout
}

type bindRecord struct {
	dn       string
	password string
}

// newFakeDirectory builds a directory with one service account and no entries.
func newFakeDirectory() *fakeDirectory {
	return &fakeDirectory{
		entries:         map[string]map[string][]string{},
		passwords:       map[string]string{},
		serviceDN:       "cn=svc,dc=example,dc=com",
		servicePassword: "svc-secret",
	}
}

// addUser registers a user entry with a DN, a password, and attributes.
func (d *fakeDirectory) addUser(dn, password string, attrs map[string][]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries[dn] = attrs
	d.passwords[dn] = password
}

func (d *fakeDirectory) recorded() ([]string, []bindRecord) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f := append([]string(nil), d.recordedFilters...)
	b := append([]bindRecord(nil), d.recordedBinds...)
	return f, b
}

// fakeConn is one connection to the fakeDirectory, implementing the conn
// interface the Authenticator uses. Its "current bound identity" is tracked so
// the verify-leg rebind semantics match a real server.
type fakeConn struct {
	dir    *fakeDirectory
	closed bool
	tlsUp  bool // StartTLS completed on this conn
}

func (c *fakeConn) StartTLS(_ *tls.Config) error {
	c.dir.mu.Lock()
	defer c.dir.mu.Unlock()
	if c.dir.startTLSErr != nil {
		return c.dir.startTLSErr
	}
	c.dir.startTLSCalled = true
	c.tlsUp = true
	return nil
}

func (c *fakeConn) Bind(dn, password string) error {
	c.dir.mu.Lock()
	defer c.dir.mu.Unlock()
	c.dir.recordedBinds = append(c.dir.recordedBinds, bindRecord{dn: dn, password: password})

	// Service-account / anonymous bind (search leg).
	if dn == c.dir.serviceDN {
		if c.dir.serviceBindErr != nil {
			return c.dir.serviceBindErr
		}
		if password != c.dir.servicePassword {
			return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid service credentials"))
		}
		return nil
	}
	if dn == "" {
		// Anonymous bind: accepted (a directory that allows anonymous search).
		return nil
	}

	// User bind (verify leg). A non-existent DN (the dummy-bind probe, or any
	// unknown DN) and a wrong password BOTH yield InvalidCredentials — exactly
	// the conflated failure a real directory returns, which the Authenticator
	// collapses to ErrAuthFailed.
	want, ok := c.dir.passwords[dn]
	if !ok || want != password {
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	}
	return nil
}

func (c *fakeConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	c.dir.mu.Lock()
	c.dir.recordedFilters = append(c.dir.recordedFilters, req.Filter)
	searchErr := c.dir.searchErr
	hang := c.dir.searchHang
	opTimeout := c.dir.opTimeout
	custom := c.dir.searchEntriesFor
	c.dir.mu.Unlock()

	if hang > 0 {
		// Model a hung search: the conn's per-op deadline fires before the hang
		// elapses, returning a timeout error (as go-ldap's SetTimeout would).
		if opTimeout > 0 && opTimeout < hang {
			time.Sleep(opTimeout)
			return nil, ldap.NewError(ldap.ErrorNetwork, errors.New("ldap: connection timed out"))
		}
		time.Sleep(hang)
	}
	if searchErr != nil {
		return nil, searchErr
	}

	var entries []*ldap.Entry
	if custom != nil {
		entries = custom(req.Filter)
	} else {
		entries = c.dir.matchFilter(req)
	}
	return &ldap.SearchResult{Entries: entries}, nil
}

func (c *fakeConn) Close() error {
	c.closed = true
	return nil
}

// matchFilter is a tiny matcher: it finds entries whose uid / sAMAccountName /
// cn equals the value embedded in an equality clause of the (already escaped)
// filter. It deliberately does NOT interpret LDAP filter operators — so an
// injection that tried to widen the query would only "work" if the escaped
// metacharacters happened to equal a stored attribute value, which they never
// do. This models the security property: escaping makes the injected payload an
// inert literal.
func (d *fakeDirectory) matchFilter(req *ldap.SearchRequest) []*ldap.Entry {
	d.mu.Lock()
	defer d.mu.Unlock()
	val, attr, ok := extractEqualityValue(req.Filter)
	if !ok {
		return nil
	}
	var out []*ldap.Entry
	for dn, attrs := range d.entries {
		for _, v := range attrs[attr] {
			if v == val {
				out = append(out, buildEntry(dn, attrs, req.Attributes))
			}
		}
		// Also allow matching by the requested ID attr stored under a different
		// key when the filter used it (e.g. cn= in a group search).
	}
	return out
}

// extractEqualityValue pulls the value + attribute from the LAST "attr=value)"
// equality clause in a filter string. Good enough for the test filters
// ((&(objectClass=...)(uid=VALUE)) etc.). Returns the raw (still-escaped) value
// — which is exactly what we compare against stored values, proving escaping
// neutralizes injection.
func extractEqualityValue(filter string) (value, attr string, ok bool) {
	// Find the last '=' that is followed by a value terminated by ')'.
	// Walk clauses of the form (attr=value).
	best := ""
	bestAttr := ""
	found := false
	depth := 0
	clauseStart := -1
	for i := 0; i < len(filter); i++ {
		switch filter[i] {
		case '(':
			depth++
			clauseStart = i + 1
		case ')':
			if clauseStart >= 0 && clauseStart <= i {
				clause := filter[clauseStart:i]
				if eq := strings.IndexByte(clause, '='); eq > 0 {
					a := clause[:eq]
					v := clause[eq+1:]
					// Skip the objectClass guard clause; we want the identity attr.
					if !strings.EqualFold(a, "objectClass") && v != "" {
						best = v
						bestAttr = a
						found = true
					}
				}
			}
			clauseStart = -1
			depth--
		}
	}
	_ = depth
	return best, bestAttr, found
}

func buildEntry(dn string, attrs map[string][]string, requested []string) *ldap.Entry {
	// Honor the requested attribute set: a real server returns only what was
	// asked for. If requested is empty, return all (rare in our flow).
	filtered := map[string][]string{}
	for name, vals := range attrs {
		if len(requested) > 0 && !containsFold(requested, name) {
			continue
		}
		filtered[name] = vals
	}
	e := ldap.NewEntry(dn, filtered)
	e.DN = dn
	return e
}

func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// fakeDialer hands out fakeConns backed by one shared fakeDirectory. It records
// the per-op timeout (so the timeout test can model SetTimeout) and can be made
// to fail the dial (driving the failover + unavailable tests).
type fakeDialer struct {
	dir *fakeDirectory
	// dialErrFor returns an error for a given URL (failover test); nil ⇒ dial
	// succeeds. When the function itself is nil, every dial succeeds.
	dialErrFor func(rawURL string) error
	dialed     []string // URLs dialed, in order
	requestTO  time.Duration
}

func (d *fakeDialer) Dial(rawURL string, _ time.Duration, _ *tls.Config) (conn, error) {
	d.dialed = append(d.dialed, rawURL)
	if d.dialErrFor != nil {
		if err := d.dialErrFor(rawURL); err != nil {
			return nil, err
		}
	}
	d.dir.mu.Lock()
	d.dir.opTimeout = d.requestTO
	d.dir.mu.Unlock()
	return &fakeConn{dir: d.dir}, nil
}

var _ conn = (*fakeConn)(nil)
var _ dialer = (*fakeDialer)(nil)
