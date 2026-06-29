package ldapauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/snaplink/sso/interfaces/sso"
)

// newTestAuth builds an Authenticator wired to a fake directory/dialer. cfg
// supplies only the operator-facing fields; the TLS gate is satisfied with an
// ldaps:// URL so Validate passes without real TLS (the fake dialer ignores the
// TLS config — it does no network I/O).
func newTestAuth(t *testing.T, dir *fakeDirectory, cfg Config) (*Authenticator, *fakeDialer) {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "test-ldap"
	}
	if len(cfg.URLs) == 0 {
		cfg.URLs = []string{"ldaps://dir.example.com:636"}
	}
	if cfg.BaseDN == "" {
		cfg.BaseDN = "dc=example,dc=com"
	}
	if cfg.BindDN == "" {
		cfg.BindDN = dir.serviceDN
		cfg.BindPassword = dir.servicePassword
	}
	d := &fakeDialer{dir: dir, requestTO: cfg.requestTimeout()}
	a, err := New(cfg, withDialer(d))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a, d
}

func authReq(username, password string) *sso.AuthRequest {
	return &sso.AuthRequest{Credential: map[string]string{"username": username, "password": password}}
}

// standardUser registers "alice" with uid=alice, a password, mail, and a
// memberOf group, under the default base.
func standardUser(dir *fakeDirectory) string {
	dn := "uid=alice,dc=example,dc=com"
	dir.addUser(dn, "s3cret", map[string][]string{
		"uid":      {"alice"},
		"mail":     {"alice@example.com"},
		"cn":       {"Alice Example"},
		"memberOf": {"cn=engineers,ou=groups,dc=example,dc=com", "cn=admins,ou=groups,dc=example,dc=com"},
	})
	return dn
}

// --- Happy path -----------------------------------------------------------

func TestAuthenticate_HappyPath(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	standardUser(dir)
	a, _ := newTestAuth(t, dir, Config{
		UserFilter:  "(&(objectClass=person)(uid=%s))",
		IDAttribute: "uid",
		AttributeMapping: map[string]string{
			"mail": "email",
			"cn":   "name",
		},
		GroupAttribute: "memberOf",
	})

	res, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.ExternalID != "alice" {
		t.Errorf("ExternalID = %q, want alice", res.ExternalID)
	}
	if res.Provider != "test-ldap" {
		t.Errorf("Provider = %q, want test-ldap", res.Provider)
	}
	if len(res.AuthMethods) != 1 || res.AuthMethods[0] != AuthMethodLDAP {
		t.Errorf("AuthMethods = %v, want [%s]", res.AuthMethods, AuthMethodLDAP)
	}
	if res.Attributes["email"] != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", res.Attributes["email"])
	}
	if res.Attributes["name"] != "Alice Example" {
		t.Errorf("name = %q, want Alice Example", res.Attributes["name"])
	}
	// Groups (memberOf) are comma-joined under "groups".
	gs := res.Attributes["groups"]
	if !strings.Contains(gs, "cn=engineers,ou=groups,dc=example,dc=com") ||
		!strings.Contains(gs, "cn=admins,ou=groups,dc=example,dc=com") {
		t.Errorf("groups = %q, want both engineers + admins DNs", gs)
	}
}

// --- Wrong password vs unknown user: SAME error (anti-enumeration) --------

func TestAuthenticate_WrongPassword(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	standardUser(dir)
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(uid=%s)", IDAttribute: "uid"})

	_, err := a.Authenticate(context.Background(), authReq("alice", "WRONG"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("wrong password err = %v, want ErrAuthFailed", err)
	}
}

func TestAuthenticate_UnknownUser_SameErrorAsWrongPassword(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	standardUser(dir)
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(uid=%s)", IDAttribute: "uid"})

	_, wrongPwErr := a.Authenticate(context.Background(), authReq("alice", "WRONG"))
	_, unknownErr := a.Authenticate(context.Background(), authReq("nobody", "whatever"))

	// The two MUST be the same wire error — no probe can tell "no such user"
	// from "wrong password".
	if !errors.Is(unknownErr, ErrAuthFailed) {
		t.Fatalf("unknown-user err = %v, want ErrAuthFailed", unknownErr)
	}
	if !errors.Is(wrongPwErr, ErrAuthFailed) {
		t.Fatalf("wrong-password err = %v, want ErrAuthFailed", wrongPwErr)
	}
	if unknownErr.Error() != wrongPwErr.Error() {
		t.Errorf("unknown-user err %q != wrong-password err %q (enumeration oracle)", unknownErr, wrongPwErr)
	}
}

// TestAuthenticate_UnknownUser_DummyBindForTimingParity proves a search miss
// STILL performs a user bind (the dummy bind), so an unknown user pays the same
// bind round-trip a wrong-password attempt does — closing the timing
// side-channel. We assert by inspecting the binds the directory received.
func TestAuthenticate_UnknownUser_DummyBindForTimingParity(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	standardUser(dir)
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(uid=%s)", IDAttribute: "uid"})

	_, err := a.Authenticate(context.Background(), authReq("nobody", "supplied-pw"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}

	_, binds := dir.recorded()
	// Expected binds: [service-account bind, dummy user bind].
	if len(binds) < 2 {
		t.Fatalf("got %d binds %v, want >= 2 (service + dummy user bind)", len(binds), binds)
	}
	last := binds[len(binds)-1]
	// The dummy bind targets a non-existent DN under the base, with the SUPPLIED
	// password (so the work matches a real wrong-password bind).
	if !strings.Contains(last.dn, dummyBindRDN) {
		t.Errorf("dummy bind DN = %q, want it to contain the non-existent probe RDN %q", last.dn, dummyBindRDN)
	}
	if !strings.HasSuffix(last.dn, "dc=example,dc=com") {
		t.Errorf("dummy bind DN = %q, want it under the configured base", last.dn)
	}
	if last.password != "supplied-pw" {
		t.Errorf("dummy bind used password %q, want the supplied password (timing parity)", last.password)
	}
}

// Symmetry check: a wrong-password attempt for a KNOWN user also ends in a user
// bind, so the bind-count shape matches the unknown-user case.
func TestAuthenticate_WrongPassword_PerformsUserBind(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	standardUser(dir)
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(uid=%s)", IDAttribute: "uid"})

	_, _ = a.Authenticate(context.Background(), authReq("alice", "WRONG"))
	_, binds := dir.recorded()
	if len(binds) < 2 {
		t.Fatalf("got %d binds, want >= 2 (service + user verify bind)", len(binds))
	}
	last := binds[len(binds)-1]
	if last.dn != "uid=alice,dc=example,dc=com" {
		t.Errorf("verify bind DN = %q, want the real user DN", last.dn)
	}
}

func TestAuthenticate_EmptyPassword_RejectedNoBind(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	standardUser(dir)
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(uid=%s)", IDAttribute: "uid"})

	// Empty password must be rejected WITHOUT ever dialing/binding (an empty-pw
	// bind can be an anonymous success on a real directory).
	_, err := a.Authenticate(context.Background(), authReq("alice", ""))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("empty-password err = %v, want ErrAuthFailed", err)
	}
	filters, binds := dir.recorded()
	if len(binds) != 0 || len(filters) != 0 {
		t.Errorf("empty password performed I/O: binds=%v filters=%v, want none", binds, filters)
	}
}

// --- LDAP INJECTION (the load-bearing security test) ----------------------

// TestAuthenticate_LDAPInjection_UsernameEscaped proves a username containing
// filter metacharacters is ESCAPED before it reaches the directory: the filter
// the backend RECEIVES carries the \HH-escaped form, the injection does NOT
// widen the query (no entry matches), and the result is the generic
// ErrAuthFailed (indistinguishable from any other miss).
func TestAuthenticate_LDAPInjection_UsernameEscaped(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	// A decoy "admin" entry the injection would try to reach if unescaped.
	dir.addUser("uid=admin,dc=example,dc=com", "admin-pw", map[string][]string{"uid": {"admin"}})
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(&(objectClass=person)(uid=%s))", IDAttribute: "uid"})

	// The classic filter-injection payload: close the uid clause and inject a
	// wildcard OR to match every entry.
	malicious := "*)(uid=*))(|(uid=*"
	_, err := a.Authenticate(context.Background(), authReq(malicious, "anything"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("injection attempt err = %v, want ErrAuthFailed (no entry should match)", err)
	}

	filters, _ := dir.recorded()
	if len(filters) == 0 {
		t.Fatal("no filter recorded")
	}
	sent := filters[0]

	// 1. The RAW payload must NOT appear verbatim in the sent filter — if it did,
	//    the metacharacters would be live and the query widened.
	if strings.Contains(sent, malicious) {
		t.Errorf("sent filter %q contains the RAW injection payload — NOT escaped", sent)
	}
	// 2. The sent filter MUST equal exactly the filter built from the
	//    EscapeFilter'd username — the precise, canonical defense.
	wantFilter := "(&(objectClass=person)(uid=" + ldap.EscapeFilter(malicious) + "))"
	if sent != wantFilter {
		t.Errorf("sent filter = %q, want escaped form %q", sent, wantFilter)
	}
	// 3. Spot-check the escaping turned '*' '(' ')' into their \HH sequences, so
	//    the structure of the filter cannot be altered by the payload.
	escaped := ldap.EscapeFilter(malicious)
	for _, meta := range []string{"*", "(", ")"} {
		if strings.Contains(escaped, meta) {
			t.Errorf("escaped username %q still contains live metacharacter %q", escaped, meta)
		}
	}
	if !strings.Contains(escaped, `\2a`) { // '*' -> \2a
		t.Errorf("escaped username %q missing \\2a for '*'", escaped)
	}
}

// A grab-bag of metacharacters (backslash, parens, NUL) are all escaped.
func TestAuthenticate_LDAPInjection_AllMetacharsEscaped(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	standardUser(dir)
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(uid=%s)", IDAttribute: "uid"})

	for _, payload := range []string{
		`*`,
		`a)(b`,
		`back\slash`,
		"nul\x00byte",
		`(|(uid=*))`,
	} {
		dir.recordedFilters = nil
		_, _ = a.Authenticate(context.Background(), authReq(payload, "pw"))
		filters, _ := dir.recorded()
		if len(filters) == 0 {
			t.Fatalf("payload %q: no filter recorded", payload)
		}
		sent := filters[0]
		want := "(uid=" + ldap.EscapeFilter(payload) + ")"
		if sent != want {
			t.Errorf("payload %q: sent filter %q, want %q", payload, sent, want)
		}
		// None of the raw metacharacters survive in the value portion.
		val := strings.TrimSuffix(strings.TrimPrefix(sent, "(uid="), ")")
		for _, meta := range []string{"*", "(", ")", `\5c`} {
			_ = meta
		}
		if strings.ContainsAny(val, "*()") && !strings.Contains(val, `\`) {
			t.Errorf("payload %q: value %q has unescaped metacharacters", payload, val)
		}
	}
}

// --- Ambiguous (>1) match rejected ----------------------------------------

func TestAuthenticate_AmbiguousMatch_Rejected(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	// Force the search to return TWO entries for any filter.
	dir.searchEntriesFor = func(_ string) []*ldap.Entry {
		return []*ldap.Entry{
			ldap.NewEntry("uid=a,dc=example,dc=com", map[string][]string{"uid": {"dup"}}),
			ldap.NewEntry("uid=b,dc=example,dc=com", map[string][]string{"uid": {"dup"}}),
		}
	}
	dir.addUser("uid=a,dc=example,dc=com", "pw", map[string][]string{"uid": {"dup"}})
	dir.addUser("uid=b,dc=example,dc=com", "pw", map[string][]string{"uid": {"dup"}})
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(uid=%s)", IDAttribute: "uid"})

	_, err := a.Authenticate(context.Background(), authReq("dup", "pw"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("ambiguous-match err = %v, want ErrAuthFailed", err)
	}
	// Must NOT have bound as either ambiguous entry (only the service bind + the
	// timing-parity dummy bind are allowed).
	_, binds := dir.recorded()
	for _, b := range binds {
		if b.dn == "uid=a,dc=example,dc=com" || b.dn == "uid=b,dc=example,dc=com" {
			t.Errorf("bound as an ambiguous entry %q — must never happen", b.dn)
		}
	}
}

// --- Group second-search path (reverse membership) ------------------------

func TestAuthenticate_GroupSearch_ReverseMembership(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	dir.addUser("uid=bob,dc=example,dc=com", "pw", map[string][]string{"uid": {"bob"}})
	// Group entries returned by the GroupFilter search.
	dir.searchEntriesFor = func(filter string) []*ldap.Entry {
		if strings.Contains(filter, "groupOfNames") {
			// The group search: return two groups.
			return []*ldap.Entry{
				ldap.NewEntry("cn=team,ou=groups,dc=example,dc=com", map[string][]string{"cn": {"team"}}),
				ldap.NewEntry("cn=staff,ou=groups,dc=example,dc=com", map[string][]string{"cn": {"staff"}}),
			}
		}
		// The user search: return bob.
		return []*ldap.Entry{ldap.NewEntry("uid=bob,dc=example,dc=com", map[string][]string{"uid": {"bob"}})}
	}
	a, _ := newTestAuth(t, dir, Config{
		UserFilter:  "(uid=%s)",
		IDAttribute: "uid",
		GroupBaseDN: "ou=groups,dc=example,dc=com",
		GroupFilter: "(&(objectClass=groupOfNames)(member=%s))",
	})

	res, err := a.Authenticate(context.Background(), authReq("bob", "pw"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	gs := res.Attributes["groups"]
	if !strings.Contains(gs, "team") || !strings.Contains(gs, "staff") {
		t.Errorf("groups = %q, want team + staff", gs)
	}

	// The group filter must have escaped the user DN and used the member= clause.
	filters, _ := dir.recorded()
	var groupFilter string
	for _, f := range filters {
		if strings.Contains(f, "groupOfNames") {
			groupFilter = f
		}
	}
	if groupFilter == "" {
		t.Fatal("group search filter not recorded")
	}
	wantGroupFilter := "(&(objectClass=groupOfNames)(member=" + ldap.EscapeFilter("uid=bob,dc=example,dc=com") + "))"
	if groupFilter != wantGroupFilter {
		t.Errorf("group filter = %q, want %q (user DN escaped)", groupFilter, wantGroupFilter)
	}
}

// Group filter injection: a user DN containing metacharacters is escaped in the
// group second-search too.
func TestAuthenticate_GroupSearch_DNEscaped(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	// User DN deliberately carries a paren (legal-ish in a CN value) to prove
	// escaping in the group filter.
	weirdDN := `uid=ev(il,dc=example,dc=com`
	dir.searchEntriesFor = func(filter string) []*ldap.Entry {
		if strings.Contains(filter, "groupOfNames") {
			return nil // no groups; we only care about the filter shape
		}
		return []*ldap.Entry{ldap.NewEntry(weirdDN, map[string][]string{"uid": {"evil"}})}
	}
	dir.addUser(weirdDN, "pw", map[string][]string{"uid": {"evil"}})
	a, _ := newTestAuth(t, dir, Config{
		UserFilter:  "(uid=%s)",
		IDAttribute: "uid",
		GroupBaseDN: "ou=groups,dc=example,dc=com",
		GroupFilter: "(&(objectClass=groupOfNames)(member=%s))",
	})

	_, err := a.Authenticate(context.Background(), authReq("evil", "pw"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	filters, _ := dir.recorded()
	for _, f := range filters {
		if strings.Contains(f, "groupOfNames") {
			want := "(&(objectClass=groupOfNames)(member=" + ldap.EscapeFilter(weirdDN) + "))"
			if f != want {
				t.Errorf("group filter = %q, want escaped %q", f, want)
			}
			if strings.Contains(f, "ev(il") {
				t.Errorf("group filter %q contains the unescaped '(' from the DN", f)
			}
		}
	}
}

// TestAuthenticate_GroupSearch_MemberUid_UsernameEscaped guards the OTHER
// group-second-search branch: a posixGroup/memberUid filter substitutes the
// USERNAME (not the user DN), and that username — being user-controlled — must
// be escaped with ldap.EscapeFilter before it reaches the directory. The DN
// branch already has TestAuthenticate_GroupSearch_DNEscaped; without this test
// the username/memberUid branch (where a malicious username flows into a group
// filter) had no injection coverage, so a future refactor could drop the
// escaping on this path undetected. We feed a username full of filter
// metacharacters and assert the group filter the directory RECEIVED is exactly
// the escaped form, the raw payload is absent, and it was the USERNAME (not the
// DN) that was substituted.
func TestAuthenticate_GroupSearch_MemberUid_UsernameEscaped(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()

	// The user lives at a DN that is intentionally UNRELATED to the username, so
	// asserting the username (not the DN) reached the group filter is unambiguous.
	const userDN = "uid=svc-account-7,dc=example,dc=com"
	// A username carrying LDAP filter metacharacters: an attempt to break out of
	// the memberUid clause and widen the group query.
	const malicious = "*)(memberUid=*"
	const groupFilter = "(&(objectClass=posixGroup)(memberUid=%s))"

	// Route the two searches by filter shape: the posixGroup/memberUid filter is
	// the group search (return one group); anything else is the user search
	// (return the single user entry, so the flow proceeds to group resolution).
	// The user search filter (uid=...) embeds the SAME escaped malicious value, so
	// we cannot key on the metacharacters — we key on the posixGroup objectClass.
	dir.searchEntriesFor = func(filter string) []*ldap.Entry {
		if strings.Contains(filter, "posixGroup") {
			return []*ldap.Entry{
				ldap.NewEntry("cn=devs,ou=groups,dc=example,dc=com", map[string][]string{"cn": {"devs"}}),
			}
		}
		return []*ldap.Entry{ldap.NewEntry(userDN, map[string][]string{"uid": {"svc-account-7"}})}
	}
	dir.addUser(userDN, "pw", map[string][]string{"uid": {"svc-account-7"}})

	a, _ := newTestAuth(t, dir, Config{
		UserFilter:  "(uid=%s)",
		IDAttribute: "uid",
		GroupBaseDN: "ou=groups,dc=example,dc=com",
		// A memberUid (posixGroup) filter selects the USERNAME-substitution branch
		// in resolveGroups (the "memberuid" case-insensitive match).
		GroupFilter: groupFilter,
	})

	res, err := a.Authenticate(context.Background(), authReq(malicious, "pw"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// The group resolved despite the metacharacter username — escaping makes the
	// payload an inert literal, it does not abort the lookup.
	if gs := res.Attributes["groups"]; !strings.Contains(gs, "devs") {
		t.Errorf("groups = %q, want devs", gs)
	}

	// Find the GROUP filter (the posixGroup one) among the recorded filters. The
	// user search filter (uid=...) also carries the escaped username, so we must
	// pick the group filter specifically.
	filters, _ := dir.recorded()
	var groupSent string
	for _, f := range filters {
		if strings.Contains(f, "posixGroup") {
			groupSent = f
		}
	}
	if groupSent == "" {
		t.Fatal("group (posixGroup/memberUid) search filter not recorded")
	}

	// 1. The group filter MUST equal exactly the filter built from the
	//    EscapeFilter'd USERNAME — the canonical defense on the memberUid branch.
	//    Using the username (not userDN) here also proves the branch selection:
	//    if the DN had been substituted, this exact-match would fail.
	wantGroupFilter := fmt.Sprintf(groupFilter, ldap.EscapeFilter(malicious))
	if groupSent != wantGroupFilter {
		t.Errorf("group filter = %q, want escaped-username form %q", groupSent, wantGroupFilter)
	}
	// 2. The RAW payload must NOT appear verbatim — if it did, the parens/wildcard
	//    would be live and the group query widened.
	if strings.Contains(groupSent, malicious) {
		t.Errorf("group filter %q contains the RAW injection payload — NOT escaped", groupSent)
	}
	// 3. It must be the USERNAME, not the user DN, that was substituted (the
	//    memberUid branch). The DN must be absent from the group filter.
	if strings.Contains(groupSent, userDN) {
		t.Errorf("group filter %q contains the user DN — the memberUid branch must substitute the username, not the DN", groupSent)
	}
	// 4. Spot-check the live metacharacters were turned into their \HH sequences,
	//    so the payload cannot alter the filter structure.
	for _, meta := range []string{"*)", "*("} { // raw paren+wildcard pairs from the payload
		if strings.Contains(groupSent, meta) {
			t.Errorf("group filter %q still contains a live metacharacter sequence %q", groupSent, meta)
		}
	}
	if !strings.Contains(groupSent, `\2a`) { // '*' -> \2a
		t.Errorf("group filter %q missing \\2a escape for '*'", groupSent)
	}
}

// TestResolveGroups_BranchSelection_DNvsUsername confirms the SELECTION between
// the two group-second-search branches: a "member"-style filter routes the user
// DN into the placeholder, while a "memberUid"-style filter routes the username.
// This locks the routing rule the escaping tests each assert on one side.
func TestResolveGroups_BranchSelection_DNvsUsername(t *testing.T) {
	t.Parallel()
	const userDN = "uid=zoe,dc=example,dc=com"
	const username = "zoe"

	cases := []struct {
		name        string
		groupFilter string
		wantValue   string // the value EscapeFilter'd into the placeholder
	}{
		{
			name:        "member filter substitutes the user DN",
			groupFilter: "(&(objectClass=groupOfNames)(member=%s))",
			wantValue:   userDN,
		},
		{
			name:        "memberUid filter substitutes the username",
			groupFilter: "(&(objectClass=posixGroup)(memberUid=%s))",
			wantValue:   username,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := newFakeDirectory()
			dir.addUser(userDN, "pw", map[string][]string{"uid": {username}})
			dir.searchEntriesFor = func(filter string) []*ldap.Entry {
				// Group search yields nothing; we only inspect the filter shape.
				if strings.Contains(filter, "groupOfNames") || strings.Contains(filter, "posixGroup") {
					return nil
				}
				return []*ldap.Entry{ldap.NewEntry(userDN, map[string][]string{"uid": {username}})}
			}
			a, _ := newTestAuth(t, dir, Config{
				UserFilter:  "(uid=%s)",
				IDAttribute: "uid",
				GroupBaseDN: "ou=groups,dc=example,dc=com",
				GroupFilter: tc.groupFilter,
			})

			if _, err := a.Authenticate(context.Background(), authReq(username, "pw")); err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			filters, _ := dir.recorded()
			var groupSent string
			for _, f := range filters {
				if strings.Contains(f, "groupOfNames") || strings.Contains(f, "posixGroup") {
					groupSent = f
				}
			}
			if groupSent == "" {
				t.Fatal("group search filter not recorded")
			}
			want := fmt.Sprintf(tc.groupFilter, ldap.EscapeFilter(tc.wantValue))
			if groupSent != want {
				t.Errorf("group filter = %q, want %q (value %q substituted)", groupSent, want, tc.wantValue)
			}
		})
	}
}

// --- Operational failures (distinct from a credential verdict) ------------

func TestAuthenticate_ServiceBindRejected_DirectoryUnavailable(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	standardUser(dir)
	a, _ := newTestAuth(t, dir, Config{
		UserFilter:   "(uid=%s)",
		IDAttribute:  "uid",
		BindDN:       dir.serviceDN,
		BindPassword: "WRONG-SERVICE-PW", // service creds rejected
	})

	_, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("service-bind-rejected err = %v, want ErrDirectoryUnavailable", err)
	}
	// Crucially NOT ErrAuthFailed (it's an operator problem, not a user verdict)
	// — and it reveals nothing about whether "alice" exists.
	if errors.Is(err, ErrAuthFailed) {
		t.Error("service-bind failure leaked as ErrAuthFailed")
	}
}

func TestAuthenticate_DialFailure_Failover(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	standardUser(dir)
	d := &fakeDialer{
		dir:       dir,
		requestTO: DefaultRequestTimeout,
		dialErrFor: func(rawURL string) error {
			if strings.Contains(rawURL, "dc1") {
				return errors.New("dial dc1: connection refused")
			}
			return nil // dc2 succeeds
		},
	}
	cfg := Config{
		Name:         "ad",
		URLs:         []string{"ldaps://dc1.example.com:636", "ldaps://dc2.example.com:636"},
		BaseDN:       "dc=example,dc=com",
		BindDN:       dir.serviceDN,
		BindPassword: dir.servicePassword,
		UserFilter:   "(uid=%s)",
		IDAttribute:  "uid",
	}
	a, err := New(cfg, withDialer(d))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
	if err != nil {
		t.Fatalf("Authenticate (should fail over to dc2): %v", err)
	}
	if res.ExternalID != "alice" {
		t.Errorf("ExternalID = %q, want alice", res.ExternalID)
	}
	if len(d.dialed) != 2 || !strings.Contains(d.dialed[0], "dc1") || !strings.Contains(d.dialed[1], "dc2") {
		t.Errorf("dialed = %v, want [dc1, dc2] (failover)", d.dialed)
	}
}

func TestAuthenticate_AllDialsFail_Unavailable(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	d := &fakeDialer{
		dir:        dir,
		requestTO:  DefaultRequestTimeout,
		dialErrFor: func(_ string) error { return errors.New("connection refused") },
	}
	cfg := Config{
		Name: "ad", URLs: []string{"ldaps://a:636", "ldaps://b:636"},
		BaseDN: "dc=example,dc=com", BindDN: dir.serviceDN, BindPassword: dir.servicePassword,
		UserFilter: "(uid=%s)", IDAttribute: "uid",
	}
	a, _ := New(cfg, withDialer(d))
	_, err := a.Authenticate(context.Background(), authReq("alice", "pw"))
	if !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("all-dials-fail err = %v, want ErrDirectoryUnavailable", err)
	}
}

// --- Timeout: a hung search returns a bounded error, not a hang -----------

func TestAuthenticate_SearchTimeout_Bounded(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	standardUser(dir)
	dir.searchHang = time.Hour // the search would hang forever
	cfg := Config{
		UserFilter: "(uid=%s)", IDAttribute: "uid",
		RequestTimeout: 50 * time.Millisecond, // the per-op bound fires first
	}
	a, _ := newTestAuth(t, dir, cfg)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := a.Authenticate(context.Background(), authReq("alice", "s3cret"))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a bounded timeout error, got nil")
		}
		// A search timeout is operational (the directory didn't answer) — surfaces
		// as ErrDirectoryUnavailable, not a credential verdict.
		if !errors.Is(err, ErrDirectoryUnavailable) {
			t.Errorf("timeout err = %v, want ErrDirectoryUnavailable", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("Authenticate took %v — bound did not fire promptly", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Authenticate HUNG past the request timeout — bound not enforced")
	}
}

func TestAuthenticate_ContextCancelled_BetweenFailover(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	d := &fakeDialer{
		dir:        dir,
		requestTO:  DefaultRequestTimeout,
		dialErrFor: func(_ string) error { return errors.New("refused") },
	}
	cfg := Config{
		Name: "ad", URLs: []string{"ldaps://a:636", "ldaps://b:636"},
		BaseDN: "dc=example,dc=com", BindDN: dir.serviceDN, BindPassword: dir.servicePassword,
		UserFilter: "(uid=%s)", IDAttribute: "uid",
	}
	a, _ := New(cfg, withDialer(d))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	_, err := a.Authenticate(ctx, authReq("alice", "pw"))
	if !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("cancelled-context err = %v, want ErrDirectoryUnavailable", err)
	}
}

// --- Interface contract: LoginURL "" + Callback not applicable ------------

func TestLoginURL_Empty(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(uid=%s)"})
	if got := a.LoginURL("some-state"); got != "" {
		t.Errorf("LoginURL = %q, want \"\" (direct credential auth)", got)
	}
}

func TestCallback_NotApplicable(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(uid=%s)"})
	if _, err := a.Callback(context.Background(), &sso.CallbackState{}); !errors.Is(err, ErrCallbackNotApplicable) {
		t.Errorf("Callback err = %v, want ErrCallbackNotApplicable", err)
	}
}

func TestName(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	a, _ := newTestAuth(t, dir, Config{Name: "corp-ad", UserFilter: "(uid=%s)"})
	if a.Name() != "corp-ad" {
		t.Errorf("Name() = %q, want corp-ad", a.Name())
	}
}

// --- ID-attribute fallback to DN ------------------------------------------

func TestAuthenticate_IDAttributeAbsent_FallsBackToDN(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	// User has no "objectGUID" attribute, so ExternalID must fall back to the DN.
	dir.addUser("uid=carol,dc=example,dc=com", "pw", map[string][]string{"uid": {"carol"}})
	a, _ := newTestAuth(t, dir, Config{UserFilter: "(uid=%s)", IDAttribute: "objectGUID"})

	res, err := a.Authenticate(context.Background(), authReq("carol", "pw"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.ExternalID != "uid=carol,dc=example,dc=com" {
		t.Errorf("ExternalID = %q, want the entry DN fallback", res.ExternalID)
	}
}

// --- Anonymous search bind (no service account) ---------------------------

func TestAuthenticate_AnonymousSearchBind(t *testing.T) {
	t.Parallel()
	dir := newFakeDirectory()
	dir.serviceDN = "" // directory permits anonymous search
	dir.addUser("uid=dave,dc=example,dc=com", "pw", map[string][]string{"uid": {"dave"}})
	cfg := Config{
		Name: "anon", URLs: []string{"ldaps://dir:636"}, BaseDN: "dc=example,dc=com",
		UserFilter: "(uid=%s)", IDAttribute: "uid",
		// No BindDN ⇒ anonymous search.
	}
	d := &fakeDialer{dir: dir, requestTO: DefaultRequestTimeout}
	a, err := New(cfg, withDialer(d))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := a.Authenticate(context.Background(), authReq("dave", "pw"))
	if err != nil {
		t.Fatalf("Authenticate (anonymous search): %v", err)
	}
	if res.ExternalID != "dave" {
		t.Errorf("ExternalID = %q, want dave", res.ExternalID)
	}
}
