package ldapauth

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// groupsAttributeKey is the AuthResult.Attributes key under which resolved
// group memberships are stored (comma-joined). Kept distinct so it never
// collides with an operator-mapped attribute name.
const groupsAttributeKey = "groups"

// groupsSeparator joins group values into the single Attributes string value
// (AuthResult.Attributes is map[string]string, not multi-valued). A comma is
// the conventional list separator; group DNs/names do not contain bare commas
// in a way that would be ambiguous for a consumer that splits on it (DNs are
// presented as whole strings here, one per resolved membership).
const groupsSeparator = ","

// searchUser performs the SEARCH leg: it resolves username to exactly one
// directory entry, returning the entry DN, the IDAttribute value, and the
// mapped attributes. It returns ErrAuthFailed (the generic, anti-enumeration
// error) when the user is not found OR when more than one entry matches —
// indistinguishable from a wrong password to any caller.
//
// INJECTION DEFENSE: the username is escaped with ldap.EscapeFilter before it
// is substituted into the filter. The raw username is NEVER formatted into the
// filter string. fmt.Sprintf with a single %s arg over the operator's
// (Validate-checked single-placeholder) filter then yields a filter where the
// user-controlled portion is inert — "*)(uid=*" becomes the literal escaped
// sequence "\2a)(uid=\2a", which matches only an entry whose attribute value is
// that exact (absurd) string, not a widened query.
func (a *Authenticator) searchUser(c conn, username string) (entryDN, idValue string, attrs map[string]string, memberOf []string, err error) {
	filter := fmt.Sprintf(a.cfg.userFilter(), ldap.EscapeFilter(username))

	// Request only the attributes we will read: the ID attribute, every mapped
	// attribute, and (when memberOf-style) the group attribute. Requesting a
	// closed set means the directory cannot push an unexpected attribute onto
	// the AuthResult.
	wanted := a.requestedAttributes()

	req := ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		// SizeLimit 2 (not 1): we WANT to detect an ambiguous >1 match and
		// reject it, rather than have the server silently truncate to the first
		// entry and let us bind as an arbitrary one of several matches.
		2,
		0, // per-request time limit comes from Conn.SetTimeout, not here
		false,
		filter,
		wanted,
		nil,
	)
	sr, err := c.Search(req)
	if err != nil {
		// A transport/search error is operational, not a verdict. But it could
		// also be a directory that returns "size limit exceeded" as an error
		// when >1 entry matches; treat THAT as the ambiguous-match verdict
		// (ErrAuthFailed) so it collapses with the other enumeration cases.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return "", "", nil, nil, ErrAuthFailed
		}
		return "", "", nil, nil, fmt.Errorf("%w: search: %v", ErrDirectoryUnavailable, err)
	}

	// Require EXACTLY ONE entry. 0 (unknown user) and >1 (ambiguous) BOTH
	// collapse to the generic ErrAuthFailed — the caller then runs a dummy bind
	// for timing parity. Never bind as one of several ambiguous matches.
	if len(sr.Entries) != 1 {
		return "", "", nil, nil, ErrAuthFailed
	}
	entry := sr.Entries[0]

	attrs = a.mapAttributes(entry)
	idValue = entry.GetAttributeValue(a.cfg.idAttribute())
	// Capture memberOf-style group values from the entry NOW (the attribute was
	// requested in this same search), so the caller needs no second round-trip
	// and we keep zero shared per-request state on the Authenticator.
	if a.cfg.GroupAttribute != "" {
		memberOf = entry.GetAttributeValues(a.cfg.GroupAttribute)
	}
	return entry.DN, idValue, attrs, memberOf, nil
}

// requestedAttributes is the closed set of attribute names the search asks the
// directory to return: the ID attribute, every source key in AttributeMapping,
// and (when configured) the memberOf-style group attribute. Deduplicated.
func (a *Authenticator) requestedAttributes() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	add(a.cfg.idAttribute())
	for src := range a.cfg.AttributeMapping {
		add(src)
	}
	add(a.cfg.GroupAttribute) // no-op when empty
	return out
}

// mapAttributes projects the entry's directory attributes onto the local
// AuthResult.Attributes keys per cfg.AttributeMapping. Only mapped attributes
// are emitted (nothing passes through implicitly). A multi-valued directory
// attribute is joined with the same separator groups use; a single value passes
// through verbatim.
func (a *Authenticator) mapAttributes(entry *ldap.Entry) map[string]string {
	if len(a.cfg.AttributeMapping) == 0 {
		return nil
	}
	out := make(map[string]string, len(a.cfg.AttributeMapping))
	for src, dst := range a.cfg.AttributeMapping {
		vals := entry.GetAttributeValues(src)
		if len(vals) == 0 {
			continue
		}
		if len(vals) == 1 {
			out[dst] = vals[0]
		} else {
			out[dst] = strings.Join(vals, groupsSeparator)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// dummyBind performs a deliberately-failing user bind on a search miss so the
// TIMING of an unknown-user attempt matches a real wrong-password attempt
// (which always pays one user-bind round-trip in Authenticate step 4). Without
// this, an attacker could distinguish "user does not exist" (no bind happened —
// fast) from "wrong password" (a bind happened — slower) by latency, defeating
// the single-error anti-enumeration contract. This is the LDAP analogue of the
// password authenticator's cost-matched dummy bcrypt hash (§2).
//
// It binds a syntactically-valid but non-existent DN under the search base with
// the SUPPLIED password (so the bind does the same work a real one would). The
// result is IGNORED — it is expected to fail; we never branch on it. Any error
// (it will error) is intentionally discarded.
func (a *Authenticator) dummyBind(c conn, password string) {
	// A DN that is well-formed but certain not to exist: a random-looking RDN
	// under the configured base. The directory still performs the bind attempt
	// (DN parse + lookup + credential check), which is the round-trip we want to
	// reproduce. We bind the SUPPLIED password, not a constant, so the work is
	// identical to a genuine wrong-password bind.
	dummyDN := fmt.Sprintf("cn=%s,%s", dummyBindRDN, a.cfg.BaseDN)
	_ = c.Bind(dummyDN, password)
}

// dummyBindRDN is the fixed RDN value used to synthesize the non-existent DN in
// dummyBind. It contains no user-controlled input (so it cannot itself be an
// injection vector) and is the kind of value that will not collide with a real
// account.
const dummyBindRDN = "ldap-nonexistent-timing-parity-probe"

// resolveGroups returns the user's group memberships, by whichever path the
// config selected: the memberOf-style values already captured off the user
// entry during searchUser (preferred, no extra search — passed in as memberOf),
// else a reverse-membership second search under GroupBaseDN. Returns nil with
// no error when group resolution is not configured. INJECTION DEFENSE in the
// second-search path mirrors searchUser: the user DN / username placed into
// GroupFilter is escaped with ldap.EscapeFilter.
func (a *Authenticator) resolveGroups(c conn, userDN, username string, memberOf []string) ([]string, error) {
	// memberOf path (preferred): the values were read off the user entry in the
	// single user search; no second round-trip, and no shared state on the
	// Authenticator (the slice was threaded through return values).
	if a.cfg.GroupAttribute != "" {
		return memberOf, nil
	}

	if a.cfg.GroupBaseDN == "" || a.cfg.GroupFilter == "" {
		return nil, nil // group resolution not configured
	}

	// Reverse-membership second search. The %s in GroupFilter is the user DN for
	// groupOfNames(member=) or the username for posixGroup(memberUid=); the
	// operator picks which by how they wrote the filter. We escape BOTH the DN
	// and the username and substitute whichever the single placeholder expects —
	// since we cannot know which, we escape the value the operator's filter is
	// built around. The convention: a filter mentioning "member" wants the DN; a
	// filter mentioning "memberUid" wants the username. We default to the DN
	// (the groupOfNames model) and fall back to username only for memberUid.
	value := userDN
	if strings.Contains(strings.ToLower(a.cfg.GroupFilter), "memberuid") {
		value = username
	}
	filter := fmt.Sprintf(a.cfg.GroupFilter, ldap.EscapeFilter(value))

	req := ldap.NewSearchRequest(
		a.cfg.GroupBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // group count is naturally bounded by the directory; no artificial cap
		0,
		false,
		filter,
		[]string{a.cfg.groupNameAttribute()},
		nil,
	)
	sr, err := c.Search(req)
	if err != nil {
		return nil, fmt.Errorf("group search: %w", err)
	}
	groups := make([]string, 0, len(sr.Entries))
	for _, e := range sr.Entries {
		if name := e.GetAttributeValue(a.cfg.groupNameAttribute()); name != "" {
			groups = append(groups, name)
		}
	}
	return groups, nil
}

// joinGroups renders the resolved group list into the single Attributes string
// value.
func joinGroups(groups []string) string {
	return strings.Join(groups, groupsSeparator)
}
