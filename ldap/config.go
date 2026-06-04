package ldapauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Default* fill the corresponding zero-valued Config fields. The timeouts
// bound the dial and per-operation (bind/search) round-trips so a slow or
// dead directory cannot hang a login indefinitely.
const (
	// DefaultDialTimeout caps the TCP/TLS connect to one directory URL. With
	// failover (multiple URLs) the WORST-CASE total connect time is
	// len(URLs) * DialTimeout, so keep it modest.
	DefaultDialTimeout = 5 * time.Second

	// DefaultRequestTimeout caps each LDAP operation (bind, search) once
	// connected. go-ldap's Conn.SetTimeout applies it per request.
	DefaultRequestTimeout = 10 * time.Second

	// DefaultUserFilter matches a person entry by the standard RFC 4519 uid
	// attribute. The %s placeholder is replaced with the ldap.EscapeFilter'd
	// username at search time — NEVER the raw username (LDAP injection).
	DefaultUserFilter = "(&(objectClass=person)(uid=%s))"

	// DefaultIDAttribute is the directory attribute read back as the stable
	// AuthResult.ExternalID. uid for RFC 4519 / posixAccount directories;
	// Active Directory operators typically override with sAMAccountName or
	// objectGUID.
	DefaultIDAttribute = "uid"

	// usernamePlaceholder is the single token a UserFilter MUST contain so the
	// escaped username can be substituted. fmt-style %s keeps the operator's
	// mental model identical to the go-ldap docs.
	usernamePlaceholder = "%s"
)

// Config describes one upstream LDAP / Active Directory directory this server
// authenticates users against. One Config yields one Authenticator; an
// operator may wire several (one per directory), selected at /auth/login by
// provider=<Name>.
//
// SECURITY: BindPassword (the service-account secret) and the end-user's
// password are credentials — they are sent ONLY over a TLS-protected
// connection to the directory and are NEVER logged, NEVER placed on the
// returned AuthResult, and NEVER stamped into a token.
type Config struct {
	// Name is the authenticator name + the value clients pass in
	// provider=<name> to choose this directory at /auth/login. It is also the
	// AuthResult.Provider value. REQUIRED.
	Name string

	// URLs are the directory endpoints, tried in order for FAILOVER (the first
	// that DIALS wins; a dial failure falls through to the next). Each is a
	// standard LDAP URL: "ldaps://dc1.corp.example.com:636" (implicit TLS) or
	// "ldap://dc1.corp.example.com:389" (plaintext, requires StartTLS — see
	// the TLS gate in Validate). At least one is REQUIRED.
	URLs []string

	// BindDN + BindPassword are the SERVICE ACCOUNT used for the search leg
	// (step 1 of search-then-bind): a low-privilege read-only account that can
	// resolve a username to its entry DN. Empty BindDN ⇒ an ANONYMOUS search
	// bind (only works on directories that permit anonymous search — most AD
	// deployments do not). The end-user is NEVER authenticated with these
	// credentials; they only locate the user's DN.
	BindDN       string
	BindPassword string

	// BaseDN is the search base under which user entries live, e.g.
	// "ou=people,dc=corp,dc=example,dc=com". REQUIRED.
	BaseDN string

	// UserFilter is the RFC 4515 search filter locating the user entry. It
	// MUST contain exactly one %s placeholder, replaced at search time with
	// the ldap.EscapeFilter'd username (NEVER the raw username — that is the
	// LDAP-injection hole). Empty ⇒ DefaultUserFilter. Examples:
	//
	//	(&(objectClass=person)(uid=%s))                  # OpenLDAP / posix
	//	(&(objectClass=user)(sAMAccountName=%s))         # Active Directory
	//	(&(objectClass=inetOrgPerson)(mail=%s))          # login by email
	UserFilter string

	// IDAttribute is the entry attribute read back as the stable
	// AuthResult.ExternalID (the user's durable directory identifier). Empty ⇒
	// DefaultIDAttribute ("uid"). AD operators usually set "sAMAccountName" or
	// the immutable "objectGUID". If the attribute is absent on the entry the
	// entry DN is used as a fallback so ExternalID is never empty.
	IDAttribute string

	// AttributeMapping projects directory attributes onto AuthResult.Attributes
	// keys this server uses. Key = the LDAP attribute name as the directory
	// emits it (e.g. "mail", "displayName"); value = the local attribute key
	// (e.g. "email", "name"). Only the listed attributes are requested + read;
	// nothing is passed through implicitly, so a directory cannot smuggle an
	// unexpected attribute onto the AuthResult. Empty ⇒ no attributes mapped
	// (only ExternalID + groups are populated).
	AttributeMapping map[string]string

	// GroupAttribute, when set, is the entry attribute carrying the user's
	// group memberships read DIRECTLY off the user entry — typically "memberOf"
	// (Active Directory + the OpenLDAP memberof overlay). Each value is a group
	// DN string. This is the cheap, no-second-search path and is preferred when
	// available. Empty + no GroupBaseDN ⇒ groups are not resolved.
	GroupAttribute string

	// GroupBaseDN + GroupFilter perform a SECOND search to resolve groups that
	// reference the user (the reverse-membership / RFC 4519 "member" model used
	// by groupOfNames / posixGroup). GroupFilter MUST contain a %s placeholder
	// replaced with the ldap.EscapeFilter'd user DN (groupOfNames) or username
	// (posixGroup) — again NEVER the raw value. Only consulted when
	// GroupAttribute is empty (memberOf is preferred). Examples:
	//
	//	GroupBaseDN: "ou=groups,dc=corp,dc=example,dc=com"
	//	GroupFilter: "(&(objectClass=groupOfNames)(member=%s))"   # %s = user DN
	//	GroupFilter: "(&(objectClass=posixGroup)(memberUid=%s))"  # %s = username
	GroupBaseDN string
	GroupFilter string

	// GroupNameAttribute is the attribute read from each matched group entry as
	// its name (e.g. "cn"). Only used by the GroupBaseDN/GroupFilter second-
	// search path. Empty ⇒ "cn". (The GroupAttribute/memberOf path yields raw
	// group DN strings; this does not apply there.)
	GroupNameAttribute string

	// StartTLS, when true, dials a plaintext ldap:// connection and immediately
	// upgrades it to TLS via the StartTLS extended operation (RFC 4513) before
	// ANY bind — so credentials never traverse the wire in plaintext. Mutually
	// compatible with ldaps:// URLs is discouraged (ldaps:// is already TLS);
	// use StartTLS with ldap:// URLs. Either ldaps:// OR StartTLS is REQUIRED
	// unless AllowInsecure is set.
	StartTLS bool

	// TLSConfig is an OPTIONAL fully-formed *tls.Config for the ldaps:// /
	// StartTLS connection. When nil a config is built from CACertPEM +
	// ServerName + InsecureSkipVerify below. When non-nil it is used verbatim
	// (the operator owns it). The directory's certificate is ALWAYS verified
	// unless InsecureSkipVerify / AllowInsecure is set.
	TLSConfig *tls.Config

	// CACertPEM is an OPTIONAL PEM bundle of CA certificate(s) that signed the
	// directory's TLS certificate, for directories using a private/enterprise
	// CA not in the system trust store. Empty ⇒ the system roots. Ignored when
	// TLSConfig is supplied.
	CACertPEM []byte

	// ServerName overrides the TLS SNI / certificate-name verification host.
	// Empty ⇒ the host from the dialed URL. Ignored when TLSConfig is supplied.
	ServerName string

	// InsecureSkipVerify disables TLS certificate verification on the ldaps:// /
	// StartTLS connection. DANGEROUS — a man-in-the-middle can then harvest
	// every credential. Permitted ONLY for development against a self-signed
	// directory, and ONLY together with AllowInsecure (so an operator cannot
	// trip it without also acknowledging the broader insecure posture). Ignored
	// when TLSConfig is supplied.
	InsecureSkipVerify bool

	// AllowInsecure opts OUT of the TLS-required gate, permitting plaintext
	// ldap:// without StartTLS (and permitting InsecureSkipVerify). This sends
	// the service-account AND end-user passwords in CLEARTEXT — it exists only
	// for local development / a trusted-network test directory and MUST NEVER be
	// set in production. Default false: Validate rejects a non-TLS config.
	AllowInsecure bool

	// DialTimeout caps the TCP/TLS connect to one URL. Zero ⇒ DefaultDialTimeout.
	DialTimeout time.Duration

	// RequestTimeout caps each LDAP operation (bind, search) once connected.
	// Zero ⇒ DefaultRequestTimeout.
	RequestTimeout time.Duration
}

// Validate checks the required fields and — critically — the TLS gate and the
// filter-placeholder invariant, failing the operator's boot CLOSED on a
// misconfiguration (a directory-auth gate that silently sent credentials in
// plaintext, or a filter missing its placeholder, would be a security
// regression, not a runtime warning).
func (c *Config) Validate() error {
	if c.Name == "" {
		return errors.New("ldap: Name required")
	}
	if len(c.URLs) == 0 {
		return errors.New("ldap: at least one URL required")
	}
	if c.BaseDN == "" {
		return errors.New("ldap: BaseDN required")
	}

	// A BindDN with no password is almost always a misconfiguration that would
	// silently degrade to an UNAUTHENTICATED bind (RFC 4513 §5.1.2: a non-empty
	// DN with an empty password is an unauthenticated bind, which many
	// directories accept and which then runs the "service" search with
	// anonymous rights). Reject it rather than let the search leg run with
	// surprising privileges. Anonymous search (empty BindDN) stays allowed.
	if c.BindDN != "" && c.BindPassword == "" {
		return errors.New("ldap: BindPassword required when BindDN is set (an empty password is an unauthenticated bind)")
	}

	tlsConfigured := c.TLSConfig != nil
	scheme, err := c.urlsScheme()
	if err != nil {
		return err
	}
	usesLDAPS := scheme == "ldaps"

	// TLS gate: credentials (service-account + end-user passwords) must travel
	// over TLS. Satisfied by ldaps:// URLs, by StartTLS on ldap:// URLs, or by
	// an operator-supplied TLSConfig (which implies they intend TLS). Only an
	// explicit AllowInsecure opt-out (dev only) bypasses it.
	if !usesLDAPS && !c.StartTLS && !tlsConfigured && !c.AllowInsecure {
		return errors.New("ldap: TLS required — use an ldaps:// URL, set StartTLS, or supply TLSConfig (set AllowInsecure only for development)")
	}
	// InsecureSkipVerify is itself a credential-exposure footgun: gate it behind
	// the same explicit AllowInsecure acknowledgement so it can't be set in
	// isolation. (An operator-supplied TLSConfig owns its own verification, so
	// this only governs the built-from-fields path.)
	if c.InsecureSkipVerify && !c.AllowInsecure && !tlsConfigured {
		return errors.New("ldap: InsecureSkipVerify requires AllowInsecure (it disables certificate verification — development only)")
	}

	filter := c.UserFilter
	if filter == "" {
		filter = DefaultUserFilter
	}
	if !strings.Contains(filter, usernamePlaceholder) {
		// Without the placeholder the username would never be substituted — the
		// filter would match the same (wrong) set for every login. A
		// configuration this broken must fail loud at boot.
		return fmt.Errorf("ldap: UserFilter must contain the %q username placeholder, got %q", usernamePlaceholder, filter)
	}
	// Reject MULTIPLE placeholders: substitution uses fmt.Sprintf with a single
	// argument, so a second %s would render as "%!s(MISSING)" and silently
	// corrupt the filter. One, and only one.
	if strings.Count(filter, usernamePlaceholder) != 1 {
		return fmt.Errorf("ldap: UserFilter must contain exactly one %q placeholder, got %q", usernamePlaceholder, filter)
	}

	// The GroupFilter placeholder discipline is validated UNCONDITIONALLY whenever
	// a GroupFilter is set — even alongside GroupAttribute (a misconfig where the
	// memberOf path wins and the GroupFilter is dead config). Previously this
	// check was nested under `GroupAttribute == ""`, so a GroupFilter with a wrong
	// placeholder count set next to a GroupAttribute passed boot SILENTLY; if the
	// operator later removed GroupAttribute the broken filter would surface only
	// at runtime as a corrupted "%!s(MISSING)" filter. Fail loud at boot instead.
	if c.GroupFilter != "" && strings.Count(c.GroupFilter, usernamePlaceholder) != 1 {
		return fmt.Errorf("ldap: GroupFilter must contain exactly one %q placeholder, got %q", usernamePlaceholder, c.GroupFilter)
	}

	// The group second-search path (only taken when GroupAttribute is empty) needs
	// BOTH its base and its filter — one without the other can't perform the
	// reverse-membership search. (The placeholder count is already enforced above.)
	if c.GroupAttribute == "" && (c.GroupBaseDN != "" || c.GroupFilter != "") {
		if c.GroupBaseDN == "" || c.GroupFilter == "" {
			return errors.New("ldap: GroupBaseDN and GroupFilter must both be set for group-search resolution")
		}
	}
	return nil
}

// urlsScheme validates every URL parses and returns the COMMON scheme. Mixed
// schemes (some ldaps://, some ldap://) are rejected — the TLS posture must be
// uniform across the failover set, or a failover hop could silently downgrade
// from TLS to plaintext.
func (c *Config) urlsScheme() (string, error) {
	var scheme string
	for _, raw := range c.URLs {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return "", fmt.Errorf("ldap: parse URL %q: %w", raw, err)
		}
		s := strings.ToLower(u.Scheme)
		if s != "ldap" && s != "ldaps" {
			return "", fmt.Errorf("ldap: URL %q must use the ldap:// or ldaps:// scheme", raw)
		}
		if u.Host == "" {
			return "", fmt.Errorf("ldap: URL %q must include a host", raw)
		}
		if scheme == "" {
			scheme = s
		} else if scheme != s {
			return "", errors.New("ldap: all URLs must use the same scheme (do not mix ldap:// and ldaps:// — a failover hop could downgrade TLS)")
		}
	}
	return scheme, nil
}

// tlsConfig returns the *tls.Config for the ldaps:// / StartTLS connection: the
// operator-supplied one verbatim when set, else one built from CACertPEM +
// ServerName + InsecureSkipVerify. serverHost is the host parsed from the
// dialed URL, used as the SNI / verification name when ServerName is unset.
func (c *Config) tlsConfig(serverHost string) (*tls.Config, error) {
	if c.TLSConfig != nil {
		return c.TLSConfig, nil
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.InsecureSkipVerify, // gated behind AllowInsecure in Validate
		ServerName:         c.ServerName,
	}
	if cfg.ServerName == "" {
		cfg.ServerName = serverHost
	}
	if len(c.CACertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(c.CACertPEM) {
			return nil, errors.New("ldap: CACertPEM contained no valid PEM certificate")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func (c *Config) dialTimeout() time.Duration {
	if c.DialTimeout > 0 {
		return c.DialTimeout
	}
	return DefaultDialTimeout
}

func (c *Config) requestTimeout() time.Duration {
	if c.RequestTimeout > 0 {
		return c.RequestTimeout
	}
	return DefaultRequestTimeout
}

func (c *Config) userFilter() string {
	if c.UserFilter != "" {
		return c.UserFilter
	}
	return DefaultUserFilter
}

func (c *Config) idAttribute() string {
	if c.IDAttribute != "" {
		return c.IDAttribute
	}
	return DefaultIDAttribute
}

func (c *Config) groupNameAttribute() string {
	if c.GroupNameAttribute != "" {
		return c.GroupNameAttribute
	}
	return "cn"
}
