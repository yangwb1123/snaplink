package kerberosauth

import (
	"errors"
	"strings"
)

// DefaultMountPath is where the Negotiate handler is mounted when Config.Path
// is empty. It is a credential-bearing endpoint (it mints SSO tokens), so it
// lives under /auth like /auth/login and the SAML ACS.
const DefaultMountPath = "/auth/kerberos"

// Default attribute keys the handler writes onto the minted Subject /
// AuthResult when the corresponding AttributeMapping entry is unset. They are
// the local (server-side) attribute names — the same vocabulary the other
// authenticators emit — NOT Kerberos wire names.
const (
	// defaultRealmAttr is the AuthResult attribute key the validated Kerberos
	// realm is written under. A consumer can branch authorization on the realm
	// (the Kerberos security domain) the principal authenticated against.
	defaultRealmAttr = "krb5_realm"

	// defaultGroupsAttr is the AuthResult attribute key the validated PAC group
	// SIDs are written under (comma-joined). Present only when the service
	// ticket carried a PAC (Active Directory) AND DisablePAC is false.
	defaultGroupsAttr = "krb5_groups"
)

// Config describes one Kerberos/SPNEGO (Windows Integrated Authentication /
// desktop SSO) login surface. The operator's forked cmd builds it, constructs
// the prod gokrb5 validator from the keytab, and wires the resulting
// HandlerSpec via srv.Handle (see the package doc).
//
// SECURITY: the keytab (KeytabPath / KeytabBytes) is a HIGH-VALUE SECRET — it
// holds the long-term key of the server's Kerberos service principal, the
// trust anchor every SPNEGO token is validated against. It is loaded ONCE at
// construction, NEVER logged, and NEVER placed in an error or response. A
// forged/expired/wrong-realm SPNEGO token that cannot be validated against
// this keytab NEVER authenticates (fail-closed; see validator.go).
type Config struct {
	// Name is the authenticator/provider name. It is the AuthResult.Provider +
	// Subject.Provider value the minted tokens carry, and the audit provider
	// label. REQUIRED. (Unlike the password/LDAP authenticators it is NOT a
	// /auth/login?provider= selector — SPNEGO is a Negotiate-header flow on its
	// own mounted endpoint, not an sso.Authenticator.)
	Name string

	// KeytabPath is the filesystem path to the service keytab holding the key
	// for ServicePrincipal (e.g. "/etc/sso/http.keytab"). Exactly one of
	// KeytabPath or KeytabBytes is REQUIRED. The prod validator loads it once;
	// a down/missing file fails construction CLOSED (boot fails loud), never at
	// request time.
	KeytabPath string

	// KeytabBytes is the raw keytab content, an alternative to KeytabPath for
	// operators who inject the keytab from a secret manager (Vault, k8s Secret)
	// rather than a file. Exactly one of KeytabPath / KeytabBytes is REQUIRED.
	// Treated with the same secrecy as KeytabPath: never logged, never in an
	// error/response.
	KeytabBytes []byte

	// ServicePrincipal is the SPN the keytab holds the key for, in the Kerberos
	// "HTTP/host@REALM" (or just "HTTP/host") form — e.g.
	// "HTTP/sso.example.com" or "HTTP/sso.example.com@EXAMPLE.COM". It is
	// passed to gokrb5 as the KeytabPrincipal so the AP-REQ is validated
	// against the RIGHT key when the keytab holds several (the common AD case).
	// REQUIRED.
	ServicePrincipal string

	// Realm is the Kerberos realm (e.g. "EXAMPLE.COM") this surface accepts
	// principals from. REQUIRED. After gokrb5 validates the ticket against the
	// keytab, the handler additionally REJECTS any authenticated principal
	// whose realm does not equal this value (case-insensitive) — defense in
	// depth so a keytab that happens to trust a cross-realm principal still
	// only mints for the configured realm.
	Realm string

	// ClientID is the registered sso.Client the handler mints tokens for. The
	// SPNEGO flow has no client-supplied client_id (the browser only sends the
	// Negotiate header), so the surface is bound to ONE client at config time.
	// REQUIRED; resolved fresh from the ClientStore per request (so an inactive
	// or deleted client fails the mint, never a stale cache).
	ClientID string

	// AttributeMapping renames the well-known derived attributes the handler
	// writes onto the AuthResult/Subject. Key = the derived attribute
	// ("realm" or "groups"); value = the local attribute key to store it under.
	// Empty / a missing key ⇒ the defaults (krb5_realm, krb5_groups). Only
	// these two derived attributes are ever emitted — a Kerberos ticket cannot
	// smuggle an arbitrary attribute onto the token.
	AttributeMapping map[string]string

	// DisablePAC turns OFF decoding of the AD PAC (Privilege Attribute
	// Certificate) carried in the service ticket. The PAC is what yields the
	// principal's group SIDs; decoding it requires the KDC's key material in
	// the keytab and adds work per request. Default false (PAC decoded when
	// present — the common AD desktop-SSO case wants groups). Set true for a
	// pure-MIT-Kerberos KDC (no PAC) or when groups aren't needed; the
	// principal + realm still authenticate.
	DisablePAC bool

	// Path is where the Negotiate handler is mounted. Empty ⇒ DefaultMountPath
	// ("/auth/kerberos"). The operator mounts the returned HandlerSpec at this
	// path via srv.Handle.
	Path string
}

// Validate checks the REQUIRED fields, failing the operator's boot CLOSED on a
// misconfiguration — a credential-validation gate with no keytab, no service
// principal, no realm, or no client to mint for is not a runtime warning but a
// security/wiring regression. It performs NO I/O (the keytab is loaded by the
// prod validator constructor, so a down keytab fails there, not here).
func (c *Config) Validate() error {
	if c.Name == "" {
		return errors.New("kerberos: Name required")
	}
	// Exactly one keytab source. Neither ⇒ nothing to validate tokens against
	// (every token would have to be trusted blindly — the auth-bypass hole);
	// both ⇒ ambiguous which the operator meant.
	hasPath := strings.TrimSpace(c.KeytabPath) != ""
	hasBytes := len(c.KeytabBytes) > 0
	switch {
	case !hasPath && !hasBytes:
		return errors.New("kerberos: a keytab is required (set KeytabPath or KeytabBytes) — it is the trust anchor every SPNEGO token is validated against")
	case hasPath && hasBytes:
		return errors.New("kerberos: set only one of KeytabPath or KeytabBytes, not both")
	}
	if strings.TrimSpace(c.ServicePrincipal) == "" {
		return errors.New("kerberos: ServicePrincipal required (e.g. HTTP/sso.example.com)")
	}
	if strings.TrimSpace(c.Realm) == "" {
		return errors.New("kerberos: Realm required (e.g. EXAMPLE.COM)")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("kerberos: ClientID required (the registered client tokens are minted for)")
	}
	return nil
}

// mountPath returns the configured mount path or the default.
func (c *Config) mountPath() string {
	if p := strings.TrimSpace(c.Path); p != "" {
		return p
	}
	return DefaultMountPath
}

// realmAttr / groupsAttr resolve the local attribute key for each derived
// attribute, honoring AttributeMapping with the default fallback.
func (c *Config) realmAttr() string {
	if c.AttributeMapping != nil {
		if k := strings.TrimSpace(c.AttributeMapping["realm"]); k != "" {
			return k
		}
	}
	return defaultRealmAttr
}

func (c *Config) groupsAttr() string {
	if c.AttributeMapping != nil {
		if k := strings.TrimSpace(c.AttributeMapping["groups"]); k != "" {
			return k
		}
	}
	return defaultGroupsAttr
}
