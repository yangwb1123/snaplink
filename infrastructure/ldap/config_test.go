package ldapauth

import (
	"crypto/tls"
	"strings"
	"testing"
)

// baseValidCfg is a minimal config that passes Validate (ldaps:// satisfies the
// TLS gate). Tests mutate a copy to exercise each rule.
func baseValidCfg() Config {
	return Config{
		Name:         "dir",
		URLs:         []string{"ldaps://dir.example.com:636"},
		BaseDN:       "dc=example,dc=com",
		BindDN:       "cn=svc,dc=example,dc=com",
		BindPassword: "secret",
		UserFilter:   "(uid=%s)",
		IDAttribute:  "uid",
	}
}

func TestValidate_OK(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidate_RequiresName(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.Name = ""
	mustValidateErr(t, c, "Name")
}

func TestValidate_RequiresURL(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.URLs = nil
	mustValidateErr(t, c, "URL")
}

func TestValidate_RequiresBaseDN(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.BaseDN = ""
	mustValidateErr(t, c, "BaseDN")
}

// THE TLS GATE: a plain ldap:// without StartTLS and without AllowInsecure
// must be REJECTED — TLS settings alone do not prevent plaintext credentials.
func TestValidate_TLSRequired_PlainLDAPRejected(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.URLs = []string{"ldap://dir.example.com:389"}
	mustValidateErr(t, c, "TLS required")
}

func TestValidate_TLS_StartTLSSatisfiesGate(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.URLs = []string{"ldap://dir.example.com:389"}
	c.StartTLS = true
	if err := c.Validate(); err != nil {
		t.Fatalf("ldap:// + StartTLS rejected: %v", err)
	}
}

func TestValidate_TLS_AllowInsecureOptOut(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.URLs = []string{"ldap://dir.example.com:389"}
	c.AllowInsecure = true
	if err := c.Validate(); err != nil {
		t.Fatalf("ldap:// + AllowInsecure rejected: %v", err)
	}
}

func TestValidate_TLS_SuppliedTLSConfigRequiresTransport(t *testing.T) {
	t.Parallel()
	for _, urls := range [][]string{
		{"ldap://dir.example.com:389"},
		{"ldap://dir.example.com:389", "ldap://backup.example.com:389"},
	} {
		c := baseValidCfg()
		c.URLs = urls
		c.TLSConfig = &tls.Config{ServerName: "dir.example.com"}
		mustValidateErr(t, c, "TLS required")
	}
}

func TestValidate_TLS_SuppliedTLSConfigWithTransport(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		url           string
		startTLS      bool
		allowInsecure bool
	}{
		{name: "LDAPS", url: "ldaps://dir.example.com:636"},
		{name: "StartTLS", url: "ldap://dir.example.com:389", startTLS: true},
		{name: "development opt-out", url: "ldap://dir.example.com:389", allowInsecure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseValidCfg()
			c.URLs = []string{tc.url}
			c.StartTLS = tc.startTLS
			c.AllowInsecure = tc.allowInsecure
			c.TLSConfig = &tls.Config{ServerName: "dir.example.com"}
			if err := c.Validate(); err != nil {
				t.Fatalf("explicit transport policy with TLSConfig rejected: %v", err)
			}
			a, err := New(c)
			if err != nil {
				t.Fatalf("New rejected explicit transport policy with TLSConfig: %v", err)
			}
			if a.cfg.StartTLS != c.StartTLS || a.cfg.AllowInsecure != c.AllowInsecure || a.cfg.TLSConfig != c.TLSConfig {
				t.Error("New changed the explicit transport policy or supplied TLSConfig")
			}
		})
	}
}

func TestNew_TLSConfigOnly_FailsClosedBeforeDial(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.URLs = []string{"ldap://dir.example.com:389"}
	c.TLSConfig = &tls.Config{ServerName: "dir.example.com"}
	d := &fakeDialer{dir: newFakeDirectory()}
	a, err := New(c, withDialer(d))
	if err == nil || !strings.Contains(err.Error(), "TLS required") {
		t.Errorf("New must reject TLSConfig-only plaintext with TLS required, got err = %v", err)
	}
	if a != nil {
		t.Error("New returned an authenticator for TLSConfig-only plaintext")
	}
	if len(d.dialed) != 0 {
		t.Errorf("New performed %d dials before rejecting the config", len(d.dialed))
	}
}

// InsecureSkipVerify alone (without AllowInsecure) must be rejected on the
// built-from-fields path — it disables certificate verification.
func TestValidate_InsecureSkipVerify_NeedsAllowInsecure(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.InsecureSkipVerify = true
	mustValidateErr(t, c, "InsecureSkipVerify")
}

func TestValidate_InsecureSkipVerify_WithAllowInsecure_OK(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.URLs = []string{"ldap://dir.example.com:389"}
	c.InsecureSkipVerify = true
	c.AllowInsecure = true
	if err := c.Validate(); err != nil {
		t.Fatalf("InsecureSkipVerify + AllowInsecure rejected: %v", err)
	}
}

// THE FILTER PLACEHOLDER GATE: a filter without %s would never substitute the
// username and must be rejected.
func TestValidate_UserFilter_RequiresPlaceholder(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.UserFilter = "(objectClass=person)"
	mustValidateErr(t, c, "placeholder")
}

func TestValidate_UserFilter_RejectsMultiplePlaceholders(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.UserFilter = "(|(uid=%s)(mail=%s))"
	mustValidateErr(t, c, "exactly one")
}

func TestValidate_DefaultFilterUsedWhenEmpty(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.UserFilter = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("empty UserFilter (should default) rejected: %v", err)
	}
	if c.userFilter() != DefaultUserFilter {
		t.Errorf("userFilter() = %q, want default %q", c.userFilter(), DefaultUserFilter)
	}
}

func TestValidate_BindDNWithoutPassword_Rejected(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.BindPassword = ""
	mustValidateErr(t, c, "BindPassword")
}

func TestValidate_MixedSchemes_Rejected(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.URLs = []string{"ldaps://a:636", "ldap://b:389"}
	mustValidateErr(t, c, "same scheme")
}

func TestValidate_UnknownScheme_Rejected(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.URLs = []string{"https://a:443"}
	mustValidateErr(t, c, "scheme")
}

func TestValidate_GroupSearch_BothRequired(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.GroupBaseDN = "ou=groups,dc=example,dc=com" // filter missing
	mustValidateErr(t, c, "GroupFilter")
}

func TestValidate_GroupFilter_RequiresPlaceholder(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.GroupBaseDN = "ou=groups,dc=example,dc=com"
	c.GroupFilter = "(objectClass=groupOfNames)" // no %s
	mustValidateErr(t, c, "GroupFilter")
}

func TestValidate_MemberOfPath_NoGroupSearchRequired(t *testing.T) {
	t.Parallel()
	// With GroupAttribute set (memberOf), GroupBaseDN/Filter are not needed.
	c := baseValidCfg()
	c.GroupAttribute = "memberOf"
	if err := c.Validate(); err != nil {
		t.Fatalf("memberOf path rejected: %v", err)
	}
}

// A GroupFilter set ALONGSIDE GroupAttribute (a misconfig: the memberOf path
// wins, the GroupFilter is dead config) must STILL have its placeholder
// validated — previously this slipped through boot silently because the check
// was nested under `GroupAttribute == ""`. A missing %s now fails loud at boot.
func TestValidate_GroupFilter_PlaceholderCheckedEvenWithGroupAttribute(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.GroupAttribute = "memberOf"
	c.GroupFilter = "(objectClass=groupOfNames)" // no %s placeholder
	mustValidateErr(t, c, "GroupFilter")
}

// Symmetric guard: a GroupFilter with MULTIPLE placeholders alongside
// GroupAttribute is also rejected (fmt.Sprintf with one arg would corrupt it).
func TestValidate_GroupFilter_MultiplePlaceholdersCheckedWithGroupAttribute(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.GroupAttribute = "memberOf"
	c.GroupFilter = "(|(memberUid=%s)(member=%s))" // two placeholders
	mustValidateErr(t, c, "exactly one")
}

// A well-formed GroupFilter (single %s) alongside GroupAttribute stays VALID —
// the unconditional check only rejects a malformed placeholder count, not the
// mere coexistence of the two fields.
func TestValidate_GroupFilter_WellFormedWithGroupAttribute_OK(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.GroupAttribute = "memberOf"
	c.GroupFilter = "(&(objectClass=posixGroup)(memberUid=%s))"
	if err := c.Validate(); err != nil {
		t.Fatalf("well-formed GroupFilter alongside GroupAttribute rejected: %v", err)
	}
}

func TestValidate_ErrorOrderPreserved(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "name before URLs",
			mutate: func(c *Config) {
				c.Name, c.URLs = "", nil
			},
			want: "ldap: Name required",
		},
		{
			name: "URLs before base",
			mutate: func(c *Config) {
				c.URLs, c.BaseDN = nil, ""
			},
			want: "ldap: at least one URL required",
		},
		{
			name: "base before service password",
			mutate: func(c *Config) {
				c.BaseDN, c.BindPassword = "", ""
			},
			want: "ldap: BaseDN required",
		},
		{
			name: "service password before URL scheme",
			mutate: func(c *Config) {
				c.BindPassword = ""
				c.URLs = []string{"https://dir.example.com"}
			},
			want: "ldap: BindPassword required when BindDN is set (an empty password is an unauthenticated bind)",
		},
		{
			name: "common scheme before TLS admission",
			mutate: func(c *Config) {
				c.URLs = []string{"ldap://first.example.com:389", "ldaps://second.example.com:636"}
			},
			want: "ldap: all URLs must use the same scheme (do not mix ldap:// and ldaps:// — a failover hop could downgrade TLS)",
		},
		{
			name: "TLS admission before verification and filters",
			mutate: func(c *Config) {
				c.URLs = []string{"ldap://dir.example.com:389"}
				c.InsecureSkipVerify = true
				c.UserFilter = "(objectClass=person)"
			},
			want: "ldap: TLS required — use an ldaps:// URL or set StartTLS (set AllowInsecure only for development)",
		},
		{
			name: "verification before user filter",
			mutate: func(c *Config) {
				c.InsecureSkipVerify = true
				c.UserFilter = "(objectClass=person)"
			},
			want: "ldap: InsecureSkipVerify requires AllowInsecure (it disables certificate verification — development only)",
		},
		{
			name: "user filter before group filter",
			mutate: func(c *Config) {
				c.UserFilter = "(objectClass=person)"
				c.GroupFilter = "(objectClass=groupOfNames)"
			},
			want: `ldap: UserFilter must contain the "%s" username placeholder, got "(objectClass=person)"`,
		},
		{
			name: "group placeholder before search pairing",
			mutate: func(c *Config) {
				c.GroupFilter = "(objectClass=groupOfNames)"
			},
			want: `ldap: GroupFilter must contain exactly one "%s" placeholder, got "(objectClass=groupOfNames)"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseValidCfg()
			tc.mutate(&c)
			if err := c.Validate(); err == nil || err.Error() != tc.want {
				t.Errorf("Validate err = %v, want %q", err, tc.want)
			}
		})
	}
}

// New() surfaces a Validate error (boot fails closed).
func TestNew_InvalidConfig_FailsClosed(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.URLs = []string{"ldap://plaintext:389"} // TLS gate trips
	if _, err := New(c); err == nil {
		t.Fatal("New accepted an insecure (no-TLS) config — must fail closed")
	}
}

// tlsConfig builds a verifying config from CACertPEM/ServerName by default.
func TestTLSConfig_BuiltFromFields(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.ServerName = "override.example.com"
	cfg, err := c.tlsConfig("dialed.example.com")
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Error("default tlsConfig has InsecureSkipVerify=true — must verify by default")
	}
	if cfg.ServerName != "override.example.com" {
		t.Errorf("ServerName = %q, want the explicit override", cfg.ServerName)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want >= TLS1.2", cfg.MinVersion)
	}
}

func TestTLSConfig_ServerNameDefaultsToDialedHost(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	cfg, err := c.tlsConfig("dialed.example.com")
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	if cfg.ServerName != "dialed.example.com" {
		t.Errorf("ServerName = %q, want the dialed host", cfg.ServerName)
	}
}

func TestTLSConfig_BadCACert_Errors(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	c.CACertPEM = []byte("not a pem")
	if _, err := c.tlsConfig("h"); err == nil {
		t.Fatal("tlsConfig accepted a non-PEM CACertPEM")
	}
}

func TestTLSConfig_SuppliedVerbatim(t *testing.T) {
	t.Parallel()
	c := baseValidCfg()
	supplied := &tls.Config{ServerName: "mine"}
	c.TLSConfig = supplied
	got, err := c.tlsConfig("ignored")
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	if got != supplied {
		t.Error("tlsConfig did not return the operator-supplied config verbatim")
	}
}

func mustValidateErr(t *testing.T, c Config, wantSubstr string) {
	t.Helper()
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate accepted an invalid config, want error containing %q", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Errorf("Validate err = %q, want substring %q", err.Error(), wantSubstr)
	}
}
