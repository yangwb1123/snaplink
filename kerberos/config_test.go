package kerberosauth_test

import (
	"strings"
	"testing"

	kerberosauth "github.com/snaplink/sso/kerberos"
)

func validConfig() kerberosauth.Config {
	return kerberosauth.Config{
		Name:             "kerberos",
		KeytabBytes:      []byte("kt"),
		ServicePrincipal: "HTTP/sso.example.com",
		Realm:            "EXAMPLE.COM",
		ClientID:         "kiosk-app",
	}
}

// TestConfigValidate covers the required-field matrix: each missing REQUIRED
// field fails CLOSED (a credential-validation gate misconfiguration is a
// security regression, not a runtime warning).
func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*kerberosauth.Config)
		wantErr string
	}{
		{"valid (keytab bytes)", func(c *kerberosauth.Config) {}, ""},
		{"valid (keytab path)", func(c *kerberosauth.Config) {
			c.KeytabBytes = nil
			c.KeytabPath = "/etc/sso/http.keytab"
		}, ""},
		{"missing name", func(c *kerberosauth.Config) { c.Name = "" }, "Name required"},
		{"no keytab at all", func(c *kerberosauth.Config) {
			c.KeytabBytes = nil
			c.KeytabPath = ""
		}, "keytab is required"},
		{"both keytab sources", func(c *kerberosauth.Config) {
			c.KeytabPath = "/etc/sso/http.keytab" // bytes already set
		}, "only one of KeytabPath or KeytabBytes"},
		{"missing service principal", func(c *kerberosauth.Config) { c.ServicePrincipal = "" }, "ServicePrincipal required"},
		{"missing realm", func(c *kerberosauth.Config) { c.Realm = "" }, "Realm required"},
		{"missing client_id", func(c *kerberosauth.Config) { c.ClientID = "" }, "ClientID required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
