package sp

import (
	"strings"
	"testing"
)

func TestSPConfig_Validate(t *testing.T) {
	t.Parallel()
	base := func() SPConfig {
		return SPConfig{
			Name:        "idp",
			EntityID:    "https://sp/meta",
			ACSURL:      "https://sp/acs",
			IDPCert:     []byte("dummy"),
			IDPEntityID: "https://idp",
		}
	}
	cases := []struct {
		name    string
		mutate  func(c *SPConfig)
		wantErr string // substring; "" = no error
	}{
		{"valid_cert_anchor", func(c *SPConfig) {}, ""},
		{"valid_metadata_xml", func(c *SPConfig) {
			c.IDPCert, c.IDPEntityID = nil, ""
			c.IDPMetadataXML = []byte("<xml/>")
		}, ""},
		{"valid_metadata_url", func(c *SPConfig) {
			c.IDPCert, c.IDPEntityID = nil, ""
			c.IDPMetadataURL = "https://idp/meta"
		}, ""},
		{"missing_name", func(c *SPConfig) { c.Name = "" }, "Name required"},
		{"missing_entityid", func(c *SPConfig) { c.EntityID = "" }, "EntityID required"},
		{"missing_acsurl", func(c *SPConfig) { c.ACSURL = "" }, "ACSURL required"},
		{"no_trust_anchor", func(c *SPConfig) { c.IDPCert, c.IDPEntityID = nil, "" }, "trust anchor is required"},
		{"two_trust_anchors", func(c *SPConfig) { c.IDPMetadataURL = "https://idp/meta" }, "exactly one"},
		{"cert_without_idp_entityid", func(c *SPConfig) { c.IDPEntityID = "" }, "IDPEntityID required"},
		{"sign_without_key", func(c *SPConfig) { c.SignAuthnRequests = true }, "SignAuthnRequests requires SPPrivateKey"},
		{"key_without_cert", func(c *SPConfig) { c.SPPrivateKey = []byte("k") }, "SPCert required"},
		// IDPSLOResponseURL: embedded as a 302 Location, so it must be absolute https.
		{"slo_response_url_https_ok", func(c *SPConfig) { c.IDPSLOResponseURL = "https://idp/saml/slo/continue" }, ""},
		{"slo_response_url_empty_ok", func(c *SPConfig) { c.IDPSLOResponseURL = "" }, ""},
		{"slo_response_url_http_rejected", func(c *SPConfig) { c.IDPSLOResponseURL = "http://idp/saml/slo/continue" }, "absolute https URL"},
		{"slo_response_url_file_rejected", func(c *SPConfig) { c.IDPSLOResponseURL = "file:///etc/passwd" }, "absolute https URL"},
		{"slo_response_url_relative_rejected", func(c *SPConfig) { c.IDPSLOResponseURL = "/saml/slo/continue" }, "absolute https URL"},
		{"slo_response_url_hostless_rejected", func(c *SPConfig) { c.IDPSLOResponseURL = "https:///nohost" }, "absolute https URL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base()
			c.mutate(&cfg)
			err := cfg.Validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, c.wantErr)
			}
		})
	}
}
