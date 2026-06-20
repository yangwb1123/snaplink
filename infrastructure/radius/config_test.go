package radiusauth

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// baseValidCfg is a minimal config that passes Validate.
func baseValidCfg() Config {
	return Config{
		Name:         "nps",
		Servers:      []string{"radius.example.com:1812"},
		SharedSecret: "s3cret",
	}
}

func TestValidate_OK(t *testing.T) {
	c := baseValidCfg()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidate_RequiresName(t *testing.T) {
	c := baseValidCfg()
	c.Name = ""
	mustValidateErr(t, c, "Name")
}

func TestValidate_RequiresServer(t *testing.T) {
	c := baseValidCfg()
	c.Servers = nil
	mustValidateErr(t, c, "server")
}

// THE security-anchor gate: an empty shared secret must be REJECTED — it would
// leave the PAP password effectively in the clear and the response
// unauthenticated.
func TestValidate_RequiresSharedSecret(t *testing.T) {
	c := baseValidCfg()
	c.SharedSecret = ""
	mustValidateErr(t, c, "SharedSecret")
}

func TestValidate_ServerMustHavePort(t *testing.T) {
	c := baseValidCfg()
	c.Servers = []string{"radius.example.com"} // no :port
	mustValidateErr(t, c, "host:port")
}

func TestValidate_EmptyServerEntry_Rejected(t *testing.T) {
	c := baseValidCfg()
	c.Servers = []string{"radius.example.com:1812", "  "}
	mustValidateErr(t, c, "empty")
}

func TestValidate_PAPDefault_OK(t *testing.T) {
	c := baseValidCfg()
	c.AuthProtocol = "" // defaults to PAP
	if err := c.Validate(); err != nil {
		t.Fatalf("default (PAP) rejected: %v", err)
	}
	if c.authProtocol() != AuthPAP {
		t.Errorf("authProtocol() = %q, want pap", c.authProtocol())
	}
}

func TestValidate_PAPExplicit_OK(t *testing.T) {
	c := baseValidCfg()
	c.AuthProtocol = AuthPAP
	if err := c.Validate(); err != nil {
		t.Fatalf("explicit PAP rejected: %v", err)
	}
}

func TestValidate_PAPCaseInsensitive_OK(t *testing.T) {
	c := baseValidCfg()
	c.AuthProtocol = "PAP"
	if err := c.Validate(); err != nil {
		t.Fatalf("uppercase PAP rejected: %v", err)
	}
}

// CHAP is reserved but not implemented by the stock exchanger — Validate must
// fail loud rather than silently send PAP.
func TestValidate_CHAP_RejectedByStockExchanger(t *testing.T) {
	c := baseValidCfg()
	c.AuthProtocol = AuthCHAP
	mustValidateErr(t, c, "chap")
}

func TestValidate_UnknownProtocol_Rejected(t *testing.T) {
	c := baseValidCfg()
	c.AuthProtocol = "mschapv2"
	mustValidateErr(t, c, "unknown AuthProtocol")
}

func TestValidate_RetriesLowerBound(t *testing.T) {
	c := baseValidCfg()
	c.Retries = -2
	mustValidateErr(t, c, "Retries")
}

// RadSec InsecureSkipVerify must require the explicit AllowInsecure acknowledgement.
func TestValidate_RadSecInsecureSkipVerify_NeedsAllowInsecure(t *testing.T) {
	c := baseValidCfg()
	c.UseRadSec = true
	c.RadSecInsecureSkipVerify = true
	mustValidateErr(t, c, "RadSecAllowInsecure")
}

func TestValidate_RadSecInsecureSkipVerify_WithAllowInsecure_OK(t *testing.T) {
	c := baseValidCfg()
	c.UseRadSec = true
	c.RadSecInsecureSkipVerify = true
	c.RadSecAllowInsecure = true
	if err := c.Validate(); err != nil {
		t.Fatalf("RadSec insecure + AllowInsecure rejected: %v", err)
	}
}

// A mutual-RadSec client cert needs BOTH cert and key.
func TestValidate_RadSecClientCert_BothHalvesRequired(t *testing.T) {
	c := baseValidCfg()
	c.UseRadSec = true
	c.RadSecClientCertPEM = []byte("cert-only")
	mustValidateErr(t, c, "both be set")
}

func TestValidate_RadSec_SuppliedTLSConfig_SkipsFieldGate(t *testing.T) {
	c := baseValidCfg()
	c.UseRadSec = true
	c.RadSecTLSConfig = &tls.Config{ServerName: "radius.example.com"}
	// Even with InsecureSkipVerify set on the fields, a supplied TLSConfig owns
	// verification, so the field gate does not trip.
	c.RadSecInsecureSkipVerify = true
	if err := c.Validate(); err != nil {
		t.Fatalf("RadSec with supplied TLSConfig rejected: %v", err)
	}
}

// --- Defaults + derived helpers -------------------------------------------

func TestDefaults_Timeout_NASIdentifier(t *testing.T) {
	c := baseValidCfg()
	if c.requestTimeout() != DefaultTimeout {
		t.Errorf("requestTimeout() = %v, want default %v", c.requestTimeout(), DefaultTimeout)
	}
	if c.nasIdentifier() != DefaultNASIdentifier {
		t.Errorf("nasIdentifier() = %q, want default %q", c.nasIdentifier(), DefaultNASIdentifier)
	}
}

func TestOverrides_Timeout_NASIdentifier(t *testing.T) {
	c := baseValidCfg()
	c.Timeout = 2 * time.Second
	c.NASIdentifier = "sso-1"
	if c.requestTimeout() != 2*time.Second {
		t.Errorf("requestTimeout() = %v, want 2s", c.requestTimeout())
	}
	if c.nasIdentifier() != "sso-1" {
		t.Errorf("nasIdentifier() = %q, want sso-1", c.nasIdentifier())
	}
}

// retryInterval must fit all retransmits inside the bounded Timeout.
func TestRetryInterval_FitsWithinTimeout(t *testing.T) {
	c := baseValidCfg()
	c.Timeout = 6 * time.Second
	c.Retries = 2 // 3 sends total => interval 2s
	if got := c.retryInterval(); got != 2*time.Second {
		t.Errorf("retryInterval() = %v, want 2s (Timeout/(Retries+1))", got)
	}
}

func TestRetryInterval_NoRetransmit_WhenRetriesNegative(t *testing.T) {
	c := baseValidCfg()
	c.Retries = -1
	if got := c.retryInterval(); got != 0 {
		t.Errorf("retryInterval() = %v, want 0 (no retransmit)", got)
	}
}

func TestUseTCP_RadSecImpliesTCP(t *testing.T) {
	c := baseValidCfg()
	c.UseRadSec = true
	if !c.useTCP() {
		t.Error("useTCP() = false, want true when RadSec enabled")
	}
}

// radSecTLSConfig builds a verifying config from the CA/ServerName fields.
func TestRadSecTLSConfig_BuiltFromFields(t *testing.T) {
	c := baseValidCfg()
	c.UseRadSec = true
	c.RadSecServerName = "radius.example.com"
	cfg, err := c.radSecTLSConfig()
	if err != nil {
		t.Fatalf("radSecTLSConfig: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Error("default RadSec tls.Config has InsecureSkipVerify=true — must verify")
	}
	if cfg.ServerName != "radius.example.com" {
		t.Errorf("ServerName = %q, want radius.example.com", cfg.ServerName)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want >= TLS1.2", cfg.MinVersion)
	}
}

func TestRadSecTLSConfig_BadCACert_Errors(t *testing.T) {
	c := baseValidCfg()
	c.RadSecCACertPEM = []byte("not a pem")
	if _, err := c.radSecTLSConfig(); err == nil {
		t.Fatal("radSecTLSConfig accepted a non-PEM CA cert")
	}
}

func TestRadSecTLSConfig_SuppliedVerbatim(t *testing.T) {
	c := baseValidCfg()
	supplied := &tls.Config{ServerName: "mine"}
	c.RadSecTLSConfig = supplied
	got, err := c.radSecTLSConfig()
	if err != nil {
		t.Fatalf("radSecTLSConfig: %v", err)
	}
	if got != supplied {
		t.Error("radSecTLSConfig did not return the operator-supplied config verbatim")
	}
}

// --- Reply-attribute mapping on the prod exchanger -------------------------

// mapReplyAttributes maps ONLY the configured RADIUS reply attributes onto local
// keys, reading the real Filter-Id / Class values back off a packet via the
// layeh rfc2865 helpers. Nothing unconfigured is copied.
func TestMapReplyAttributes_FilterIDAndClass(t *testing.T) {
	cfg := baseValidCfg()
	cfg.ReplyAttributeMapping = map[radius.Type]string{
		rfc2865.FilterID_Type: "filter_id",
		rfc2865.Class_Type:    "radius_class",
	}
	ex, err := newRadiusExchanger(cfg)
	if err != nil {
		t.Fatalf("newRadiusExchanger: %v", err)
	}

	// Build a stand-in Access-Accept carrying the two attributes (the same packet
	// type the real server would return).
	resp := radius.New(radius.CodeAccessAccept, []byte(cfg.SharedSecret))
	if err := rfc2865.FilterID_SetString(resp, "Enterprise-VPN"); err != nil {
		t.Fatalf("set Filter-Id: %v", err)
	}
	if err := rfc2865.Class_SetString(resp, "policy-42"); err != nil {
		t.Fatalf("set Class: %v", err)
	}

	attrs := ex.mapReplyAttributes(resp)
	if attrs["filter_id"] != "Enterprise-VPN" {
		t.Errorf("filter_id = %q, want Enterprise-VPN", attrs["filter_id"])
	}
	if attrs["radius_class"] != "policy-42" {
		t.Errorf("radius_class = %q, want policy-42", attrs["radius_class"])
	}
}

// An unconfigured attribute present on the reply is NOT copied — a server cannot
// smuggle an attribute onto the Subject unless the operator mapped it.
func TestMapReplyAttributes_OnlyConfiguredCopied(t *testing.T) {
	cfg := baseValidCfg()
	cfg.ReplyAttributeMapping = map[radius.Type]string{
		rfc2865.FilterID_Type: "filter_id",
	}
	ex, _ := newRadiusExchanger(cfg)

	resp := radius.New(radius.CodeAccessAccept, []byte(cfg.SharedSecret))
	_ = rfc2865.FilterID_SetString(resp, "ok")
	_ = rfc2865.Class_SetString(resp, "should-not-appear") // NOT in the mapping

	attrs := ex.mapReplyAttributes(resp)
	if attrs["filter_id"] != "ok" {
		t.Errorf("filter_id = %q, want ok", attrs["filter_id"])
	}
	if _, present := attrs["radius_class"]; present {
		t.Error("unmapped Class attribute leaked onto the result")
	}
	if len(attrs) != 1 {
		t.Errorf("attrs = %v, want exactly the one mapped key", attrs)
	}
}

// No mapping configured => nil attrs (only ExternalID is populated downstream).
func TestMapReplyAttributes_NoMapping_Nil(t *testing.T) {
	cfg := baseValidCfg()
	ex, _ := newRadiusExchanger(cfg)
	resp := radius.New(radius.CodeAccessAccept, []byte(cfg.SharedSecret))
	_ = rfc2865.FilterID_SetString(resp, "ignored")
	if attrs := ex.mapReplyAttributes(resp); attrs != nil {
		t.Errorf("mapReplyAttributes with no mapping = %v, want nil", attrs)
	}
}

// --- buildAccessRequest sets the expected attributes -----------------------

func TestBuildAccessRequest_SetsUserNameAndNAS(t *testing.T) {
	cfg := baseValidCfg()
	cfg.NASIdentifier = "sso.example.com"
	ex, _ := newRadiusExchanger(cfg)

	packet, err := ex.buildAccessRequest("alice", "pw")
	if err != nil {
		t.Fatalf("buildAccessRequest: %v", err)
	}
	if packet.Code != radius.CodeAccessRequest {
		t.Errorf("Code = %v, want Access-Request", packet.Code)
	}
	if got := rfc2865.UserName_GetString(packet); got != "alice" {
		t.Errorf("User-Name = %q, want alice", got)
	}
	if got := rfc2865.NASIdentifier_GetString(packet); got != "sso.example.com" {
		t.Errorf("NAS-Identifier = %q, want sso.example.com", got)
	}
	// The User-Password attribute must be PRESENT (PAP-encrypted by layeh). We
	// don't assert the plaintext (it's encrypted under the Request Authenticator);
	// presence of the attribute Type is the contract.
	if _, ok := packet.Lookup(rfc2865.UserPassword_Type); !ok {
		t.Error("User-Password attribute missing from Access-Request")
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
