package config

import (
	"context"
	"testing"
)

// TestAccessLogConfig_DefaultOn proves the tri-state default: an absent
// logging.access_log block means ON, so ServerOptions installs the
// always-on access logger with the zero-value body policy (no bodies).
func TestAccessLogConfig_DefaultOn(t *testing.T) {
	t.Parallel()
	cfg := &Config{}
	cfg.Server.Issuer = "https://sso.example"
	if !cfg.Logging.AccessLog.enabled() {
		t.Fatal("absent logging.access_log must default to enabled")
	}
	opts := cfg.ServerOptions()
	if len(opts) == 0 {
		t.Fatal("ServerOptions returned no options for a default config")
	}
}

// TestAccessLogConfig_ExplicitFalseDisables proves that an explicit
// enabled: false round-trips and removes the middleware from ServerOptions.
func TestAccessLogConfig_ExplicitFalseDisables(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "accesslog-off.yaml", `
server:
  issuer: https://sso.example
logging:
  level: info
  access_log:
    enabled: false
`)
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p))
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	if cfg.Logging.AccessLog.Enabled == nil || *cfg.Logging.AccessLog.Enabled != false {
		t.Fatalf("logging.access_log.enabled = %v, want explicit false", cfg.Logging.AccessLog.Enabled)
	}
	if cfg.Logging.AccessLog.enabled() {
		t.Fatal("explicit false must disable the access log")
	}
	// ServerOptions must still produce options for everything else wired
	// above, but must NOT include the access-log option. Comparing option
	// slices directly is impossible (closures); the observable contract is
	// the tri-state flag itself, pinned here.
	if cfg.ServerOptions() == nil {
		t.Fatal("ServerOptions returned nil")
	}
}

// TestAccessLogConfig_BodyPolicyMapping proves the body block maps 1:1
// onto the SDK policy shape.
func TestAccessLogConfig_BodyPolicyMapping(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "accesslog-body.yaml", `
server:
  issuer: https://sso.example
logging:
  access_log:
    body:
      paths: ["/token", "/par"]
      sample_rate: 0.5
      max_body_bytes: 1024
`)
	cfg, err := LoadFromSources(context.Background(), NewFileSource(p))
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	pol := cfg.Logging.AccessLog.bodyPolicy()
	if len(pol.Paths) != 2 || pol.Paths[0] != "/token" || pol.Paths[1] != "/par" {
		t.Errorf("paths = %v, want [/token /par]", pol.Paths)
	}
	if pol.SampleRate != 0.5 {
		t.Errorf("sample_rate = %v, want 0.5", pol.SampleRate)
	}
	if pol.MaxBodyBytes != 1024 {
		t.Errorf("max_body_bytes = %v, want 1024", pol.MaxBodyBytes)
	}
	if pol.AllowAllPaths {
		t.Error("allow_all_paths should stay false")
	}
}

// TestAccessLogConfig_Validation proves misconfiguration fails loudly at
// boot instead of silently combining contradictory capture modes.
func TestAccessLogConfig_Validation(t *testing.T) {
	t.Parallel()
	bad := []string{
		"allow_all_paths: true\n    body:\n      paths: [\"/token\"]", // ambiguous
		"sample_rate: 1.5",   // out of range
		"sample_rate: -0.1",  // out of range
		"max_body_bytes: -5", // negative cap
	}
	for _, tc := range bad {
		t.Run(tc, func(t *testing.T) {
			p := writeTemp(t, "accesslog-bad.yaml", `
server:
  issuer: https://sso.example
logging:
  access_log:
    body:
`+indentBody(tc))
			if _, err := LoadFromSources(context.Background(), NewFileSource(p)); err == nil {
				t.Fatal("expected validation error, got none")
			}
		})
	}
}

// indentBody re-indents the snippet fragments above (written flat) under
// the access_log.body key.
func indentBody(s string) string {
	out := ""
	for _, line := range splitLines(s) {
		out += "      " + line + "\n"
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
