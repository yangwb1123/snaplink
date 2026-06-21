package config

import (
	"context"
	"flag"
	"testing"
)

func newTestFlags(args []string) *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("listen", "", "")
	fs.String("log-level", "", "")
	fs.Bool("dev", false, "")
	_ = fs.Parse(args)
	return fs
}

func TestFlagSource_OnlySetFlagsEmit(t *testing.T) {
	fs := newTestFlags([]string{"--listen=:9090"})
	src := NewFlagSource(fs).
		Bind("listen", "server.listen").
		Bind("log-level", "logging.level")

	m, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	srv := m["server"].(map[string]any)
	if srv["listen"] != ":9090" {
		t.Errorf("listen = %v", srv["listen"])
	}
	if _, ok := m["logging"]; ok {
		t.Errorf("unset flag leaked: %v", m["logging"])
	}
}

func TestFlagSource_NoBindings_ReturnsNil(t *testing.T) {
	fs := newTestFlags([]string{"--listen=:9090"})
	src := NewFlagSource(fs) // no Bind calls
	m, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m != nil {
		t.Errorf("expected nil for empty bindings, got %v", m)
	}
}

func TestFlagSource_UnboundFlagIgnored(t *testing.T) {
	fs := newTestFlags([]string{"--listen=:9090", "--dev=true"})
	src := NewFlagSource(fs).Bind("listen", "server.listen")
	m, _ := src.Load(context.Background())
	srv := m["server"].(map[string]any)
	if srv["listen"] != ":9090" {
		t.Errorf("listen wrong: %v", srv)
	}
	// --dev is set but unbound — must not appear in the map.
	if _, ok := m["dev"]; ok {
		t.Errorf("unbound flag leaked: %v", m)
	}
}

func TestFlagSource_BoolCoercion(t *testing.T) {
	fs := newTestFlags([]string{"--dev=true"})
	src := NewFlagSource(fs).Bind("dev", "bootstrap.disabled")
	m, _ := src.Load(context.Background())
	boot := m["bootstrap"].(map[string]any)
	if boot["disabled"] != true {
		t.Errorf("disabled = %v (%T)", boot["disabled"], boot["disabled"])
	}
}

func TestFlagSource_OverridesFileAndEnv(t *testing.T) {
	p := writeTemp(t, "f.yaml", "server:\n  listen: :7070\n")
	envSrc := &EnvSource{Prefix: "SSO_", Separator: "__", Environ: envFn(
		"SSO_SERVER__LISTEN=:8080",
	)}
	fs := newTestFlags([]string{"--listen=:9999"})
	flagSrc := NewFlagSource(fs).Bind("listen", "server.listen")

	cfg, err := LoadFromSources(context.Background(),
		NewFileSource(p),
		envSrc,
		flagSrc,
	)
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	if cfg.Server.Listen != ":9999" {
		t.Errorf("flag should win over file+env: listen = %q", cfg.Server.Listen)
	}
}

func TestFlagSource_UnsetFlag_LetsLowerSourcesWin(t *testing.T) {
	// Flag bound but not on argv — file value should remain.
	p := writeTemp(t, "f.yaml", "logging:\n  level: debug\n")
	fs := newTestFlags([]string{"--listen=:9090"}) // --log-level NOT set
	flagSrc := NewFlagSource(fs).
		Bind("listen", "server.listen").
		Bind("log-level", "logging.level")

	cfg, err := LoadFromSources(context.Background(), NewFileSource(p), flagSrc)
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("unset flag overrode file: level = %q", cfg.Logging.Level)
	}
}
