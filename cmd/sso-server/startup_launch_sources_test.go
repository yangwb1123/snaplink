package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/config"
)

// Exercise the actual stock source-chain owner, not a copied config.Load-only
// approximation. These tests load synthetic private configuration, never build
// an app, open a store, run bootstrap, start a worker or listen on a socket.
func TestStartupLaunch_ConfigSourceChain(t *testing.T) {
	cases := []struct {
		name       string
		env        map[string]string
		args       []string
		listen     string
		level      string
		reap       time.Duration
		fileParity bool
	}{
		{"file_only_parity_requires_absent_overlays", nil, nil, "127.0.0.1:18000", "info", 0, true},
		{"environment_can_enable_reaper", map[string]string{"SSO_OAUTH__REFRESH_TOKEN__REAP_INTERVAL": "1s"}, nil, "127.0.0.1:18000", "info", time.Second, false},
		{"environment_overrides_file", map[string]string{"SSO_SERVER__LISTEN": "127.0.0.1:19000"}, nil, "127.0.0.1:19000", "info", 0, false},
		{"flags_override_environment", map[string]string{"SSO_SERVER__LISTEN": "127.0.0.1:19000", "SSO_LOGGING__LEVEL": "error"}, []string{"-listen", "127.0.0.1:20000", "-log-level", "debug"}, "127.0.0.1:20000", "debug", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			startupLaunchClearEnv(t)
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			path := filepath.Join(t.TempDir(), "off-config.json")
			body := []byte(`{"version":1,"server":{"listen":"127.0.0.1:18000"}}`)
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			f := startupLaunchParse(t, append([]string{"-config", path, "-grpc-listen", ""}, tc.args...))
			c := startupLaunchLoad(t, f)
			if c.Server.Listen != tc.listen || c.Logging.Level != tc.level || c.OAuth.RefreshToken.ReapInterval != tc.reap {
				t.Fatal("actual stock file/environment/flag precedence changed")
			}
			fileOnly, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(c, fileOnly) != tc.fileParity {
				t.Fatal("file-only inspection unexpectedly matches an overlaid stock config")
			}
			if f.grpcListen != "" || f.etcdEndpoints != "" || f.validateOnly || c.Bootstrap.Disabled {
				t.Fatal("fixture transport/bootstrap posture changed")
			}
		})
	}
}

func startupLaunchClearEnv(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, config.DefaultEnvPrefix) {
			continue
		}
		t.Setenv(name, "") // t restores the original value after this subtest.
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func startupLaunchParse(t *testing.T, args []string) runtimeFlags {
	t.Helper()
	previousFlags, previousArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = previousFlags, previousArgs })
	flag.CommandLine = flag.NewFlagSet("startup-launch-test", flag.ContinueOnError)
	os.Args = append([]string{"startup-launch-test"}, args...)
	return parseRuntimeFlags()
}

func startupLaunchLoad(t *testing.T, f runtimeFlags) *config.Config {
	t.Helper()
	sources, closeSources, err := buildConfigSources(f)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSources()
	if len(sources) != 3 {
		t.Fatal("expected the complete stock file/environment/flag chain")
	}
	c, err := config.LoadFromSources(context.Background(), sources...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
