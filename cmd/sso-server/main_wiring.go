package main

import (
	"context"
	"flag"
	"strings"

	"github.com/snaplink/sso/config"
	configetcd "github.com/snaplink/sso/config/etcd"
	configreload "github.com/snaplink/sso/config/reload"
	"github.com/snaplink/sso/platform/tracing"
	"github.com/snaplink/sso/shared/spi"
)

// runtimeFlags holds the parsed CLI flag values main needs after Load.
// Config-bound flags (listen, log-level, …) are intentionally absent: they
// are resolved by the Loader via FlagSource, not read directly here.
type runtimeFlags struct {
	cfgPath string

	// Runtime-only flags: not in Config (yet) — passed directly to run().
	grpcListen string
	tlsCert    string
	tlsKey     string

	// Optional centralized config endpoints (empty = etcd disabled).
	etcdEndpoints string
	etcdPrefix    string

	// validateOnly when set loads and validates config then exits.
	validateOnly bool
}

// parseRuntimeFlags registers every flag, binds config-bound ones to their
// Config paths via FlagSource, parses argv, and returns the runtime-only
// values. The config-bound flags (listen/log-level/restore/password-file)
// are declared here for usage + FlagSource binding; their values are read by
// the Loader, not returned.
func parseRuntimeFlags() runtimeFlags {
	flag.Usage = usage
	// Bound to Config fields via FlagSource below. The values themselves
	// aren't read directly — Loader resolves them when building *Config,
	// so a flag without --foo on argv leaves the file / env value alone.
	cfgPath := flag.String("config", "config.yaml", "path to YAML config")
	_ = flag.String("listen", "", "override server.listen from config (e.g. :9090)")
	_ = flag.String("log-level", "", "override logging.level (debug|info|error)")
	_ = flag.String("bootstrap-restore-from", "", "snapshot URI for first-boot restore (overrides snapshot.restore_from); e.g. file:///var/snapshots/snap.snap")
	_ = flag.String("bootstrap-admin-password-file", "", "path to write the generated admin password to (mode 0600), in addition to stdout; overrides bootstrap.admin_password_file")

	// Runtime-only flags: not in Config (yet) — passed directly to run().
	grpcListen := flag.String("grpc-listen", ":8081", "gRPC listen address ('' to disable)")
	tlsCert := flag.String("tls-cert", "", "TLS cert file (omit for HTTP)")
	tlsKey := flag.String("tls-key", "", "TLS key file (omit for HTTP)")
	validateOnly := flag.Bool("validate-only", false, "load and validate config then exit without starting the server")

	// Optional centralized config: when --etcd-endpoints is set, an etcd
	// Source slots into the Loader chain between env and flag, so a
	// cluster-wide value beats the local file + env but a one-shot CLI
	// override still wins. Endpoints empty = skip (etcd is an optional
	// operator-side dep, not a runtime requirement).
	etcdEndpoints := flag.String("etcd-endpoints", "", "comma-separated etcd endpoints for live config; empty disables (e.g. localhost:2379)")
	etcdPrefix := flag.String("etcd-prefix", configetcd.DefaultPrefix, "etcd key prefix when --etcd-endpoints is set")
	flag.Parse()

	return runtimeFlags{
		cfgPath:       *cfgPath,
		grpcListen:    *grpcListen,
		tlsCert:       *tlsCert,
		tlsKey:        *tlsKey,
		etcdEndpoints: *etcdEndpoints,
		etcdPrefix:    *etcdPrefix,
		validateOnly:  *validateOnly,
	}
}

// buildConfigSources assembles the Loader source chain — priority low → high:
// file < env < etcd? < flag. Operators drop a YAML file for the bulk of
// config, sprinkle ENV in container orchestrators (12-factor), opt into etcd
// for cluster-wide live values, and use CLI flags for ad-hoc overrides
// (debugging, one-shot reruns).
//
// The returned cleanup closes the etcd connection (no-op when etcd is
// disabled); callers must defer it for the process lifetime. The etcd Source
// only does one Get on Load and doesn't watch — cheap to hold open, and it
// avoids the close-on-error edge case if Load fails.
func buildConfigSources(f runtimeFlags) ([]config.Source, func(), error) {
	flagSrc := config.NewFlagSource(flag.CommandLine).
		Bind("listen", "server.listen").
		Bind("log-level", "logging.level").
		Bind("bootstrap-restore-from", "snapshot.restore_from").
		Bind("bootstrap-admin-password-file", "bootstrap.admin_password_file")

	sources := []config.Source{
		config.NewFileSource(f.cfgPath),
		config.NewEnvSource(),
	}
	cleanup := func() {}
	if f.etcdEndpoints != "" {
		etcdSrc, err := configetcd.New(configetcd.Config{
			Endpoints: strings.Split(f.etcdEndpoints, ","),
			Prefix:    f.etcdPrefix,
		})
		if err != nil {
			return nil, nil, err
		}
		cleanup = func() { _ = etcdSrc.Close() }
		sources = append(sources, etcdSrc)
	}
	sources = append(sources, flagSrc)
	return sources, cleanup, nil
}

// newConfigReloader builds the OPTIONAL SIGHUP hot-reload orchestrator,
// seeded with cfg and re-reading from the SAME source chain buildConfigSources
// assembled at boot. logger.SetLevel is the only currently-wired safe-reload
// hook — logging.level is genuinely live (a *slog.LevelVar), everything else
// a reload detects changed is reported but left untouched. See
// waitForShutdown (main_shutdown.go) and config/reload's package doc for the
// full rationale.
func newConfigReloader(cfg *config.Config, sources []config.Source, logger *slogLogger) *configreload.Reloader {
	return configreload.New(cfg, func(ctx context.Context) (*config.Config, error) {
		return config.LoadFromSources(ctx, sources...)
	}, logger.SetLevel)
}

// initTracing wires OTLP tracing and returns its shutdown func. The call is
// a no-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset, so it is safe to leave
// unconditional; shutdown flushes pending spans on process exit. On init
// failure it logs and returns a no-op shutdown so callers can defer it
// unconditionally.
func initTracing(cfg *config.Config, logger spi.Logger) func(context.Context) error {
	tracingShutdown, err := tracing.Init(context.Background(),
		tracing.WithServiceName(cfg.Server.Issuer),
	)
	if err != nil {
		logger.Error("tracing init failed; continuing without traces", "error", err)
		return func(context.Context) error { return nil }
	}
	return tracingShutdown
}
