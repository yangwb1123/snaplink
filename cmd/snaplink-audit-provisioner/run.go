package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 1 << 20
	logRepeatInterval = 5 * time.Minute
)

func execute(
	ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string,
	reload <-chan os.Signal,
) int {
	config, err := parseRuntimeConfig(args, getenv, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: configuration invalid\n", programName)
		return 2
	}
	provisioner, err := buildProvisioner(config)
	if err != nil {
		fmt.Fprintf(stderr, "%s: configuration invalid\n", programName)
		return 2
	}
	status := &runtimeStatus{}
	if config.OneShot {
		return runOneShot(ctx, config.ManifestFile, provisioner, status, stdout, stderr)
	}
	return runContinuous(ctx, config, provisioner, status, stderr, reload)
}

func buildProvisioner(config runtimeConfig) (*auditgovernance.Provisioner, error) {
	tokens, err := auditgovernance.NewPlatformTokenSource(auditgovernance.PlatformTokenConfig{
		TokenURL: config.TokenURL, ClientID: config.ClientID, ClientSecret: config.ClientSecret,
		Resource: config.Resource, Timeout: config.RequestTimeout,
		AllowInsecureLoopback: config.AllowInsecureLoopback,
	}, nil)
	if err != nil {
		return nil, err
	}
	control, err := auditgovernance.NewControlClient(auditgovernance.ControlConfig{
		BaseURL: config.BaseURL, Timeout: config.RequestTimeout,
		AllowInsecureLoopback: config.AllowInsecureLoopback,
	}, tokens, nil)
	if err != nil {
		return nil, err
	}
	return auditgovernance.NewProvisioner(control)
}

func runOneShot(
	ctx context.Context, manifestFile string, provisioner *auditgovernance.Provisioner,
	status *runtimeStatus, stdout, stderr io.Writer,
) int {
	result, err := reconcileFile(ctx, manifestFile, provisioner)
	class := status.record(result, err)
	if err != nil {
		fmt.Fprintf(stderr, "%s: reconcile result=%s\n", programName, class)
		return oneShotErrorCode(err)
	}
	fmt.Fprintf(stdout, "revision=%d tenants_created=%d sources_created=%d schemas_created=%d\n",
		result.Revision, result.TenantsCreated, result.SourcesCreated, result.SchemasCreated)
	return 0
}

func oneShotErrorCode(err error) int {
	if errors.Is(err, auditgovernance.ErrDesiredManifest) {
		return 2
	}
	if errors.Is(err, auditgovernance.ErrDesiredStale) ||
		errors.Is(err, auditgovernance.ErrDesiredConflict) || errors.Is(err, auditgovernance.ErrRemoteDrift) {
		return 3
	}
	return 1
}

func runContinuous(
	ctx context.Context, config runtimeConfig, provisioner *auditgovernance.Provisioner,
	status *runtimeStatus, stderr io.Writer, reload <-chan os.Signal,
) int {
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		fmt.Fprintf(stderr, "%s: listen failed\n", programName)
		return 1
	}
	server := newStatusServer(config.Listen, newStatusHandler(status), stderr)
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	logger := &boundedReconcileLogger{output: stderr}
	reconcileAndRecord(ctx, config.ManifestFile, provisioner, status, logger)
	ticker := time.NewTicker(config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return shutdownStatusServer(server, served, config.ShutdownTimeout, stderr)
		case err := <-served:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintf(stderr, "%s: status server failed\n", programName)
				return 1
			}
			return 0
		case <-ticker.C:
			reconcileAndRecord(ctx, config.ManifestFile, provisioner, status, logger)
		case <-reload:
			reconcileAndRecord(ctx, config.ManifestFile, provisioner, status, logger)
		}
	}
}

func newStatusServer(address string, handler http.Handler, stderr io.Writer) *http.Server {
	return &http.Server{
		Addr: address, Handler: handler, ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout: defaultRequestTimeout, WriteTimeout: defaultRequestTimeout,
		IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes,
		ErrorLog: log.New(stderr, programName+": ", 0),
	}
}

func shutdownStatusServer(server *http.Server, served <-chan error, timeout time.Duration, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintf(stderr, "%s: shutdown failed\n", programName)
		return 1
	}
	if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return 1
	}
	return 0
}

func reconcileAndRecord(
	ctx context.Context, manifestFile string, provisioner *auditgovernance.Provisioner,
	status *runtimeStatus, logger *boundedReconcileLogger,
) {
	result, err := reconcileFile(ctx, manifestFile, provisioner)
	class := status.record(result, err)
	logger.log(class, result)
}

func reconcileFile(
	ctx context.Context, manifestFile string, provisioner *auditgovernance.Provisioner,
) (auditgovernance.ReconcileResult, error) {
	manifest, err := auditgovernance.LoadDesiredManifest(manifestFile)
	if err != nil {
		return auditgovernance.ReconcileResult{}, err
	}
	return provisioner.Apply(ctx, manifest)
}

type boundedReconcileLogger struct {
	output       io.Writer
	lastClass    string
	lastRevision uint64
	lastAt       time.Time
}

func (logger *boundedReconcileLogger) log(class string, result auditgovernance.ReconcileResult) {
	now := time.Now()
	created := result.TenantsCreated + result.SourcesCreated + result.SchemasCreated
	changed := class != logger.lastClass || result.Revision != logger.lastRevision || created > 0
	if !changed && now.Sub(logger.lastAt) < logRepeatInterval {
		return
	}
	fmt.Fprintf(logger.output, "%s: reconcile result=%s revision=%d tenants_created=%d sources_created=%d schemas_created=%d\n",
		programName, class, result.Revision, result.TenantsCreated, result.SourcesCreated, result.SchemasCreated)
	logger.lastClass, logger.lastRevision, logger.lastAt = class, result.Revision, now
}
