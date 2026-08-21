package serverbuildauthn

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/buildinfo"
	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// ExternalAuditRuntime is the stock-server lifecycle adapter for the typed
// external audit worker. It is a write-only audit tap: the primary recorder
// remains authoritative and worker delivery errors are logged and swallowed.
type ExternalAuditRuntime struct {
	manager  *modules.Manager
	moduleID string
	logger   spi.Logger
}

// BuildExternalAuditRuntime validates launch material, starts the first
// worker generation, and returns the lifecycle-managed audit tap.
func BuildExternalAuditRuntime(
	cfg config.ExternalAuditWorkerConfig, recorder *audit.Recorder, logger spi.Logger,
) (*ExternalAuditRuntime, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if recorder == nil {
		return nil, errors.New("audit.external_worker requires audit.enabled")
	}
	if logger == nil {
		logger = spi.NopLogger{}
	}
	spec, err := buildExternalWorkerSpec(cfg)
	if err != nil {
		return nil, err
	}
	factory, err := modules.NewExternalFactory(spec)
	if err != nil {
		return nil, fmt.Errorf("audit.external_worker: %w", err)
	}
	runtime := &ExternalAuditRuntime{moduleID: spec.ModuleID, logger: logger}
	options := externalWorkerManagerOptions(cfg, externalWorkerObserver(recorder, logger))
	runtime.manager, err = modules.New([]modules.Definition{{ID: spec.ModuleID, Factory: factory}}, options)
	if err != nil {
		return nil, fmt.Errorf("audit.external_worker lifecycle: %w", err)
	}
	if _, err := runtime.manager.Activate(context.Background(), spec.ModuleID, nil); err != nil {
		_ = runtime.manager.Close(context.Background())
		return nil, fmt.Errorf("audit.external_worker startup: %w", err)
	}
	if err := runtime.manager.WaitObserver(context.Background()); err != nil {
		_ = runtime.manager.Close(context.Background())
		return nil, fmt.Errorf("audit.external_worker observer: %w", err)
	}
	logger.Info("audit: external worker enabled", "module_id", spec.ModuleID, "mode", externalWorkerMode(cfg))
	return runtime, nil
}

func buildExternalWorkerSpec(cfg config.ExternalAuditWorkerConfig) (modules.ExternalModuleSpec, error) {
	profile := strings.TrimSpace(cfg.BuildProfile)
	if strings.TrimSpace(cfg.RemoteAddress) == "" && profile != buildinfo.BuildProfile {
		return modules.ExternalModuleSpec{}, fmt.Errorf("audit.external_worker: build_profile %q does not match host profile %q", profile, buildinfo.BuildProfile)
	}
	provenanceKey, err := decodeExternalWorkerKey(cfg.ProvenancePublicKey, "provenance_public_key")
	if err != nil {
		return modules.ExternalModuleSpec{}, err
	}
	signatureKey, err := decodeExternalWorkerKey(cfg.SignaturePublicKey, "signature_public_key")
	if err != nil {
		return modules.ExternalModuleSpec{}, err
	}
	tlsConfig, err := buildExternalWorkerTLS(cfg)
	if err != nil {
		return modules.ExternalModuleSpec{}, err
	}
	return modules.ExternalModuleSpec{
		ModuleID:             strings.TrimSpace(cfg.ModuleID),
		Executable:           cfg.Executable,
		Args:                 append([]string(nil), cfg.Args...),
		SocketPath:           cfg.SocketPath,
		AuthToken:            []byte(cfg.AuthToken),
		ExpectedSHA256:       strings.TrimSpace(cfg.ExpectedSHA256),
		SignaturePath:        cfg.SignaturePath,
		SignaturePublicKey:   signatureKey,
		ProvenancePath:       cfg.ProvenancePath,
		ProvenancePublicKey:  provenanceKey,
		RequiredReleaseID:    strings.TrimSpace(cfg.ReleaseID),
		RequiredBuildProfile: profile,
		RemoteAddress:        strings.TrimSpace(cfg.RemoteAddress),
		TLSConfig:            tlsConfig,
		PeerSPIFFEID:         strings.TrimSpace(cfg.PeerSPIFFEID),
		RequiredCapabilities: []modules.ExternalCapability{modules.ExternalCapabilityAuditBatch},
		StartupTimeout:       cfg.StartupTimeout,
		RequestTimeout:       cfg.RequestTimeout,
		MaxFrameBytes:        cfg.MaxFrameBytes,
		MaxBatchEvents:       cfg.MaxBatchEvents,
	}, nil
}

func buildExternalWorkerTLS(cfg config.ExternalAuditWorkerConfig) (*tls.Config, error) {
	if strings.TrimSpace(cfg.RemoteAddress) == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("audit.external_worker: load client certificate: %w", err)
	}
	roots, err := loadExternalWorkerRoots(cfg.TLS.CAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   strings.TrimSpace(cfg.TLS.ServerName),
	}, nil
}

func loadExternalWorkerRoots(path string) (*x509.CertPool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit.external_worker: read tls.ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("audit.external_worker: tls.ca_file contains no certificates")
	}
	return pool, nil
}

func decodeExternalWorkerKey(raw, name string) (ed25519.PublicKey, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	if key, err := hex.DecodeString(value); err == nil && len(key) == ed25519.PublicKeySize {
		return ed25519.PublicKey(key), nil
	}
	for _, decoder := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
	} {
		if key, err := decoder(value); err == nil && len(key) == ed25519.PublicKeySize {
			return ed25519.PublicKey(key), nil
		}
	}
	return nil, fmt.Errorf("audit.external_worker: %s must be 32-byte hex or base64 Ed25519 public key", name)
}

func externalWorkerManagerOptions(cfg config.ExternalAuditWorkerConfig, observer modules.TransitionObserver) modules.Options {
	lifecycleTimeout := cfg.StartupTimeout + cfg.RequestTimeout
	if lifecycleTimeout <= 0 {
		lifecycleTimeout = 20 * time.Second
	}
	if lifecycleTimeout < 5*time.Second {
		lifecycleTimeout = 5 * time.Second
	}
	drainTimeout := cfg.RequestTimeout
	if drainTimeout <= 0 {
		drainTimeout = 30 * time.Second
	}
	return modules.Options{
		LifecycleTimeout:   lifecycleTimeout,
		DrainTimeout:       drainTimeout,
		TransitionObserver: observer,
	}
}

func externalWorkerObserver(recorder *audit.Recorder, logger spi.Logger) modules.TransitionObserver {
	return modules.TransitionObserverFunc(func(ctx context.Context, event modules.TransitionEvent) error {
		logger.Info("external audit worker lifecycle transition",
			"type", event.Type, "module_id", event.ModuleID, "generation", event.Generation,
			"related_generation", event.RelatedGeneration)
		if recorder == nil {
			return nil
		}
		auditEvent := &audit.Event{
			Type: audit.EventExternalWorkerLifecycleTransition, Outcome: audit.OutcomeSuccess,
			Timestamp: event.OccurredAt, Reason: string(event.Type),
		}
		audit.SetMeta(auditEvent, "module_id", event.ModuleID)
		audit.SetMeta(auditEvent, "generation", fmt.Sprintf("%d", event.Generation))
		if event.RelatedGeneration != 0 {
			audit.SetMeta(auditEvent, "related_generation", fmt.Sprintf("%d", event.RelatedGeneration))
		}
		recorder.Record(ctx, auditEvent)
		return nil
	})
}

func externalWorkerMode(cfg config.ExternalAuditWorkerConfig) string {
	if strings.TrimSpace(cfg.RemoteAddress) != "" {
		return "remote"
	}
	return "local"
}

// Record sends one redacted, hash-stamped event to the active worker. Delivery
// is fail-open so a worker outage cannot change an OAuth response.
func (r *ExternalAuditRuntime) Record(ctx context.Context, event *audit.Event) error {
	if r == nil || r.manager == nil || event == nil {
		return nil
	}
	lease, err := r.manager.Acquire(r.moduleID, modules.LeaseRequest)
	if err != nil {
		if !errors.Is(err, modules.ErrManagerClosed) {
			r.logDeliveryFailure("acquire", err)
		}
		return nil
	}
	defer lease.Release()
	sink, ok := lease.Instance().(audit.Sink)
	if !ok {
		r.logDeliveryFailure("capability", errors.New("worker does not expose audit sink"))
		return nil
	}
	if err := sink.Record(ctx, event); err != nil {
		r.logDeliveryFailure("record", err)
	}
	return nil
}

func (r *ExternalAuditRuntime) logDeliveryFailure(operation string, _ error) {
	if r != nil && r.logger != nil {
		r.logger.Error("audit external worker delivery failed",
			"module_id", r.moduleID, "operation", operation, "error_class", "worker_error")
	}
}

// Ready checks both manager health and the worker's authenticated readiness
// RPC, so a child process that exits after boot withdraws /readyz.
func (r *ExternalAuditRuntime) Ready(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return modules.ErrManagerClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.manager.Ready(ctx); err != nil {
		return err
	}
	lease, err := r.manager.Acquire(r.moduleID, modules.LeaseRequest)
	if err != nil {
		return err
	}
	defer lease.Release()
	instance, ok := lease.Instance().(interface{ Ready(context.Context) error })
	if !ok {
		return errors.New("external module: active worker is not readiness-capable")
	}
	return instance.Ready(ctx)
}

// Close drains the active generation and stops the child or closes the remote
// connection. It is called after the recorder's asynchronous queue drains.
func (r *ExternalAuditRuntime) Close(ctx context.Context) error {
	if r == nil || r.manager == nil {
		return nil
	}
	return r.manager.Close(ctx)
}

func (r *ExternalAuditRuntime) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

func (r *ExternalAuditRuntime) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

var _ audit.Sink = (*ExternalAuditRuntime)(nil)
