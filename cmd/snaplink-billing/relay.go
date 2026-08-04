package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
)

const (
	auditRelayModuleID   = "audit-governance-relay"
	maxAuditDesiredBytes = 4 << 10
	auditDesiredPoll     = 5 * time.Second
)

var (
	errAuditDesiredInvalid      = errors.New("audit relay desired state is invalid")
	errAuditDesiredStale        = errors.New("audit relay desired state revision is stale")
	errAuditDesiredEquivocation = errors.New("audit relay desired state revision conflicts")
)

type auditDesired struct {
	Revision uint64 `json:"revision"`
	Enabled  bool   `json:"enabled"`
}

func buildRelays(
	config runtimeConfig, commerceOutbox, usageOutbox tenantcommerce.OutboxStore, generation uint64,
) ([]auditgovernance.ManagedRelay, error) {
	if !config.Audit.enabled() {
		return nil, nil
	}
	httpClient := newUpstreamHTTPClient(config.Audit.HTTPTimeout)
	tokens, err := auditgovernance.NewOAuthTokenSource(auditgovernance.OAuthTokenConfig{
		TokenURL: config.Audit.TokenURL, ClientID: config.Audit.ClientID,
		ClientSecret: config.Audit.ClientSecret, SourcePrefix: config.Audit.SourcePrefix,
		Scope: config.Audit.Scope, Resources: []string{config.Audit.Resource},
		Timeout: config.Audit.HTTPTimeout, AllowInsecureLoopback: config.AllowInsecureLoopback,
	}, httpClient)
	if err != nil {
		return nil, err
	}
	client, err := auditgovernance.NewHTTPClient(auditgovernance.HTTPConfig{
		BaseURL: config.Audit.BaseURL, SourcePrefix: config.Audit.SourcePrefix,
		Timeout: config.Audit.HTTPTimeout, AllowInsecureLoopback: config.AllowInsecureLoopback,
	}, tokens, httpClient)
	if err != nil {
		return nil, err
	}
	stores := []struct {
		name  string
		store tenantcommerce.OutboxStore
	}{{"commerce", commerceOutbox}, {"usage", usageOutbox}}
	runners := make([]auditgovernance.ManagedRelay, 0, len(stores))
	for _, candidate := range stores {
		relay, relayErr := auditgovernance.NewRelay(candidate.store, client, auditgovernance.RelayConfig{
			Owner: fmt.Sprintf("%s-%s-g%d", config.Audit.RelayOwner, candidate.name, generation),
		})
		if relayErr != nil {
			return nil, relayErr
		}
		runners = append(runners, auditgovernance.ManagedRelay{
			Name: candidate.name, Relay: relay,
			AuthPause: config.Audit.AuthPause, ErrorPause: config.Audit.ErrorPause,
		})
	}
	return runners, nil
}

func (app *application) startBackground(ctx context.Context, output io.Writer) func() {
	var workers sync.WaitGroup
	logger := log.New(output, programName+": ", 0)
	if app.audit != nil {
		app.audit.setLogger(logger)
		workers.Add(1)
		go func() {
			defer workers.Done()
			app.audit.watch(ctx)
		}()
	}
	if app.renewal != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			app.renewal.run(ctx, logger)
		}()
	}
	if app.quota != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			app.quota.run(ctx, logger)
		}()
	}
	return workers.Wait
}

type auditModule struct {
	manager     *modules.Manager
	runtimeFile string

	mu          sync.RWMutex
	applied     auditDesired
	appliedJSON string
	desiredErr  error
	logger      *log.Logger
}

func buildAuditModule(
	config runtimeConfig, commerceOutbox, usageOutbox tenantcommerce.OutboxStore,
) (*auditModule, error) {
	if !config.Audit.enabled() {
		return nil, nil
	}
	factory := auditgovernance.ManagedRelayFactory{Build: func(
		_ context.Context, _ []byte, generation uint64,
	) ([]auditgovernance.ManagedRelay, error) {
		return buildRelays(config, commerceOutbox, usageOutbox, generation)
	}}
	lifetime := config.Audit.HTTPTimeout + 5*time.Second
	module, err := newAuditModule(factory, config.Audit.RuntimeFile, modules.Options{
		DrainTimeout: lifetime, LifecycleTimeout: lifetime,
	})
	if err != nil {
		return nil, err
	}
	if err := module.applyInitial(context.Background()); err != nil {
		_ = module.Close()
		return nil, err
	}
	return module, nil
}

func newAuditModule(
	factory modules.Factory, runtimeFile string, options modules.Options,
) (*auditModule, error) {
	module := &auditModule{runtimeFile: runtimeFile}
	options.TransitionObserver = module
	manager, err := modules.New([]modules.Definition{{ID: auditRelayModuleID, Factory: factory}}, options)
	if err != nil {
		return nil, err
	}
	module.manager = manager
	return module, nil
}

func (m *auditModule) applyInitial(ctx context.Context) error {
	desired, encoded, err := m.loadDesired()
	if err != nil {
		return err
	}
	return m.apply(ctx, desired, encoded)
}

func (m *auditModule) loadDesired() (auditDesired, []byte, error) {
	if m.runtimeFile == "" {
		desired := auditDesired{Revision: 1, Enabled: true}
		encoded, _ := json.Marshal(desired)
		return desired, encoded, nil
	}
	return loadAuditDesired(m.runtimeFile)
}

func loadAuditDesired(path string) (auditDesired, []byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return auditDesired{}, nil, errAuditDesiredInvalid
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return auditDesired{}, nil, errAuditDesiredInvalid
	}
	body, err := io.ReadAll(io.LimitReader(file, maxAuditDesiredBytes+1))
	if err != nil || len(body) > maxAuditDesiredBytes {
		return auditDesired{}, nil, errAuditDesiredInvalid
	}
	var wire struct {
		Revision uint64 `json:"revision"`
		Enabled  *bool  `json:"enabled"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || wire.Revision == 0 || wire.Enabled == nil || decoder.Decode(&struct{}{}) != io.EOF {
		return auditDesired{}, nil, errAuditDesiredInvalid
	}
	desired := auditDesired{Revision: wire.Revision, Enabled: *wire.Enabled}
	encoded, err := json.Marshal(desired)
	if err != nil {
		return auditDesired{}, nil, errAuditDesiredInvalid
	}
	return desired, encoded, nil
}

func (m *auditModule) apply(ctx context.Context, desired auditDesired, encoded []byte) error {
	m.mu.RLock()
	applied, appliedJSON := m.applied, m.appliedJSON
	m.mu.RUnlock()
	if desired.Revision < applied.Revision {
		return errAuditDesiredStale
	}
	if desired.Revision == applied.Revision {
		if string(encoded) != appliedJSON {
			return errAuditDesiredEquivocation
		}
		m.mu.Lock()
		m.desiredErr = nil
		m.mu.Unlock()
		return nil
	}
	if err := m.transition(ctx, desired, encoded); err != nil {
		return err
	}
	m.mu.Lock()
	m.applied, m.appliedJSON, m.desiredErr = desired, string(encoded), nil
	m.mu.Unlock()
	return nil
}

func (m *auditModule) transition(ctx context.Context, desired auditDesired, encoded []byte) error {
	if desired.Enabled {
		_, err := m.manager.Activate(ctx, auditRelayModuleID, encoded)
		return err
	}
	retirement, err := m.manager.Disable(auditRelayModuleID)
	if errors.Is(err, modules.ErrModuleInactive) {
		return nil
	}
	if err != nil {
		return err
	}
	return retirement.Wait(ctx)
}

func (m *auditModule) watch(ctx context.Context) {
	if m.runtimeFile == "" {
		<-ctx.Done()
		return
	}
	reloads := make(chan os.Signal, 1)
	signal.Notify(reloads, syscall.SIGHUP)
	defer signal.Stop(reloads)
	poll := time.NewTicker(auditDesiredPoll)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reloads:
			m.reload(ctx)
		case <-poll.C:
			m.reload(ctx)
		}
	}
}

func (m *auditModule) reload(ctx context.Context) {
	m.mu.RLock()
	before, recovering := m.appliedJSON, m.desiredErr != nil
	m.mu.RUnlock()
	desired, encoded, err := m.loadDesired()
	if err == nil {
		err = m.apply(ctx, desired, encoded)
	}
	if err == nil {
		m.mu.RLock()
		changed := before != m.appliedJSON
		m.mu.RUnlock()
		if changed || recovering {
			m.logf("audit relay desired state applied")
		}
		return
	}
	m.mu.Lock()
	firstRejection := m.desiredErr == nil
	m.desiredErr = errAuditDesiredInvalid
	m.mu.Unlock()
	if firstRejection {
		m.logf("audit relay desired state rejected: %v", err)
	}
}

func (m *auditModule) Ready(ctx context.Context) error {
	m.mu.RLock()
	desiredErr := m.desiredErr
	m.mu.RUnlock()
	if desiredErr != nil {
		return desiredErr
	}
	return m.manager.Ready(ctx)
}

func (m *auditModule) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return m.manager.Close(ctx)
}

func (m *auditModule) setLogger(logger *log.Logger) {
	m.mu.Lock()
	m.logger = logger
	m.mu.Unlock()
}

func (m *auditModule) logf(format string, values ...any) {
	m.mu.RLock()
	logger := m.logger
	m.mu.RUnlock()
	if logger != nil {
		logger.Printf(format, values...)
	}
}

func (m *auditModule) Observe(_ context.Context, event modules.TransitionEvent) error {
	m.logf("audit relay transition=%s generation=%d related_generation=%d",
		event.Type, event.Generation, event.RelatedGeneration)
	return nil
}

var _ modules.TransitionObserver = (*auditModule)(nil)
