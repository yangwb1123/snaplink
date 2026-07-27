// Package bootstrap is the consumer-app facade over snaplink/sso/bootstrap.
// It packages the conventional "JSON-file tracker + namespaced Runner"
// pattern into a one-shot helper so embedding apps don't have to repeat
// the same five lines of glue in every main.go.
//
// Typical usage from an embedding App:
//
//	steps := []bootstrap.Step{
//	    bootstrap.StepFunc("create_schema", 1, createSchema),
//	    bootstrap.StepFunc("seed_admin", 2, seedAdminUser),
//	}
//	bs, err := ssobootstrap.New("billing-app", "/var/lib/billing/init.json")
//	if err != nil { return err }
//	bs.Register(steps...)
//	if err := bs.Run(ctx); err != nil { return err }
//
// The namespace is the App's identity in the shared state file — it MUST
// be unique across all apps writing to the same path. The reserved
// namespace "sso-server" is rejected because it belongs to the SDK's own
// built-in steps; use anything else.
package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/bootstrap"
	bootstrapfile "github.com/yangwb1123/snaplink/platform/bootstrap/file"
)

// reservedNamespace is the SDK-owned namespace; consumer apps may not use
// it. See cmd/sso-server for the steps registered there.
const reservedNamespace = "sso-server"

// Re-exports so consumer apps don't have to import the lower-level package
// just to construct Steps.
type (
	Step   = bootstrap.Step
	Logger = bootstrap.Logger
)

// StepFunc is the convenience constructor; identical semantics to
// bootstrap.StepFunc.
func StepFunc(name string, version int, run func(ctx context.Context) error) Step {
	return bootstrap.StepFunc(name, version, run)
}

// Bootstrap wraps a Runner with a JSON-file Tracker. Constructed once per
// app; safe to register Steps after construction and call Run multiple
// times — already-applied versions are skipped.
type Bootstrap struct {
	runner  *bootstrap.Runner
	tracker *bootstrapfile.Tracker
}

// Option tweaks construction.
type Option func(*config)

type config struct {
	recorder *audit.Recorder
	logger   Logger
}

// WithRecorder wires an audit.Recorder. Each Step run/skip/failure emits
// a bootstrap_step_* event tagged with the namespace.
func WithRecorder(r *audit.Recorder) Option { return func(c *config) { c.recorder = r } }

// WithLogger sets the diagnostic logger; defaults to no-op.
func WithLogger(l Logger) Option { return func(c *config) { c.logger = l } }

// New constructs a Bootstrap rooted at the given JSON state file. The file
// is created on first MarkApplied; missing-file is treated as empty state
// (no error). Caller must Close() to release the tracker handle.
func New(namespace, statePath string, opts ...Option) (*Bootstrap, error) {
	if namespace == "" {
		return nil, errors.New("ssoclient/bootstrap: namespace required")
	}
	if namespace == reservedNamespace {
		return nil, fmt.Errorf("ssoclient/bootstrap: namespace %q is reserved for the SDK", namespace)
	}
	if statePath == "" {
		return nil, errors.New("ssoclient/bootstrap: state path required")
	}
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}
	tr, err := bootstrapfile.New(statePath)
	if err != nil {
		return nil, fmt.Errorf("ssoclient/bootstrap: tracker: %w", err)
	}
	var runnerOpts []bootstrap.Option
	if cfg.recorder != nil {
		runnerOpts = append(runnerOpts, bootstrap.WithRecorder(cfg.recorder))
	}
	if cfg.logger != nil {
		runnerOpts = append(runnerOpts, bootstrap.WithLogger(cfg.logger))
	}
	return &Bootstrap{
		runner:  bootstrap.NewRunner(namespace, tr, runnerOpts...),
		tracker: tr,
	}, nil
}

// Register adds Steps. Order doesn't matter — the Runner sorts by Version.
func (b *Bootstrap) Register(steps ...Step) { b.runner.Register(steps...) }

// Run applies every pending Step in version order. Already-applied steps
// are skipped. The first failure stops the run and is bubbled up.
func (b *Bootstrap) Run(ctx context.Context) error { return b.runner.Run(ctx) }

// Close releases the underlying tracker. Optional — file trackers don't
// hold persistent fds, but symmetry with future backends is helpful.
func (b *Bootstrap) Close() error { return b.tracker.Close() }
