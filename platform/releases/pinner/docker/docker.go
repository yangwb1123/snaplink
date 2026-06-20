// Package docker is a docker-compose-based releases.Pinner. It
// rewrites a managed .env file (RELEASE_ID, BACKEND_IMAGE,
// FRONTEND_IMAGE) inside BundleDir then runs `docker compose pull`
// followed by `docker compose up -d`. The operator's compose file
// references ${BACKEND_IMAGE} and ${FRONTEND_IMAGE} so the up-d
// recreates services with the new image tags.
//
// PinForward and PinRollback are intentionally identical: docker
// compose treats the service graph as a unit and there is no clean
// way to express "backend first, then frontend" without invasive
// compose-file gymnastics. Operators who need finer ordering should
// build a custom Pinner — this one optimises for the common
// single-host, single-graph deploy.
package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/snaplink/sso/platform/releases"
)

const (
	defaultBinary = "docker"
	envFileName   = ".env"
)

// ExecFunc runs an external command in dir with name + args. Returns
// nil on exit code 0; tests inject a recorder to keep assertions
// hermetic. Production code uses the default which wraps
// exec.CommandContext + CombinedOutput.
type ExecFunc func(ctx context.Context, dir, name string, args ...string) error

// Pinner is the docker-compose-based Pinner. mu serializes calls
// per-Pinner so concurrent Pin attempts don't race on the .env
// rewrite + compose invocation.
type Pinner struct {
	BundleDir string   // working dir; must contain a compose file
	Cmd       string   // docker binary; defaults to "docker"
	Exec      ExecFunc // injected; defaults to exec.CommandContext-backed runner

	mu sync.Mutex
}

// New constructs a Pinner. The directory must already exist and
// contain the operator's compose file (the Pinner does not
// materialise it — that's CI's job).
func New(bundleDir string) (*Pinner, error) {
	if bundleDir == "" {
		return nil, errors.New("releases/pinner/docker: bundleDir required")
	}
	abs, err := filepath.Abs(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("releases/pinner/docker: abs: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("releases/pinner/docker: stat: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("releases/pinner/docker: %q is not a directory", abs)
	}
	return &Pinner{BundleDir: abs}, nil
}

func (p *Pinner) PinForward(ctx context.Context, target *releases.Release) error {
	return p.apply(ctx, target)
}

func (p *Pinner) PinRollback(ctx context.Context, target *releases.Release) error {
	return p.apply(ctx, target)
}

func (p *Pinner) apply(ctx context.Context, target *releases.Release) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if target == nil {
		return errors.New("releases/pinner/docker: nil target")
	}
	if target.Backend.URI == "" {
		return errors.New("releases/pinner/docker: target.Backend.URI required (the image tag the compose file references via ${BACKEND_IMAGE})")
	}

	if err := atomicWrite(p.BundleDir, filepath.Join(p.BundleDir, envFileName), []byte(buildEnv(target))); err != nil {
		return err
	}

	cmd := p.Cmd
	if cmd == "" {
		cmd = defaultBinary
	}
	runner := p.Exec
	if runner == nil {
		runner = defaultExec
	}

	if err := runner(ctx, p.BundleDir, cmd, "compose", "pull"); err != nil {
		return fmt.Errorf("releases/pinner/docker: compose pull: %w", err)
	}
	if err := runner(ctx, p.BundleDir, cmd, "compose", "up", "-d"); err != nil {
		return fmt.Errorf("releases/pinner/docker: compose up: %w", err)
	}
	return nil
}

// buildEnv renders the .env contents the Pinner manages. RELEASE_ID
// is always emitted; FRONTEND_IMAGE is omitted when empty so
// backend-only deployments don't see a stale variable in their env.
func buildEnv(r *releases.Release) string {
	var b strings.Builder
	fmt.Fprintf(&b, "RELEASE_ID=%s\n", r.ID)
	fmt.Fprintf(&b, "BACKEND_IMAGE=%s\n", r.Backend.URI)
	if r.Frontend.URI != "" {
		fmt.Fprintf(&b, "FRONTEND_IMAGE=%s\n", r.Frontend.URI)
	}
	return b.String()
}

func defaultExec(ctx context.Context, dir, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// atomicWrite stages data into a tempfile in dir and renames it
// onto target. 0o600 because the .env may carry secrets (registry
// credentials referenced by image URIs).
func atomicWrite(dir, target string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".tmp-env-*")
	if err != nil {
		return fmt.Errorf("releases/pinner/docker: tempfile: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("releases/pinner/docker: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("releases/pinner/docker: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("releases/pinner/docker: chmod: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("releases/pinner/docker: rename: %w", err)
	}
	return nil
}

// Compile-time interface check.
var _ releases.Pinner = (*Pinner)(nil)
