package docker_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/snaplink/sso/releases"
	"github.com/snaplink/sso/releases/pinner/docker"
)

// recorder captures every Exec call so tests can assert the docker
// invocation sequence and command shape.
type recorder struct {
	mu    sync.Mutex
	calls []string
	err   map[string]error // map "joined args" -> error to return
}

func (r *recorder) exec(_ context.Context, dir, name string, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	joined := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, dir+"$ "+joined)
	if r.err != nil {
		if e, ok := r.err[joined]; ok {
			return e
		}
	}
	return nil
}

func validRelease(id string) *releases.Release {
	return &releases.Release{
		ID:       id,
		Frontend: releases.Artifact{URI: "ghcr.io/example/fe:" + id},
		Backend:  releases.Artifact{URI: "ghcr.io/example/api:" + id},
	}
}

func TestNew_RejectsEmptyDir(t *testing.T) {
	if _, err := docker.New(""); err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestNew_RejectsMissingDir(t *testing.T) {
	if _, err := docker.New(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected error for missing dir")
	}
}

func TestNew_RejectsFile(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "*")
	_ = f.Close()
	if _, err := docker.New(f.Name()); err == nil {
		t.Fatal("expected error when path is a file")
	}
}

func TestPinForward_WritesEnvAndCallsCompose(t *testing.T) {
	dir := t.TempDir()
	p, err := docker.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := &recorder{}
	p.Exec = rec.exec

	if err := p.PinForward(context.Background(), validRelease("rel-1")); err != nil {
		t.Fatalf("PinForward: %v", err)
	}

	// .env file should be written with all three vars.
	envBytes, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	env := string(envBytes)
	for _, want := range []string{
		"RELEASE_ID=rel-1",
		"BACKEND_IMAGE=ghcr.io/example/api:rel-1",
		"FRONTEND_IMAGE=ghcr.io/example/fe:rel-1",
	} {
		if !strings.Contains(env, want) {
			t.Errorf(".env missing %q\ngot:\n%s", want, env)
		}
	}

	// Exec sequence: pull then up -d, both in the bundle dir, both with the docker binary.
	if len(rec.calls) != 2 {
		t.Fatalf("exec calls = %d, want 2: %v", len(rec.calls), rec.calls)
	}
	if !strings.Contains(rec.calls[0], "docker compose pull") {
		t.Errorf("first call = %q", rec.calls[0])
	}
	if !strings.Contains(rec.calls[1], "docker compose up -d") {
		t.Errorf("second call = %q", rec.calls[1])
	}
}

func TestPinForward_FrontendOmittedWhenURIEmpty(t *testing.T) {
	dir := t.TempDir()
	p, _ := docker.New(dir)
	rec := &recorder{}
	p.Exec = rec.exec

	r := validRelease("rel-1")
	r.Frontend = releases.Artifact{} // no URI
	if err := p.PinForward(context.Background(), r); err != nil {
		t.Fatalf("PinForward: %v", err)
	}
	envBytes, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if strings.Contains(string(envBytes), "FRONTEND_IMAGE") {
		t.Errorf(".env should omit FRONTEND_IMAGE when frontend URI empty\ngot:\n%s", envBytes)
	}
}

func TestPinForward_BackendURIRequired(t *testing.T) {
	dir := t.TempDir()
	p, _ := docker.New(dir)
	r := validRelease("rel-1")
	r.Backend = releases.Artifact{} // no URI
	if err := p.PinForward(context.Background(), r); err == nil {
		t.Fatal("expected error for missing Backend.URI")
	}
}

func TestPinForward_PullErrorAborts(t *testing.T) {
	dir := t.TempDir()
	p, _ := docker.New(dir)
	rec := &recorder{
		err: map[string]error{"docker compose pull": errors.New("boom")},
	}
	p.Exec = rec.exec
	if err := p.PinForward(context.Background(), validRelease("rel-1")); err == nil {
		t.Fatal("expected error from pull")
	}
	// up should not have been called.
	for _, c := range rec.calls {
		if strings.Contains(c, "compose up") {
			t.Errorf("up called despite pull failure: %v", rec.calls)
		}
	}
}

func TestPinForward_UpErrorReturned(t *testing.T) {
	dir := t.TempDir()
	p, _ := docker.New(dir)
	rec := &recorder{
		err: map[string]error{"docker compose up -d": errors.New("nope")},
	}
	p.Exec = rec.exec
	if err := p.PinForward(context.Background(), validRelease("rel-1")); err == nil {
		t.Fatal("expected error from up")
	}
}

func TestPinRollback_SameAsForward(t *testing.T) {
	dir := t.TempDir()
	p, _ := docker.New(dir)
	rec := &recorder{}
	p.Exec = rec.exec
	if err := p.PinRollback(context.Background(), validRelease("rel-old")); err != nil {
		t.Fatalf("PinRollback: %v", err)
	}
	envBytes, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(envBytes), "RELEASE_ID=rel-old") {
		t.Errorf(".env missing rollback id\n%s", envBytes)
	}
	if len(rec.calls) != 2 {
		t.Errorf("exec calls = %d, want 2", len(rec.calls))
	}
}

func TestPinForward_CustomCmdHonored(t *testing.T) {
	dir := t.TempDir()
	p, _ := docker.New(dir)
	p.Cmd = "podman"
	rec := &recorder{}
	p.Exec = rec.exec
	if err := p.PinForward(context.Background(), validRelease("rel-1")); err != nil {
		t.Fatalf("PinForward: %v", err)
	}
	if !strings.Contains(rec.calls[0], "podman compose") {
		t.Errorf("first call did not use podman: %q", rec.calls[0])
	}
}
