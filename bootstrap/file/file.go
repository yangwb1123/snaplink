// Package file is the JSON-file-backed bootstrap.Tracker. Default for
// single-node deployments — zero deps, durable across restarts.
//
// State file format:
//
//	{
//	  "namespaces": {
//	    "sso-server": {"version": 3, "applied": [{"v":1,"name":"seed_admin_role","at_unix":1700000000}, ...]},
//	    "billing-app": {"version": 1, "applied": [...]}
//	  }
//	}
//
// Writes are atomic-ish (rename(tmp, target)) so a crash mid-write doesn't
// truncate the file. The whole file is rewritten on each MarkApplied —
// fine because boot is rare and the file stays small.
package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/snaplink/sso/bootstrap"
)

// Tracker is the file-backed bootstrap.Tracker.
type Tracker struct {
	path string

	mu    sync.Mutex
	state state
}

type state struct {
	Namespaces map[string]*namespaceState `json:"namespaces"`
}

type namespaceState struct {
	Version int           `json:"version"`
	Applied []appliedStep `json:"applied"`
}

type appliedStep struct {
	V      int    `json:"v"`
	Name   string `json:"name"`
	AtUnix int64  `json:"at_unix"`
}

// New constructs a Tracker rooted at the given file path. Loads any existing
// state on first call — a missing file is treated as empty (not an error).
func New(path string) (*Tracker, error) {
	if path == "" {
		return nil, errors.New("bootstrap/file: path required")
	}
	t := &Tracker{path: path, state: state{Namespaces: map[string]*namespaceState{}}}
	if err := t.load(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tracker) load() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	data, err := os.ReadFile(t.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("bootstrap/file: read %s: %w", t.path, err)
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &t.state); err != nil {
		return fmt.Errorf("bootstrap/file: parse %s: %w", t.path, err)
	}
	if t.state.Namespaces == nil {
		t.state.Namespaces = map[string]*namespaceState{}
	}
	return nil
}

func (t *Tracker) AppliedVersion(_ context.Context, namespace string) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ns, ok := t.state.Namespaces[namespace]; ok {
		return ns.Version, nil
	}
	return 0, nil
}

func (t *Tracker) MarkApplied(_ context.Context, namespace string, version int, name string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	ns := t.state.Namespaces[namespace]
	if ns == nil {
		ns = &namespaceState{}
		t.state.Namespaces[namespace] = ns
	}
	if version > ns.Version {
		ns.Version = version
	}
	ns.Applied = append(ns.Applied, appliedStep{V: version, Name: name, AtUnix: time.Now().Unix()})
	return t.flushLocked()
}

// flushLocked rewrites the entire state file atomically. Caller holds t.mu.
func (t *Tracker) flushLocked() error {
	data, err := json.MarshalIndent(t.state, "", "  ")
	if err != nil {
		return fmt.Errorf("bootstrap/file: marshal: %w", err)
	}
	dir := filepath.Dir(t.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("bootstrap/file: mkdir: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(t.path)+".*")
	if err != nil {
		return fmt.Errorf("bootstrap/file: tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath) // no-op if already renamed
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("bootstrap/file: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("bootstrap/file: close: %w", err)
	}
	if err := os.Rename(tmpPath, t.path); err != nil {
		return fmt.Errorf("bootstrap/file: rename: %w", err)
	}
	return nil
}

func (t *Tracker) Close() error { return nil }

// Compile-time interface check.
var _ bootstrap.Tracker = (*Tracker)(nil)
