// Package file is a directory-backed releases.ReleaseStore. Each
// Release lives in its own <id>.json file (so per-release writes
// don't churn unrelated entries), and the currently-pinned id lives
// in a single CURRENT file. Both are written via atomic tempfile +
// rename so partial writes never leak.
//
// Names are sanitised the same way as snapshot/storage/file —
// [A-Za-z0-9_.-] survive, everything else becomes "_".
package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/snaplink/sso/platform/releases"
)

const (
	fileExt     = ".json"
	currentFile = "CURRENT"
)

// Store persists Releases as files under baseDir.
type Store struct {
	mu      sync.Mutex
	baseDir string
}

// New constructs a Store backed by baseDir. The directory is created
// (with parents) on first use; permissions are 0o700.
func New(baseDir string) (*Store, error) {
	if baseDir == "" {
		return nil, errors.New("releases/store/file: baseDir required")
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("releases/store/file: abs: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("releases/store/file: mkdir %q: %w", abs, err)
	}
	return &Store{baseDir: abs}, nil
}

// BaseDir returns the absolute directory holding the release files.
func (s *Store) BaseDir() string { return s.baseDir }

func (s *Store) Register(_ context.Context, r *releases.Release) error {
	if err := r.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target, err := s.pathFor(r.ID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(target); err == nil {
		return releases.ErrReleaseExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("releases/store/file: stat: %w", err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("releases/store/file: marshal: %w", err)
	}
	return atomicWrite(s.baseDir, target, data)
}

func (s *Store) Get(_ context.Context, id string) (*releases.Release, error) {
	target, err := s.pathFor(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, releases.ErrReleaseNotFound
		}
		return nil, fmt.Errorf("releases/store/file: read: %w", err)
	}
	var r releases.Release
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("releases/store/file: unmarshal %q: %w", id, err)
	}
	return &r, nil
}

func (s *Store) List(_ context.Context) ([]*releases.Release, error) {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("releases/store/file: readdir: %w", err)
	}
	out := make([]*releases.Release, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, fileExt) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.baseDir, n))
		if err != nil {
			return nil, fmt.Errorf("releases/store/file: read %q: %w", n, err)
		}
		var r releases.Release
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("releases/store/file: unmarshal %q: %w", n, err)
		}
		out = append(out, &r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, err := s.pathFor(id)
	if err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("releases/store/file: remove: %w", err)
	}
	cur, err := s.readCurrent()
	if err != nil {
		return err
	}
	if cur == id {
		return s.writeCurrent("")
	}
	return nil
}

func (s *Store) SetCurrent(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, err := s.pathFor(id)
	if err != nil {
		return err
	}
	if _, err := os.Stat(target); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return releases.ErrReleaseNotFound
		}
		return fmt.Errorf("releases/store/file: stat: %w", err)
	}
	return s.writeCurrent(id)
}

func (s *Store) Current(ctx context.Context) (*releases.Release, error) {
	cur, err := s.readCurrent()
	if err != nil {
		return nil, err
	}
	if cur == "" {
		return nil, releases.ErrNoCurrent
	}
	return s.Get(ctx, cur)
}

func (s *Store) ClearCurrent(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeCurrent("")
}

// pathFor returns the on-disk path for id, after sanitising. The
// sanitised form is also what other helpers (Stat / Remove) operate
// on, so callers always agree on the same name.
func (s *Store) pathFor(id string) (string, error) {
	clean, err := sanitize(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.baseDir, clean+fileExt), nil
}

func (s *Store) readCurrent() (string, error) {
	data, err := os.ReadFile(filepath.Join(s.baseDir, currentFile))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("releases/store/file: read CURRENT: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (s *Store) writeCurrent(id string) error {
	target := filepath.Join(s.baseDir, currentFile)
	if id == "" {
		if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("releases/store/file: remove CURRENT: %w", err)
		}
		return nil
	}
	return atomicWrite(s.baseDir, target, []byte(id))
}

// atomicWrite stages data into a tempfile in dir and renames it onto
// target. The tempfile leftover is removed if rename fails. 0o600 on
// the tempfile so secrets never live as 0o644 even briefly.
func atomicWrite(dir, target string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("releases/store/file: tempfile: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("releases/store/file: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("releases/store/file: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("releases/store/file: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("releases/store/file: chmod: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("releases/store/file: rename: %w", err)
	}
	return nil
}

func sanitize(name string) (string, error) {
	if name == "" {
		return "", errors.New("releases/store/file: empty name")
	}
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		return "", fmt.Errorf("releases/store/file: sanitised name is invalid (%q)", name)
	}
	return out, nil
}

// Compile-time interface check.
var _ releases.ReleaseStore = (*Store)(nil)
