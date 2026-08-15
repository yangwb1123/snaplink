// Package file is a directory-backed snapshot.Storage. Snapshots are
// written as <name>.snap files via atomic tempfile + rename, so partial
// writes never leak and concurrent readers always see a complete file.
//
// Names are sanitised: only [A-Za-z0-9_.-] survive, everything else is
// replaced with "_". Operators that want strict naming (e.g. all
// snapshots prefixed with the namespace) should impose it externally.
package file

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/shared/core"
)

const fileExt = ".snap"

// Storage persists snapshots as files under BaseDir.
type Storage struct {
	baseDir string
}

// New constructs a Storage backed by baseDir. The directory is created
// (with parents) on first use; permissions are 0o700 so snapshots
// containing sensitive data aren't readable by other users by default.
func New(baseDir string) (*Storage, error) {
	if baseDir == "" {
		return nil, errors.New("snapshot/storage/file: baseDir required")
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("snapshot/storage/file: abs: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("snapshot/storage/file: mkdir %q: %w", abs, err)
	}
	return &Storage{baseDir: abs}, nil
}

// BaseDir returns the absolute directory holding the snapshot files.
// Useful for ops scripts that want to ls/du the on-disk footprint.
func (s *Storage) BaseDir() string { return s.baseDir }

func (s *Storage) Put(_ context.Context, name string, data []byte) error {
	clean, err := sanitize(name)
	if err != nil {
		return err
	}
	target := filepath.Join(s.baseDir, clean+fileExt)
	tmp, err := os.CreateTemp(s.baseDir, ".tmp-"+clean+"-*")
	if err != nil {
		return fmt.Errorf("snapshot/storage/file: tempfile: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// best-effort: if rename succeeds the tmp is gone; if it fails
		// remove the leftover so we don't leak files.
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("snapshot/storage/file: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("snapshot/storage/file: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("snapshot/storage/file: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("snapshot/storage/file: chmod: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("snapshot/storage/file: rename: %w", err)
	}
	return nil
}

func (s *Storage) Get(_ context.Context, name string) ([]byte, error) {
	clean, err := sanitize(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(s.baseDir, clean+fileExt))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, snapshot.ErrSnapshotNotFound
		}
		return nil, fmt.Errorf("snapshot/storage/file: read: %w", err)
	}
	return data, nil
}

func (s *Storage) List(_ context.Context) ([]string, error) {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("snapshot/storage/file: readdir: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, fileExt) {
			continue
		}
		out = append(out, strings.TrimSuffix(n, fileExt))
	}
	return out, nil
}

// ListPage implements snapshot.PaginatedSnapshotStorage: readdir + keyset
// pagination over names sorted ascending (the fixed sort both the fallback
// path and this page share). totalHint is the exact row count.
func (s *Storage) ListPage(_ context.Context, q core.PageQuery) ([]string, []byte, int, error) {
	names, err := s.List(context.Background())
	if err != nil {
		return nil, nil, 0, err
	}
	keyID := func(n string) (string, string) { return n, n }
	core.SortKeyset(names, q.Desc, keyID)
	return core.KeysetSlice(names, q, keyID)
}

// Compile-time interface checks.
var (
	_ snapshot.Storage                  = (*Storage)(nil)
	_ snapshot.PaginatedSnapshotStorage = (*Storage)(nil)
)

func (s *Storage) Delete(_ context.Context, name string) error {
	clean, err := sanitize(name)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.baseDir, clean+fileExt)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("snapshot/storage/file: remove: %w", err)
	}
	return nil
}

// sanitize returns name with non-allowlist characters replaced by "_".
// Empty names are rejected — they would land at the directory root and
// break List().
func sanitize(name string) (string, error) {
	if name == "" {
		return "", errors.New("snapshot/storage/file: empty name")
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
		return "", fmt.Errorf("snapshot/storage/file: sanitised name is invalid (%q)", name)
	}
	return out, nil
}

// Compile-time interface checks.
var (
	_ snapshot.Storage                  = (*Storage)(nil)
	_ snapshot.PaginatedSnapshotStorage = (*Storage)(nil)
)
