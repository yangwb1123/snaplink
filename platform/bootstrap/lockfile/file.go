// Package file is the flock(2)-based bootstrap lock. It serializes
// runners on a single host across processes — useful for systemd unit
// restarts that overlap, or for blue/green deploys on the same machine.
//
// Cross-host coordination is NOT supported; use bootstrap/lock/etcd for
// that. flock is also unreliable on NFS (varies by mount options) — keep
// the lock file on local disk.
//
// Only Unix-like platforms are supported (build tag below). The Lock
// writes the holder's PID to the lock file after acquiring so an
// operator can `cat` it to find the holder during incident response.

//go:build unix

package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yangwb1123/snaplink/platform/bootstrap/lock"
)

// Lock is a flock-based Lock. One instance is per-key — each TryAcquire
// allocates a separate file descriptor so multiple keys on the same Lock
// don't share state.
type Lock struct {
	dir string // base dir; key is appended as a file name
}

// New constructs a Lock that writes lock files under dir. dir must
// exist; pass "" to use the current working directory.
func New(dir string) *Lock {
	if dir == "" {
		dir = "."
	}
	return &Lock{dir: dir}
}

// TryAcquire opens (or creates) <dir>/<key>.lock and applies LOCK_EX |
// LOCK_NB. Returns ErrLocked if another holder owns the file. The
// returned Handle keeps the fd open; Release closes it (which releases
// the flock).
func (l *Lock) TryAcquire(_ context.Context, key string, _ time.Duration) (lock.Handle, error) {
	if key == "" {
		return nil, errors.New("bootstrap/lock/file: key required")
	}
	path := filepath.Join(l.dir, sanitizeKey(key)+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("bootstrap/lock/file: open %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, lock.ErrLocked
		}
		return nil, fmt.Errorf("bootstrap/lock/file: flock %s: %w", path, err)
	}
	// Best-effort: write our PID for operator-side debugging. Failures
	// here don't invalidate the lock.
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return &handle{f: f, path: path, token: nextToken()}, nil
}

// fileTokenSeq is a process-local monotonic counter so different
// Handles get different tokens within one process. Cross-process
// fencing isn't possible without a shared store — flock alone is
// enough for single-host serialization, so the token is informational.
var fileTokenSeq atomic.Uint64

func nextToken() uint64 { return fileTokenSeq.Add(1) }

func sanitizeKey(k string) string {
	// Keep / out of file paths; the key is opaque to us.
	out := make([]byte, 0, len(k))
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "_"
	}
	return string(out)
}

type handle struct {
	f      *os.File
	path   string
	token  uint64
	closed atomic.Bool
}

// Renew is a no-op — flock leases don't expire.
func (h *handle) Renew(context.Context) error { return nil }

// Release closes the fd, which releases the flock. Idempotent.
func (h *handle) Release(context.Context) error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	// Don't unlink the file — concurrent attempts would race. Leaving
	// the (empty) file behind is harmless; flock state is per-fd, not
	// per-inode, so the next TryAcquire opens its own fd cleanly.
	return h.f.Close()
}

func (h *handle) FencingToken() uint64 { return h.token }

// Compile-time interface assertions.
var (
	_ lock.Lock   = (*Lock)(nil)
	_ lock.Handle = (*handle)(nil)
)
