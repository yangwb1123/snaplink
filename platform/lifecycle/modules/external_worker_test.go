package modules

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func localExternalWorkerSocket(t *testing.T) string {
	t.Helper()
	// t.TempDir includes the full test name. Under macOS's long TMPDIR that
	// exceeds sockaddr_un's path capacity before the worker can even listen.
	directory, err := os.MkdirTemp("", "snaplink-worker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove worker socket directory: %v", err)
		}
	})
	return filepath.Join(directory, "worker.sock")
}

func TestExternalWorkerSocketDoesNotIncludeTheTestNameAndRemainsBindable(t *testing.T) {
	path := localExternalWorkerSocket(t)
	if strings.Contains(path, t.Name()) {
		t.Fatal("socket path includes the unbounded test name")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on %d-byte socket path: %v", len(path), err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close worker listener: %v", err)
		}
	})
}
